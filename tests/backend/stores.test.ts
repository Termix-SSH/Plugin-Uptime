import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { BeatStore, RING_SIZE } from "../../src/backend/beats";
import {
  DAY_MS,
  HOUR_MS,
  RollupStore,
  bucketOf,
} from "../../src/backend/rollups";

describe("BeatStore", () => {
  it("keeps the newest beats, oldest first", () => {
    const store = new BeatStore();
    for (let index = 0; index < RING_SIZE + 5; index++) {
      store.add(1, (index + 1) * 1000, "up", index);
    }
    const beats = store.list(1);
    expect(beats).toHaveLength(RING_SIZE);
    expect(beats[0].ms).toBe(5);
    expect(beats.at(-1)?.ms).toBe(RING_SIZE + 4);
  });

  it("limits and filters by time", () => {
    const store = new BeatStore();
    for (let index = 1; index <= 10; index++) {
      store.add(1, index * 1000, "down", null);
    }
    expect(store.list(1, 3)).toHaveLength(3);
    expect(store.list(1, 100, 8)).toHaveLength(3);
    expect(store.list(1, 1)[0]).toEqual({ t: 10, s: "down", ms: null });
  });

  it("survives a save and load", async () => {
    const folder = mkdtempSync(path.join(tmpdir(), "uptime-beats-"));
    const store = new BeatStore();
    store.add(7, 1000, "up", 25);
    store.add(7, 2000, "maintenance", null);
    store.add(8, 3000, "pending", 3);
    await store.save(folder);

    const again = new BeatStore();
    await again.load(folder);
    expect(again.list(7)).toEqual(store.list(7));
    expect(again.list(8)).toEqual(store.list(8));
  });

  it("ignores a damaged file", () => {
    const store = new BeatStore();
    store.decode(Buffer.from("not beats at all"));
    expect(store.list(1)).toEqual([]);

    const good = new BeatStore();
    good.add(1, 1000, "up", 1);
    const cut = new BeatStore();
    cut.decode(good.encode().subarray(0, 14));
    expect(cut.list(1)).toEqual([]);
  });

  it("drops rings of removed monitors", () => {
    const store = new BeatStore();
    store.add(1, 1000, "up", 1);
    store.add(2, 1000, "up", 1);
    store.keepOnly(new Set([2]));
    expect(store.list(1)).toEqual([]);
    expect(store.list(2)).toHaveLength(1);
  });
});

describe("RollupStore", () => {
  const now = bucketOf("day", Date.UTC(2026, 10, 4)) + 12 * HOUR_MS;

  it("works out uptime and leaves paused time out", () => {
    const store = new RollupStore();
    for (let index = 0; index < 9; index++) store.add(1, now, "up", 10);
    store.add(1, now, "down", null);
    store.add(1, now, "maintenance", null);
    store.add(1, now, "paused", null);
    store.add(1, now, "pending", null);
    expect(store.uptime(1, now).day).toBe(90);
    expect(store.uptime(1, now).quarter).toBe(90);
    expect(store.uptime(2, now).day).toBeNull();
  });

  it("averages latency over the beats that had one", () => {
    const store = new RollupStore();
    store.add(1, now, "up", 10);
    store.add(1, now, "up", 30);
    store.add(1, now, "down", null);
    const [point] = store.history(1, "hour", DAY_MS, now);
    expect(point).toMatchObject({ ms: 20, min: 10, max: 30, up: 2, down: 1 });
  });

  it("hands dirty rows out once and takes them back on a failed save", () => {
    const store = new RollupStore();
    store.add(1, now, "up", 1);
    const rows = store.takeDirty();
    expect(rows).toHaveLength(2);
    expect(store.takeDirty()).toEqual([]);
    store.restoreDirty(rows);
    expect(store.takeDirty()).toHaveLength(2);
  });

  it("gives one value per day for a status page", () => {
    const store = new RollupStore();
    store.add(1, now, "up", 1);
    store.add(1, now - 2 * DAY_MS, "down", null);
    expect(store.days(1, 4, now)).toEqual([null, 0, null, 100]);
  });

  it("drops hours after a week and days after the setting", () => {
    const store = new RollupStore();
    store.add(1, now - 8 * DAY_MS, "up", 1);
    store.add(1, now - 40 * DAY_MS, "up", 1);
    store.prune(30, now);
    expect(store.history(1, "hour", 90 * DAY_MS, now)).toEqual([]);
    expect(store.history(1, "day", 90 * DAY_MS, now)).toHaveLength(1);
  });
});
