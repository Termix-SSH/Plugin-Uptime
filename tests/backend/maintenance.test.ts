import { describe, expect, it } from "vitest";
import {
  inMaintenance,
  localTime,
  maintenanceProblem,
  windowActive,
  type MaintenanceWindow,
} from "../../src/backend/maintenance";

const base: MaintenanceWindow = {
  id: 1,
  userId: "u1",
  name: "Patch",
  scope: "all",
  monitorKeys: [],
  kind: "weekly",
  days: [0],
  startMinute: 180,
  durationMinutes: 60,
  timezone: "UTC",
  enabled: true,
};

// 2026-11-01 is a Sunday.
const sunday = (hour: number, minute = 0) =>
  Date.UTC(2026, 10, 1, hour, minute);

describe("windowActive", () => {
  it("covers a one time window, end not included", () => {
    const window = { ...base, kind: "once" as const, startsAt: 10, endsAt: 20 };
    expect(windowActive(window, 9)).toBe(false);
    expect(windowActive(window, 10)).toBe(true);
    expect(windowActive(window, 20)).toBe(false);
  });

  it("repeats on the chosen day", () => {
    expect(windowActive(base, sunday(2, 59))).toBe(false);
    expect(windowActive(base, sunday(3))).toBe(true);
    expect(windowActive(base, sunday(3, 59))).toBe(true);
    expect(windowActive(base, sunday(4))).toBe(false);
    expect(windowActive(base, sunday(3) + 86_400_000)).toBe(false);
  });

  it("runs past Saturday midnight into Sunday", () => {
    const window = {
      ...base,
      days: [6],
      startMinute: 23 * 60,
      durationMinutes: 120,
    };
    expect(windowActive(window, sunday(0, 30))).toBe(true);
    expect(windowActive(window, sunday(1, 30))).toBe(false);
  });

  it("uses the window's time zone", () => {
    const window = { ...base, timezone: "America/New_York" };
    // 03:00 in New York on that Sunday is 08:00 UTC, after the clocks change.
    expect(windowActive(window, sunday(8))).toBe(true);
    expect(windowActive(window, sunday(3))).toBe(false);
  });

  it("falls back to UTC on a bad zone", () => {
    expect(localTime(sunday(3), "Not/AZone")).toEqual({ day: 0, minute: 180 });
  });

  it("does nothing while turned off", () => {
    expect(windowActive({ ...base, enabled: false }, sunday(3))).toBe(false);
  });
});

describe("inMaintenance", () => {
  const monitor = { key: "k1", userId: "u1", tags: ["prod"] };
  const at = sunday(3);

  it("all means the author's own monitors", () => {
    expect(inMaintenance([base], monitor, at)).toBe(true);
    expect(inMaintenance([base], { ...monitor, userId: "other" }, at)).toBe(
      false,
    );
  });

  it("matches by key and by tag", () => {
    const byKey = { ...base, scope: "monitors" as const, monitorKeys: ["k1"] };
    const byTag = { ...base, scope: "tag" as const, tag: "prod" };
    const wrong = { ...base, scope: "tag" as const, tag: "dev" };
    expect(inMaintenance([byKey], monitor, at)).toBe(true);
    expect(inMaintenance([byTag], monitor, at)).toBe(true);
    expect(inMaintenance([wrong], monitor, at)).toBe(false);
  });
});

describe("maintenanceProblem", () => {
  it("wants a name, an order and a day", () => {
    expect(maintenanceProblem({ ...base, name: " " })).not.toBe("");
    expect(maintenanceProblem({ ...base, days: [] })).not.toBe("");
    expect(
      maintenanceProblem({ ...base, kind: "once", startsAt: 5, endsAt: 1 }),
    ).not.toBe("");
    expect(maintenanceProblem(base)).toBe("");
  });
});
