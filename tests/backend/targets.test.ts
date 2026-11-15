import type { LookupAddress } from "node:dns";
import { describe, expect, it } from "vitest";
import {
  BlockedTargetError,
  isPrivateAddress,
  resolveTarget,
} from "../../src/backend/targets";

type Callback = (error: Error | null, addresses: LookupAddress[]) => void;

/** A dns.lookup stand-in that answers from a list, counting calls. */
function answers(...lists: string[][]) {
  let calls = 0;
  const lookup = ((_host: string, _options: unknown, callback: Callback) => {
    const list = lists[Math.min(calls, lists.length - 1)];
    calls += 1;
    callback(
      null,
      list.map((address) => ({
        address,
        family: address.includes(":") ? 6 : 4,
      })),
    );
  }) as never;
  return { lookup, calls: () => calls };
}

describe("isPrivateAddress", () => {
  it.each([
    "10.1.2.3",
    "127.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.117.24.100",
    "::1",
    "fe80::1",
    "fd00::1",
    "::ffff:127.0.0.1",
    "not an address",
  ])("refuses %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each(["1.1.1.1", "172.32.0.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"])(
    "allows %s",
    (ip) => {
      expect(isPrivateAddress(ip)).toBe(false);
    },
  );
});

describe("resolveTarget", () => {
  it("connects to what it checked", async () => {
    const { lookup } = answers(["1.1.1.1"]);
    await expect(resolveTarget("a.test", false, lookup)).resolves.toEqual({
      address: "1.1.1.1",
      family: 4,
    });
  });

  it("refuses when any answer is private", async () => {
    const { lookup } = answers(["1.1.1.1", "192.168.1.1"]);
    await expect(
      resolveTarget("mixed.test", false, lookup),
    ).rejects.toBeInstanceOf(BlockedTargetError);
  });

  it("allows private answers with the permission", async () => {
    const { lookup } = answers(["10.0.0.1"]);
    const found = await resolveTarget("lan.test", true, lookup);
    expect(found.address).toBe("10.0.0.1");
  });

  it("checks literal addresses without a lookup", async () => {
    await expect(resolveTarget("127.0.0.1", false)).rejects.toBeInstanceOf(
      BlockedTargetError,
    );
    await expect(resolveTarget("[::1]", false)).rejects.toThrow(
      "[::1] is a private address",
    );
  });
});

describe("GHSA-64cc-43f9-c2v3 rebinding", () => {
  it("looks a name up once and returns that answer", async () => {
    const { lookup, calls } = answers(["203.0.113.10"], ["127.0.0.1"]);
    const chosen = await resolveTarget("rebind.test", false, lookup);
    expect(chosen.address).toBe("203.0.113.10");
    expect(calls()).toBe(1);
  });
});
