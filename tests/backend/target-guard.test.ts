import { describe, expect, it } from "vitest";
import {
  BlockedTargetError,
  isPrivateAddress,
  resolveTarget,
} from "../../src/backend/target-guard";

describe("isPrivateAddress", () => {
  it.each([
    "10.1.2.3",
    "127.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "100.117.24.100",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "::",
    "fe80::1",
    "fd00::1",
    "fc00::2",
    "ff02::1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:a00:1",
    "64:ff9b::a00:1",
    "not an address",
  ])("refuses %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each([
    "1.1.1.1",
    "8.8.8.8",
    "172.32.0.1",
    "100.128.0.1",
    "157.180.101.50",
    "2606:4700:4700::1111",
    "::ffff:1.1.1.1",
  ])("allows %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(false);
  });
});

describe("resolveTarget", () => {
  const answers =
    (...addresses: string[]) =>
    async () =>
      addresses.map((address) => ({
        address,
        family: address.includes(":") ? 6 : 4,
      }));

  it("connects to what it checked", async () => {
    const found = await resolveTarget("a.test", false, answers("1.1.1.1"));
    expect(found).toEqual({ address: "1.1.1.1", family: 4 });
  });

  it("refuses a name that points somewhere private", async () => {
    await expect(
      resolveTarget("sneaky.test", false, answers("10.0.0.1")),
    ).rejects.toBeInstanceOf(BlockedTargetError);
  });

  it("refuses when any answer is private", async () => {
    await expect(
      resolveTarget("mixed.test", false, answers("1.1.1.1", "192.168.1.1")),
    ).rejects.toBeInstanceOf(BlockedTargetError);
  });

  it("allows private answers with the permission", async () => {
    const found = await resolveTarget("lan.test", true, answers("10.0.0.1"));
    expect(found.address).toBe("10.0.0.1");
  });

  it("checks literal addresses without a lookup", async () => {
    await expect(resolveTarget("127.0.0.1", false)).rejects.toBeInstanceOf(
      BlockedTargetError,
    );
    await expect(resolveTarget("[::1]", false)).rejects.toBeInstanceOf(
      BlockedTargetError,
    );
  });
});

describe("GHSA-64cc-43f9-c2v3 rebinding", () => {
  it("looks a name up once and returns that answer", async () => {
    let calls = 0;
    const lookup = async () => {
      calls += 1;
      return [
        { address: calls === 1 ? "203.0.113.10" : "127.0.0.1", family: 4 },
      ];
    };
    const chosen = await resolveTarget("rebind.test", false, lookup);
    expect(chosen.address).toBe("203.0.113.10");
    expect(calls).toBe(1);
  });
});
