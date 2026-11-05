import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { matchRecords, recordLines } from "../../src/backend/checks/dns";
import {
  authHeaders,
  checkHttp,
  keywordProblem,
} from "../../src/backend/checks/http";
import {
  PING_UNAVAILABLE,
  PingPool,
  parsePingLine,
} from "../../src/backend/checks/ping";
import {
  curlCommand,
  curlConfig,
  curlValue,
  judgeCurl,
  judgeDns,
  judgeOpenssl,
  judgePing,
  judgeTcp,
} from "../../src/backend/checks/remote";
import {
  checkCommand,
  checkDocker,
  checkSystemd,
  judgeContainer,
} from "../../src/backend/checks/ssh";
import { resolveTarget } from "../../src/backend/target-guard";
import { checkTcp } from "../../src/backend/checks/tcp";
import { judgeCert } from "../../src/backend/checks/tls";
import type { RemoteRun } from "../../src/backend/checks/types";
import { env, target } from "./helpers";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});

async function serve(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  closers.push(
    () => new Promise<void>((resolve) => server.close(() => resolve())),
  );
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("checkHttp", () => {
  const run = (config: object, extra = env) =>
    checkHttp(target({ config }), extra);

  it("accepts a good status and times it", async () => {
    const url = await serve((_req, res) => res.end("hello"));
    const result = await run({ url });
    expect(result.ok).toBe(true);
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("fails an unaccepted status", async () => {
    const url = await serve((_req, res) => {
      res.statusCode = 503;
      res.end();
    });
    expect(await run({ url })).toMatchObject({
      ok: false,
      message: "Status 503",
    });
  });

  it("honors a custom status list", async () => {
    const url = await serve((_req, res) => {
      res.statusCode = 404;
      res.end();
    });
    expect((await run({ url, acceptedStatus: "200,404" })).ok).toBe(true);
  });

  it("looks for a keyword", async () => {
    const url = await serve((_req, res) => res.end("all good here"));
    expect((await run({ url, keyword: "good" })).ok).toBe(true);
    expect((await run({ url, keyword: "nope" })).ok).toBe(false);
    expect((await run({ url, keyword: "good", keywordAbsent: true })).ok).toBe(
      false,
    );
  });

  it("reads a compressed answer", async () => {
    const url = await serve((_req, res) => {
      res.setHeader("content-encoding", "gzip");
      res.end(gzipSync("zipped words"));
    });
    expect((await run({ url, keyword: "zipped" })).ok).toBe(true);
  });

  it("sends the method and body", async () => {
    let seen = "";
    const url = await serve((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        seen = `${req.method} ${req.url} ${body}`;
        res.end();
      });
    });
    await run({ url: `${url}/a?b=1`, method: "POST", body: "hi" });
    expect(seen).toBe("POST /a?b=1 hi");
  });

  it("follows redirects", async () => {
    const url = await serve((req, res) => {
      if (req.url === "/start") {
        res.statusCode = 302;
        res.setHeader("location", "/end");
        res.end();
      } else {
        res.end("done");
      }
    });
    const result = await run({ url: `${url}/start`, keyword: "done" });
    expect(result.ok).toBe(true);
  });

  it("can leave a redirect alone", async () => {
    const url = await serve((_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "/end");
      res.end();
    });
    const result = await run({
      url,
      followRedirects: false,
      acceptedStatus: "302",
    });
    expect(result.ok).toBe(true);
  });

  it("refuses a private address without the permission", async () => {
    const url = await serve((_req, res) => res.end("secret"));
    const result = await run({ url }, { ...env, allowPrivate: false });
    expect(result.ok).toBe(false);
    expect(result.message).toContain("private");
  });

  it("refuses a public site that redirects somewhere private", async () => {
    const inside = await serve((_req, res) => res.end("secret"));
    const outside = await serve((_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", inside);
      res.end();
    });
    const asked: string[] = [];
    // Treats the first site as public, as a real outside site would be.
    const resolve: typeof resolveTarget = async (host, allowPrivate) => {
      asked.push(host);
      if (asked.length === 1) return { address: "127.0.0.1", family: 4 };
      return resolveTarget(host, allowPrivate);
    };
    const result = await checkHttp(
      target({ config: { url: outside } }),
      { ...env, allowPrivate: false },
      resolve,
    );
    expect(asked).toHaveLength(2);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("private");
  });

  it("keeps the login away from another site", async () => {
    const seen: Array<string | undefined> = [];
    const other = await serve((req, res) => {
      seen.push(req.headers.authorization);
      res.end();
    });
    const url = await serve((req, res) => {
      seen.push(req.headers.authorization);
      res.statusCode = 302;
      res.setHeader("location", other);
      res.end();
    });
    await checkHttp(
      target({
        config: { url, authType: "bearer" },
        secrets: { token: "secret" },
      }),
      env,
    );
    expect(seen).toEqual(["Bearer secret", undefined]);
  });

  it("stops after too many redirects", async () => {
    const url = await serve((_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "/again");
      res.end();
    });
    expect(await run({ url })).toMatchObject({
      ok: false,
      message: "Too many redirects",
    });
  });

  it("gives up on a site that never answers", async () => {
    const hung: http.ServerResponse[] = [];
    const url = await serve((_req, res) => {
      hung.push(res);
    });
    closers.unshift(async () => {
      hung.forEach((res) => res.destroy());
    });
    const started = Date.now();
    const result = await checkHttp(
      target({ config: { url }, timeoutSec: 1 }),
      env,
    );
    expect(result.ok).toBe(false);
    expect(Date.now() - started).toBeLessThan(2500);
  });

  it("stops reading a body that stalls", async () => {
    const hung: http.ServerResponse[] = [];
    const url = await serve((_req, res) => {
      res.write("part");
      hung.push(res);
    });
    closers.unshift(async () => {
      hung.forEach((res) => res.destroy());
    });
    const result = await checkHttp(
      target({ config: { url, keyword: "part" }, timeoutSec: 1 }),
      env,
    );
    expect(result.ok).toBe(true);
  });

  it("reports a refused connection as down, not a throw", async () => {
    expect((await run({ url: "http://127.0.0.1:1/" })).ok).toBe(false);
  });
});

describe("small HTTP pieces", () => {
  it("builds login headers", () => {
    expect(
      authHeaders(
        target({
          config: { authType: "basic", username: "a" },
          secrets: { password: "b" },
        }),
      ).authorization,
    ).toBe(`Basic ${Buffer.from("a:b").toString("base64")}`);
  });

  it("explains keyword results", () => {
    expect(keywordProblem("abc", "", false)).toBe("");
    expect(keywordProblem("abc", "z", false)).toContain("Did not find");
    expect(keywordProblem("abc", "a", true)).toContain("Found");
  });
});

describe("checkTcp", () => {
  it("sees an open port", async () => {
    const server = net.createServer((socket) => socket.end());
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    closers.push(
      () => new Promise<void>((resolve) => server.close(() => resolve())),
    );
    const { port } = server.address() as AddressInfo;
    const result = await checkTcp(
      target({ type: "tcp", config: { target: "127.0.0.1", port } }),
      env,
    );
    expect(result.ok).toBe(true);
  });

  it("sees a closed port", async () => {
    const result = await checkTcp(
      target({ type: "tcp", config: { target: "127.0.0.1", port: 1 } }),
      env,
    );
    expect(result.ok).toBe(false);
  });

  it("refuses a private address without the permission", async () => {
    const result = await checkTcp(
      target({ type: "tcp", config: { target: "127.0.0.1", port: 80 } }),
      { ...env, allowPrivate: false },
    );
    expect(result.ok).toBe(false);
    expect(result.message).toContain("private");
  });
});

describe("DNS pieces", () => {
  it("flattens each record type", () => {
    expect(recordLines(["1.2.3.4"])).toEqual(["1.2.3.4"]);
    expect(recordLines([["v=spf1 ", "-all"]])).toEqual(["v=spf1 -all"]);
    expect(recordLines([{ priority: 10, exchange: "mx.test" }])).toEqual([
      "10 mx.test",
    ]);
    expect(recordLines([{ name: "sip.test", port: 5060 }])).toEqual([
      "sip.test:5060",
    ]);
  });

  it("matches any record", () => {
    expect(matchRecords(["1.2.3.4"], undefined)).toBe(true);
    expect(matchRecords([], undefined)).toBe(false);
    expect(matchRecords(["Mail.Test"], "mail.test")).toBe(true);
    expect(matchRecords(["a"], "b")).toBe(false);
  });
});

describe("judgeCert", () => {
  const cert = { daysLeft: 20, validTo: "2026-12-01", issuer: "CA" };

  it("passes a trusted cert", () => {
    expect(judgeCert(cert, 5, { trusted: true, reason: "" }).ok).toBe(true);
  });

  it("fails expired and untrusted certs and keeps the date", () => {
    const expired = judgeCert({ ...cert, daysLeft: -1 }, 5, {
      trusted: true,
      reason: "",
    });
    const untrusted = judgeCert(cert, 5, {
      trusted: false,
      reason: "SELF_SIGNED",
    });
    expect(expired.ok).toBe(false);
    expect(untrusted).toMatchObject({
      ok: false,
      message: "SELF_SIGNED",
      cert,
    });
  });
});

describe("ping", () => {
  it("reads iputils lines", () => {
    expect(
      parsePingLine("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"),
    ).toEqual({ kind: "reply", ms: 12.3 });
    expect(parsePingLine("no answer yet for icmp_seq=2")).toEqual({
      kind: "lost",
    });
    expect(parsePingLine("PING 1.1.1.1 (1.1.1.1) 56(84) bytes")).toBeNull();
  });

  function fakeProcess() {
    let send: (chunk: string) => void = () => undefined;
    const run = vi.fn(async () => ({
      pid: 1,
      onStdout: (listener: (chunk: string) => void) => {
        send = listener;
      },
      onStderr: () => undefined,
      exited: new Promise<{ code: number; signal: null }>(() => undefined),
      kill: vi.fn(),
    }));
    return {
      run,
      say: (chunk: string) => send(chunk),
      ctx: { process: { run } } as unknown as Pick<PluginContext, "process">,
    };
  }

  const monitor = target({
    type: "ping",
    intervalSec: 60,
    config: { target: "1.1.1.1" },
  });

  it("keeps one process across checks, so the audit log stays quiet", async () => {
    const fake = fakeProcess();
    let now = 1_000_000;
    const pool = new PingPool(fake.ctx, "linux", () => now, 0);
    await pool.check(monitor, true);
    fake.say("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9 ms\n");
    const first = await pool.check(monitor, true);
    expect(first).toMatchObject({ ok: true, latencyMs: 9 });
    now += 60_000;
    fake.say("64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=11 ms\n");
    await pool.check(monitor, true);
    expect(fake.run).toHaveBeenCalledTimes(1);
  });

  it("goes down when replies stop", async () => {
    const fake = fakeProcess();
    let now = 1_000_000;
    const pool = new PingPool(fake.ctx, "linux", () => now, 0);
    await pool.check(monitor, true);
    fake.say("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9 ms\n");
    now += 120_000;
    expect((await pool.check(monitor, true)).ok).toBe(false);
  });

  it("joins a line split across chunks", async () => {
    const fake = fakeProcess();
    const pool = new PingPool(fake.ctx, "linux", () => 1000, 0);
    await pool.check(monitor, true);
    fake.say("64 bytes from 1.1.1.1: ");
    fake.say("icmp_seq=1 ttl=57 time=7.5 ms\n");
    expect((await pool.check(monitor, true)).latencyMs).toBe(8);
  });

  it("starts again when the target changes", async () => {
    const fake = fakeProcess();
    const pool = new PingPool(fake.ctx, "linux", () => 1000, 0);
    await pool.check(monitor, true);
    await pool.check({ ...monitor, config: { target: "8.8.8.8" } }, true);
    expect(fake.run).toHaveBeenCalledTimes(2);
  });

  it("says so off Linux", async () => {
    const pool = new PingPool(fakeProcess().ctx, "win32");
    expect((await pool.check(monitor, true)).message).toBe(PING_UNAVAILABLE);
  });

  it("refuses a private target without the permission", async () => {
    const fake = fakeProcess();
    const pool = new PingPool(fake.ctx, "linux", () => 1000, 0);
    const result = await pool.check(
      { ...monitor, config: { target: "10.0.0.1" } },
      false,
    );
    expect(result.ok).toBe(false);
    expect(fake.run).not.toHaveBeenCalled();
  });
});

function fakeRun(
  reply: Partial<Awaited<ReturnType<RemoteRun>>>,
): RemoteRun & { calls: string[] } {
  const calls: string[] = [];
  const run = (async (_host, _as, command) => {
    calls.push(command);
    return { stdout: "", stderr: "", code: 0, timedOut: false, ...reply };
  }) as unknown as RemoteRun & { calls: string[] };
  run.calls = calls;
  return run;
}

describe("SSH checks", () => {
  const onHost = { hostId: 3 };

  it("judges containers", () => {
    expect(judgeContainer("running|healthy\n", "web")).toBe("");
    expect(judgeContainer("running|\n", "web")).toBe("");
    expect(judgeContainer("running|unhealthy\n", "web")).toContain("unhealthy");
    expect(judgeContainer("exited|\n", "web")).toContain("exited");
  });

  it("refuses names that could escape quoting", async () => {
    const run = fakeRun({});
    const result = await checkDocker(
      target({
        ...onHost,
        type: "docker",
        config: { container: "a; rm -rf /" },
      }),
      run,
    );
    expect(result.ok).toBe(false);
    expect(run.calls).toEqual([]);
  });

  it("reads a running container", async () => {
    const result = await checkDocker(
      target({ ...onHost, type: "docker", config: { container: "web" } }),
      fakeRun({ stdout: "running|healthy\n" }),
    );
    expect(result.ok).toBe(true);
  });

  it("explains a missing tool", async () => {
    const result = await checkDocker(
      target({ ...onHost, type: "docker", config: { container: "web" } }),
      fakeRun({ code: 127 }),
    );
    expect(result.message).toContain("not installed");
  });

  it("reads a unit", async () => {
    const up = await checkSystemd(
      target({ ...onHost, type: "systemd", config: { unit: "nginx.service" } }),
      fakeRun({ stdout: "active\n" }),
    );
    const failed = await checkSystemd(
      target({ ...onHost, type: "systemd", config: { unit: "nginx.service" } }),
      fakeRun({ stdout: "failed\n", code: 3 }),
    );
    expect(up.ok).toBe(true);
    expect(failed).toMatchObject({
      ok: false,
      message: "nginx.service is failed",
    });
  });

  it("uses a command's exit code and keyword", async () => {
    const monitor = target({
      ...onHost,
      type: "command",
      config: { command: "true", keyword: "yes" },
    });
    expect((await checkCommand(monitor, fakeRun({ stdout: "yes" }))).ok).toBe(
      true,
    );
    expect((await checkCommand(monitor, fakeRun({ stdout: "no" }))).ok).toBe(
      false,
    );
    expect((await checkCommand(monitor, fakeRun({ code: 2 }))).message).toBe(
      "Exit code 2",
    );
  });

  it("wraps a failed connection as a result", async () => {
    const run: RemoteRun = async () => {
      throw new Error("no route");
    };
    const result = await checkSystemd(
      target({ ...onHost, type: "systemd", config: { unit: "a.service" } }),
      run,
    );
    expect(result).toMatchObject({ ok: false, message: "no route" });
  });
});

describe("Check from a host", () => {
  it("keeps secrets out of the command line", () => {
    const monitor = target({
      config: { url: "https://a.test", authType: "bearer" },
      secrets: { token: "hunter2", headers: { "x-key": "abc" } },
    });
    expect(curlCommand(monitor)).not.toContain("hunter2");
    expect(curlConfig(monitor)).toContain("hunter2");
    expect(curlConfig(monitor)).toContain("x-key: abc");
  });

  it("escapes curl config values", () => {
    expect(curlValue('a"b\\c\nd')).toBe('"a\\"b\\\\c\\nd"');
  });

  const result = (stdout: string, code = 0) => ({
    stdout,
    stderr: "boom",
    code,
    timedOut: false,
  });

  it("reads curl's last line", () => {
    const monitor = target({ config: { keyword: "hello" } });
    expect(
      judgeCurl(monitor, result("hello\n__TERMIX_UPTIME__200 0.123")),
    ).toMatchObject({ ok: true, latencyMs: 123 });
    expect(judgeCurl(monitor, result("bye\n__TERMIX_UPTIME__200 0.1")).ok).toBe(
      false,
    );
    expect(judgeCurl(monitor, result("__TERMIX_UPTIME__500 0.1")).message).toBe(
      "Status 500",
    );
    expect(judgeCurl(monitor, result("", 127)).message).toContain("curl");
    expect(judgeCurl(monitor, result("", 7)).message).toBe("boom");
  });

  it("reads TCP, ping and DNS output", () => {
    expect(judgeTcp(result("12\n"), 22)).toMatchObject({
      ok: true,
      latencyMs: 12,
    });
    expect(judgeTcp(result("", 1), 22).ok).toBe(false);
    expect(
      judgePing(result("64 bytes from a: icmp_seq=1 time=4.2 ms\n")),
    ).toMatchObject({ ok: true, latencyMs: 4 });
    expect(judgePing(result("nothing")).ok).toBe(false);
    expect(judgeDns(result("1.2.3.4\n"), "1.2.3").ok).toBe(true);
    expect(judgeDns(result(""), undefined).ok).toBe(false);
    expect(judgeDns(result("NO_TOOL\n"), undefined).message).toContain("dig");
  });

  it("reads openssl output", () => {
    const later = new Date(Date.now() + 20 * 86_400_000).toUTCString();
    const text = `Verify return code: 0 (ok)\nnotAfter=${later}\nissuer=C = US, O = Lets Encrypt, CN = R3\n`;
    const read = judgeOpenssl(result(text), false);
    expect(read.ok).toBe(true);
    expect(read.cert?.issuer).toBe("Lets Encrypt");
    expect(read.cert?.daysLeft).toBeGreaterThanOrEqual(19);

    const untrusted = text.replace("0 (ok)", "18 (self-signed certificate)");
    expect(judgeOpenssl(result(untrusted), false).ok).toBe(false);
    expect(judgeOpenssl(result(untrusted), true).ok).toBe(true);
  });
});
