import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ALL_PERMISSIONS, startServer, type TestServer } from "./helpers";

let site: http.Server;
let siteUrl = "";
let siteStatus = 200;

beforeAll(async () => {
  site = http.createServer((_req, res) => {
    res.statusCode = siteStatus;
    res.end("hello");
  });
  await new Promise<void>((resolve) => site.listen(0, "127.0.0.1", resolve));
  siteUrl = `http://127.0.0.1:${(site.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => site.close(() => resolve()));
});

let server: TestServer;
afterEach(async () => {
  siteStatus = 200;
  await server.close();
});

const httpMonitor = () => ({
  name: "Site",
  type: "http",
  config: { url: siteUrl },
  retries: 0,
});

const add = async (body: unknown) => server.request("POST", "/monitors", body);

async function tickUntilChecked() {
  await server.mock.runScheduled();
}

describe("monitors", () => {
  it("adds, lists, changes and deletes", async () => {
    server = await startServer();
    const created = await add(httpMonitor());
    expect(created.status).toBe(201);
    expect(created.body.access).toBe("owner");
    expect(created.body.watching).toBe(true);

    const id = created.body.id;
    const changed = await server.request("PUT", `/monitors/${id}`, {
      ...httpMonitor(),
      name: "Renamed",
    });
    expect(changed.body.name).toBe("Renamed");

    const list = await server.request("GET", "/monitors");
    expect(list.body.monitors).toHaveLength(1);

    expect((await server.request("DELETE", `/monitors/${id}`)).status).toBe(
      200,
    );
    expect((await server.request("GET", "/monitors")).body.monitors).toEqual(
      [],
    );
  });

  it("checks on the timer, opens an incident and alerts", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    await tickUntilChecked();
    let seen = (await server.request("GET", `/monitors/${body.id}`)).body;
    expect(seen.status).toBe("up");

    siteStatus = 500;
    await server.request("POST", `/monitors/${body.id}/run`);
    seen = (await server.request("GET", `/monitors/${body.id}`)).body;
    expect(seen.status).toBe("down");
    expect(seen.message).toBe("Status 500");

    const incidents = (await server.request("GET", "/incidents")).body;
    expect(incidents.incidents).toHaveLength(1);
    expect(incidents.incidents[0].endedAt).toBeNull();
    expect(
      server.mock.notifications.map((n) => n.notification.category),
    ).toEqual(["uptime.down"]);

    siteStatus = 200;
    await server.request("POST", `/monitors/${body.id}/run`);
    const closed = (await server.request("GET", "/incidents")).body;
    expect(closed.incidents[0].endedAt).not.toBeNull();
    expect(server.mock.notifications.at(-1)?.notification.category).toBe(
      "uptime.up",
    );
    expect(server.mock.operationEvents?.map((e) => e.eventId)).toEqual([
      "uptime.monitor-down",
      "uptime.monitor-up",
    ]);
  });

  it("sends no alert to someone who turned them off", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    await server.request("POST", `/monitors/${body.id}/watch`, { on: false });
    siteStatus = 500;
    await server.request("POST", `/monitors/${body.id}/run`);
    expect(server.mock.notifications).toEqual([]);
  });

  it("pauses and resumes", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    const paused = await server.request("POST", `/monitors/${body.id}/pause`, {
      paused: true,
    });
    expect(paused.body.status).toBe("paused");
    const resumed = await server.request("POST", `/monitors/${body.id}/pause`, {
      paused: false,
    });
    expect(resumed.body.enabled).toBe(true);
    expect(resumed.body.status).not.toBe("paused");
  });

  it("validates input", async () => {
    server = await startServer();
    expect((await add({ ...httpMonitor(), name: " " })).status).toBe(400);
    expect((await add({ name: "x", type: "nope", config: {} })).status).toBe(
      400,
    );
    expect(
      (await add({ name: "x", type: "http", config: { url: "ftp://a" } }))
        .status,
    ).toBe(400);
    expect(
      (
        await add({
          name: "x",
          type: "http",
          config: { url: "http://user:pw@a.test" },
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await add({
          name: "x",
          type: "tcp",
          config: { target: "a;b", port: 1 },
        })
      ).status,
    ).toBe(400);
    expect(
      (await add({ name: "x", type: "docker", config: { container: "web" } }))
        .status,
    ).toBe(400);
  });

  it("clamps timing, with a floor for SSH types", async () => {
    server = await startServer();
    const { body } = await add({
      name: "Unit",
      type: "systemd",
      hostId: 1,
      config: { unit: "nginx.service" },
      intervalSec: 5,
    });
    expect(body.intervalSec).toBe(60);
  });
});

describe("secrets", () => {
  it("are never sent back and survive an edit", async () => {
    server = await startServer();
    const { body, text } = await (async () => {
      const created = await add({
        ...httpMonitor(),
        config: { url: siteUrl, authType: "bearer" },
        secrets: { token: "hunter2" },
      });
      return created;
    })();
    expect(text).not.toContain("hunter2");
    expect(body.hasSecrets).toBe(true);

    await server.request("PUT", `/monitors/${body.id}`, {
      ...httpMonitor(),
      config: { url: siteUrl, authType: "bearer" },
    });
    const read = await server.request("GET", `/monitors/${body.id}`);
    expect(read.text).not.toContain("hunter2");
    expect(read.body.hasSecrets).toBe(true);
  });
});

describe("private targets", () => {
  const noPrivate = ALL_PERMISSIONS.filter(
    (p) => p !== "uptime.private-targets",
  );

  it("are refused on save without the permission", async () => {
    server = await startServer({ permissions: noPrivate });
    const result = await add(httpMonitor());
    expect(result.status).toBe(403);
    expect(result.body.code).toBe("private_target");
  });

  it("are refused for tcp, ping and tls too", async () => {
    server = await startServer({ permissions: noPrivate });
    for (const body of [
      { name: "a", type: "tcp", config: { target: "10.0.0.1", port: 22 } },
      { name: "b", type: "ping", config: { target: "192.168.1.1" } },
      { name: "c", type: "tls", config: { target: "127.0.0.1" } },
      {
        name: "d",
        type: "dns",
        config: { target: "a.test", dnsServer: "10.0.0.53" },
      },
    ]) {
      expect((await add(body)).status).toBe(403);
    }
  });

  it("are fine from a chosen host", async () => {
    server = await startServer({ permissions: noPrivate });
    const result = await add({
      name: "Through a host",
      type: "tcp",
      fromHostId: 1,
      config: { target: "10.0.0.1", port: 22 },
    });
    expect(result.status).toBe(201);
  });
});

describe("command monitors", () => {
  const command = {
    name: "Cmd",
    type: "command",
    hostId: 1,
    config: { command: "true" },
  };

  it("need run-commands", async () => {
    server = await startServer({
      permissions: ALL_PERMISSIONS.filter((p) => p !== "uptime.run-commands"),
    });
    expect((await add(command)).status).toBe(403);
  });
});

describe("sharing", () => {
  it("gives a shared user the level they were given", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    await server.request("PUT", `/monitors/${body.id}/shares`, {
      shares: [{ userId: "u2", level: "view" }],
    });

    server.mock.setActor("u2");
    const list = await server.request("GET", "/monitors");
    expect(list.body.monitors[0].access).toBe("view");
    expect(
      (
        await server.request("PUT", `/monitors/${body.id}`, {
          ...httpMonitor(),
          name: "Mine now",
        })
      ).status,
    ).toBe(403);
    expect(
      (await server.request("DELETE", `/monitors/${body.id}`)).status,
    ).toBe(403);

    server.mock.setActor("u3");
    expect((await server.request("GET", "/monitors")).body.monitors).toEqual(
      [],
    );
    expect((await server.request("GET", `/monitors/${body.id}`)).status).toBe(
      404,
    );
  });

  it("hides a stored command from a viewer", async () => {
    server = await startServer();
    const { body } = await add({
      name: "Cmd",
      type: "command",
      hostId: 1,
      config: { command: "cat /secret/path" },
    });
    await server.request("PUT", `/monitors/${body.id}/shares`, {
      shares: [{ userId: "u2", level: "view" }],
    });
    server.mock.setActor("u2");
    const read = await server.request("GET", `/monitors/${body.id}`);
    expect(read.text).not.toContain("/secret/path");
  });

  it("lists who it can be shared with", async () => {
    server = await startServer();
    const { status, body } = await server.request("GET", "/share-targets");
    expect(status).toBe(200);
    expect(body.users).toEqual([{ id: "u2", username: "two" }]);
    expect(body.roles[0].name).toBe("ops");
  });

  it("wants a user or a role, not both", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    const result = await server.request("PUT", `/monitors/${body.id}/shares`, {
      shares: [{ userId: "u2", roleId: 5, level: "view" }],
    });
    expect(result.status).toBe(400);
  });
});

describe("push", () => {
  const push = { name: "Backup", type: "push", intervalSec: 3600, config: {} };
  const tokenOf = (url: string) => url.split("/").at(-1) as string;

  it("takes the URL once and records calls", async () => {
    server = await startServer();
    const { body } = await add(push);
    expect(body.pushUrl).toContain(
      "https://termix.test/plugin-api/uptime/push/",
    );
    const again = await server.request("GET", `/monitors/${body.id}`);
    expect(again.body.pushUrl).toBeUndefined();
    expect(again.text).not.toContain(tokenOf(body.pushUrl));

    const call = await server.request(
      "GET",
      `/push/${tokenOf(body.pushUrl)}?msg=done&ping=12`,
    );
    expect(call.status).toBe(200);
    const seen = (await server.request("GET", `/monitors/${body.id}`)).body;
    expect(seen).toMatchObject({
      status: "up",
      message: "done",
      latencyMs: 12,
    });
  });

  it("marks a reported failure", async () => {
    server = await startServer();
    const { body } = await add(push);
    await server.request("POST", `/push/${tokenOf(body.pushUrl)}`, {
      status: "down",
      msg: "disk full",
    });
    const seen = (await server.request("GET", `/monitors/${body.id}`)).body;
    expect(seen).toMatchObject({ status: "down", message: "disk full" });
  });

  it("refuses an unknown token and an old one", async () => {
    server = await startServer();
    expect((await server.request("GET", "/push/nope")).status).toBe(404);
    const { body } = await add(push);
    const fresh = await server.request("POST", `/monitors/${body.id}/push-url`);
    expect(
      (await server.request("GET", `/push/${tokenOf(body.pushUrl)}`)).status,
    ).toBe(404);
    expect(
      (await server.request("GET", `/push/${tokenOf(fresh.body.pushUrl)}`))
        .status,
    ).toBe(200);
  });
});

describe("status pages", () => {
  async function publishOne(extra: object = {}) {
    const { body } = await add(httpMonitor());
    await server.request("POST", `/monitors/${body.id}/run`);
    const page = await server.request("POST", "/pages", {
      slug: "status",
      title: "Our <status>",
      published: true,
      groups: [{ name: "Web", monitorKeys: [body.key] }],
      ...extra,
    });
    expect(page.status).toBe(201);
    return body;
  }

  it("shows names and states and never a target or error", async () => {
    server = await startServer();
    siteStatus = 500;
    await publishOne();
    const data = await server.request("GET", "/status/status/data");
    expect(data.body.overall).toBe("outage");
    expect(data.body.groups[0].monitors[0].name).toBe("Site");
    expect(data.text).not.toContain(siteUrl);
    expect(data.text).not.toContain("127.0.0.1");
    expect(data.text).not.toContain("Status 500");

    const page = await server.request("GET", "/status/status");
    expect(page.status).toBe(200);
    expect(page.text).toContain("Site");
    expect(page.text).toContain("Our &lt;status&gt;");
    expect(page.text).not.toContain("<script");
    expect(page.text).not.toContain("127.0.0.1");
  });

  it("is a 404 until published", async () => {
    server = await startServer();
    await publishOne({ published: false });
    expect((await server.request("GET", "/status/status")).status).toBe(404);
    expect((await server.request("GET", "/status/none")).status).toBe(404);
  });

  it("goes dark when the admin turns pages off", async () => {
    server = await startServer();
    await publishOne();
    await server.mock.ctx.settings.set("publicPages", false);
    expect((await server.request("GET", "/status/status")).status).toBe(404);
  });

  it("refuses monitors the author can't edit", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    await server.request("PUT", `/monitors/${body.id}/shares`, {
      shares: [{ userId: "u2", level: "view" }],
    });
    server.mock.setActor("u2");
    const page = await server.request("POST", "/pages", {
      slug: "steal",
      title: "Theirs",
      groups: [{ name: "", monitorKeys: [body.key] }],
    });
    expect(page.status).toBe(403);
  });

  it("needs the publish permission", async () => {
    server = await startServer({
      permissions: ALL_PERMISSIONS.filter((p) => p !== "uptime.publish"),
    });
    expect((await server.request("GET", "/pages")).status).toBe(403);
  });

  it("refuses a taken or bad address", async () => {
    server = await startServer();
    await publishOne();
    const again = { slug: "status", title: "Two", groups: [] };
    expect((await server.request("POST", "/pages", again)).status).toBe(409);
    expect(
      (await server.request("POST", "/pages", { ...again, slug: "Bad Slug" }))
        .status,
    ).toBe(400);
  });

  it("shows notes until a week after they are resolved", async () => {
    server = await startServer();
    await publishOne();
    const { id } = (await server.request("GET", "/pages")).body.pages[0];
    await server.request("POST", `/pages/${id}/notes`, {
      title: "Planned work",
      body: "<b>Tonight</b>",
      level: "warning",
    });
    const page = await server.request("GET", "/status/status");
    expect(page.text).toContain("Planned work");
    expect(page.text).toContain("&lt;b&gt;Tonight");
  });
});

describe("maintenance", () => {
  it("silences failures inside a window", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    const now = Date.now();
    const saved = await server.request("POST", "/maintenance", {
      name: "Work",
      scope: "all",
      kind: "once",
      startsAt: now - 1000,
      endsAt: now + 60_000,
    });
    expect(saved.status).toBe(201);
    siteStatus = 500;
    await server.request("POST", `/monitors/${body.id}/run`);
    const seen = (await server.request("GET", `/monitors/${body.id}`)).body;
    expect(seen.status).toBe("maintenance");
    expect(server.mock.notifications).toEqual([]);
    expect(
      (await server.request("GET", "/maintenance")).body.windows[0],
    ).toMatchObject({ active: true });
  });

  it("can't name someone else's monitors", async () => {
    server = await startServer();
    const { body } = await add(httpMonitor());
    server.mock.setActor("u2");
    const result = await server.request("POST", "/maintenance", {
      name: "Sneaky",
      scope: "monitors",
      monitorKeys: [body.key],
      kind: "once",
      startsAt: 1,
      endsAt: 2,
    });
    expect(result.status).toBe(403);
  });
});

describe("permissions", () => {
  it("keeps viewers from writing", async () => {
    server = await startServer({ permissions: ["uptime.view"] });
    expect((await add(httpMonitor())).status).toBe(403);
    expect((await server.request("GET", "/monitors")).status).toBe(200);
  });
});
