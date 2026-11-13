import http from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import express, { type Router } from "express";
import {
  createMockCtx,
  createTestDb,
  type MockPluginContext,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";
import type { CheckTarget } from "../../src/backend/checks/types";

export const manifest = manifestJson as unknown as PluginManifest;

export const ALL_PERMISSIONS = [
  "uptime.view",
  "uptime.manage",
  "uptime.private-targets",
  "uptime.run-commands",
  "uptime.publish",
];

export function target(partial: Partial<CheckTarget>): CheckTarget {
  return {
    id: 1,
    type: "http",
    config: {},
    secrets: {},
    hostId: null,
    fromHostId: null,
    intervalSec: 60,
    timeoutSec: 2,
    runAs: "u1",
    ...partial,
  };
}

export const env = {
  allowPrivate: true,
  signal: new AbortController().signal,
};

export interface TestServer {
  mock: MockPluginContext;
  request: (
    method: string,
    path: string,
    body?: unknown,
    // Route bodies vary per test; asserting on them is the point.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ) => Promise<{ status: number; body: any; text: string }>;
  close: () => Promise<void>;
}

/** The plugin on a real express app. Core's sign in sets the actor. */
export async function startServer(
  options: { permissions?: string[]; actor?: string } = {},
): Promise<TestServer> {
  let router: Router | null = null;
  const db = await createTestDb(path.resolve(__dirname, "../.."));
  db.sqlite.exec(
    "INSERT INTO users (id, username) VALUES ('u1', 'one'), ('u2', 'two'), ('u3', 'three')",
  );
  const mock = createMockCtx({
    sandbox: true,
    db: db.database,
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    actor: options.actor ?? "u1",
    router: () => (router = express.Router()),
    permissions: options.permissions ?? ALL_PERMISSIONS,
    dataDir: mkdtempSync(path.join(tmpdir(), "uptime-test-")),
    baseUrl: "https://termix.test",
    shareableUsers: [{ id: "u2", username: "two" }],
    shareableRoles: [{ id: 5, name: "ops", displayName: "Ops" }],
    hosts: [{ id: 1, name: "box", ip: "1.1.1.1", userId: "u1" }] as never,
  });

  const { activate } = await import("../../src/backend/index.js");
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => router!(req, res, next));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    mock,
    async request(method, route, body) {
      const res = await fetch(`http://127.0.0.1:${port}${route}`, {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      let parsed: unknown = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        // The status page answers HTML.
      }
      return { status: res.status, body: parsed, text };
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
