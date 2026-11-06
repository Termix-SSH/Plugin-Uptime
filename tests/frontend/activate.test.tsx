import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import { BeatBar } from "../../src/frontend/BeatBar";
import { parseHeaders } from "../../src/frontend/MonitorEditor";
import { targetOf, uptimeTone } from "../../src/frontend/format";
import { cardEntries } from "../../src/frontend/UptimeCard";
import type { MonitorView } from "../../src/shared/types";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const monitor = {
  id: 1,
  key: "k",
  name: "Website",
  type: "http",
  groupName: "",
  tags: [],
  config: { url: "https://a.test" },
  hasSecrets: false,
  hostId: null,
  fromHostId: null,
  intervalSec: 60,
  retries: 1,
  retryIntervalSec: 30,
  timeoutSec: 10,
  resendMinutes: 0,
  enabled: true,
  access: "owner",
  owner: true,
  status: "up",
  statusSince: 1,
  lastCheckAt: 2,
  latencyMs: 40,
  message: "Status 200",
  cert: null,
  uptime: { day: 100, week: 100, month: 99.5, quarter: null },
  beats: [{ t: 1, s: "up", ms: 40 }],
  watching: true,
} as unknown as MonitorView;

function responses(url: string) {
  const path = url.split("?")[0];
  if (path.endsWith("/monitors")) return { monitors: [monitor] };
  if (path.endsWith("/permissions")) {
    return {
      manage: true,
      publish: true,
      privateTargets: true,
      runCommands: true,
      publicPages: true,
      minIntervalSec: 20,
      defaultIntervalSec: 60,
    };
  }
  return {};
}

const api = {
  get: vi.fn(async (url: string) => ({ data: responses(url) })),
  post: vi.fn(async () => ({ data: {} })),
  put: vi.fn(async () => ({ data: {} })),
  delete: vi.fn(async () => ({ data: {} })),
} as never;

describe(`${manifest.id} frontend`, () => {
  it("registers the tab, card and rail item", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual(["uptime"]);
    expect(rendered.registered.dashboardCards()).toEqual(["uptime-overview"]);
    expect(rendered.registered.railItems().map((item) => item.id)).toEqual([
      "uptime",
    ]);
    expect(rendered.registered.slot("host-page.tiles")).toHaveLength(1);
    expect(rendered.registered.extensions("homepage.widgets")).toEqual([
      "uptime",
    ]);
  });

  it("lists monitors with their status", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales, api });
    rendered.renderTab("uptime", { isVisible: true });
    expect(await screen.findByText("Website")).toBeTruthy();
    expect(screen.getByText("https://a.test")).toBeTruthy();
    expect(await screen.findByText("Status pages")).toBeTruthy();
  });
});

describe("cards and host panels", () => {
  it("shows monitors on the dashboard card", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales, api });
    rendered.renderDashboardCard("uptime-overview");
    expect(await screen.findByText("Website")).toBeTruthy();
  });

  it("shows a host's monitors on the host page tile", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api,
      permissions: ["uptime.view"],
    });
    await new Promise((done) => setTimeout(done, 0));
    rendered.renderSlot("host-page.tiles", { hostId: 1, isVisible: true });
    expect(await screen.findByText("Website")).toBeTruthy();
  });

  it("offers a card per monitor in the add list", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales, api });
    const entries = await cardEntries(((key: string) => key) as never);
    expect(entries.map((entry) => entry.key)).toEqual([
      "overview",
      "attention",
      "monitor:k",
    ]);
  });
});

describe("BeatBar", () => {
  it("draws one bar per check and pads the rest", () => {
    const { container } = render(
      <BeatBar
        count={5}
        beats={[
          { t: 1, s: "up", ms: 3 },
          { t: 2, s: "down", ms: null },
        ]}
      />,
    );
    const bars = container.querySelectorAll("span");
    expect(bars).toHaveLength(5);
    expect(bars[4].className).toContain("bg-destructive");
    expect(bars[3].className).toContain("bg-green-500");
  });

  it("keeps only the newest checks", () => {
    const beats = Array.from({ length: 10 }, (_, t) => ({
      t,
      s: "up" as const,
      ms: 1,
    }));
    const { container } = render(<BeatBar count={3} beats={beats} />);
    expect(container.querySelectorAll("span")).toHaveLength(3);
  });
});

describe("helpers", () => {
  it("reads header lines", () => {
    expect(parseHeaders("A: b\nbad line\nC-D: e: f\n")).toEqual({
      A: "b",
      "C-D": "e: f",
    });
  });

  it("names a target", () => {
    expect(targetOf(monitor)).toBe("https://a.test");
    expect(
      targetOf({
        ...monitor,
        type: "tcp",
        config: { target: "a", port: 22 },
      }),
    ).toBe("a:22");
    expect(
      targetOf({ ...monitor, type: "docker", config: { container: "c" } }, "h"),
    ).toBe("c | h");
  });

  it("colors uptime", () => {
    expect(uptimeTone(null)).toBe("default");
    expect(uptimeTone(100)).toBe("ok");
    expect(uptimeTone(97)).toBe("warn");
    expect(uptimeTone(50)).toBe("bad");
  });
});
