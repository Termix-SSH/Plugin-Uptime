import { describe, expect, it } from "vitest";
import {
  applyResult,
  certStep,
  freshState,
  reminderDue,
  type RunState,
} from "../../src/backend/state";

const ok = { ok: true, latencyMs: 12, message: "fine" };
const bad = { ok: false, latencyMs: null, message: "broken" };

function run(state: RunState, result: typeof ok | typeof bad, retries = 1) {
  return applyResult(state, result, { retries, maintenance: false, now: 1000 });
}

describe("applyResult", () => {
  it("goes up with no alert on the first good check", () => {
    const step = run(freshState(), ok);
    expect(step.state.status).toBe("up");
    expect(step.transition).toBeNull();
  });

  it("retries before going down, then alerts once", () => {
    const first = run(freshState(), bad);
    expect(first.state.status).toBe("pending");
    expect(first.retry).toBe(true);
    expect(first.transition).toBeNull();

    const second = run(first.state, bad);
    expect(second.state.status).toBe("down");
    expect(second.transition).toBe("down");

    const third = run(second.state, bad);
    expect(third.state.status).toBe("down");
    expect(third.transition).toBeNull();
  });

  it("goes down at once with no retries", () => {
    expect(run(freshState(), bad, 0).transition).toBe("down");
  });

  it("recovers from pending with no alert", () => {
    const pending = run(freshState(), bad).state;
    const step = run(pending, ok);
    expect(step.state.status).toBe("up");
    expect(step.transition).toBeNull();
  });

  it("alerts when an open incident recovers", () => {
    const down = run(freshState(), bad, 0).state;
    const step = run(down, ok);
    expect(step.transition).toBe("up");
    expect(step.state.open).toBe(false);
  });

  it("stays down after a restart that lost the failure count", () => {
    const restored: RunState = { ...freshState(), status: "down", open: true };
    const step = run(restored, bad, 3);
    expect(step.state.status).toBe("down");
    expect(step.transition).toBeNull();
    expect(step.retry).toBe(false);
  });

  it("opens no incident in maintenance", () => {
    const step = applyResult(freshState(), bad, {
      retries: 0,
      maintenance: true,
      now: 1000,
    });
    expect(step.state.status).toBe("maintenance");
    expect(step.transition).toBeNull();
    expect(step.state.open).toBe(false);
  });

  it("keeps since until the status changes", () => {
    const up = run(freshState(), ok).state;
    const later = applyResult(up, ok, {
      retries: 1,
      maintenance: false,
      now: 5000,
    }).state;
    expect(later.since).toBe(1000);
  });
});

describe("reminderDue", () => {
  const down = { ...freshState(), open: true, lastAlertAt: 0 };

  it("waits for the gap", () => {
    expect(reminderDue(down, 10, 9 * 60_000)).toBe(false);
    expect(reminderDue(down, 10, 10 * 60_000)).toBe(true);
  });

  it("stays quiet when turned off or closed", () => {
    expect(reminderDue(down, 0, 1e12)).toBe(false);
    expect(reminderDue({ ...down, open: false }, 10, 1e12)).toBe(false);
  });
});

describe("certStep", () => {
  it("has nothing to say early", () => {
    expect(certStep(60, 30)).toBeNull();
  });

  it("moves through the steps", () => {
    expect(certStep(30, 30)).toBe(30);
    expect(certStep(20, 30)).toBe(30);
    expect(certStep(14, 30)).toBe(14);
    expect(certStep(3, 30)).toBe(7);
  });

  it("starts at the user's own number", () => {
    expect(certStep(12, 14)).toBe(14);
    expect(certStep(5, 10)).toBe(7);
  });
});
