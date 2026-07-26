import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(
    (
      _event: string,
      _handler: (event: {
        payload: { configured: boolean; connected: boolean };
      }) => void,
    ) => Promise.resolve(() => {}),
  ),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: mocks.invoke,
  Channel: class {
    onmessage: (message: unknown) => void = () => {};
  },
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: mocks.listen,
}));

import {
  aiPassNativeFetch,
  getAiPassStatusSnapshot,
  initializeAiPassStatus,
} from "./client";

describe("AI Pass native fetch bridge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
  });

  it("returns channel bytes without ever adding a browser bearer credential", async () => {
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "aipass_chat") {
        const channel = args?.onEvent as { onmessage: (message: unknown) => void };
        queueMicrotask(() => {
          channel.onmessage({
            type: "headers",
            status: 200,
            content_type: "text/event-stream",
          });
          channel.onmessage({ type: "data", data: btoa("data: ok\n\n") });
          channel.onmessage({ type: "done" });
        });
      }
      return Promise.resolve();
    });

    const response = await aiPassNativeFetch("https://aipass.one/oauth2/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: "Bearer browser-placeholder" },
      body: JSON.stringify({ model: "live/model", messages: [] }),
    });

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("data: ok\n\n");
    const [, args] = mocks.invoke.mock.calls.find(([command]) => command === "aipass_chat")!;
    expect(args).toMatchObject({
      body: JSON.stringify({ model: "live/model", messages: [] }),
    });
    expect(JSON.stringify(args).toLowerCase()).not.toContain("authorization");
    expect(JSON.stringify(args)).not.toContain("browser-placeholder");
  });

  it("maps AbortSignal cancellation to the native upstream request", async () => {
    let channel: { onmessage: (message: unknown) => void } | undefined;
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "aipass_chat") {
        channel = args?.onEvent as typeof channel;
        return new Promise(() => {});
      }
      return Promise.resolve();
    });
    const controller = new AbortController();
    const pending = aiPassNativeFetch("https://aipass.one/oauth2/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "live/model", messages: [] }),
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(channel).toBeDefined());
    channel!.onmessage({
      type: "headers",
      status: 200,
      content_type: "text/event-stream",
    });
    const response = await pending;

    controller.abort();

    await expect(response.text()).rejects.toMatchObject({ name: "AbortError" });
    expect(mocks.invoke).toHaveBeenCalledWith(
      "aipass_cancel_chat",
      expect.objectContaining({ requestId: expect.any(String) }),
    );
  });

  it("cancels native work when the stream protocol is invalid", async () => {
    mocks.invoke.mockImplementation((command: string, args?: Record<string, unknown>) => {
      if (command === "aipass_chat") {
        const channel = args?.onEvent as { onmessage: (message: unknown) => void };
        queueMicrotask(() => {
          channel.onmessage({
            type: "headers",
            status: 200,
            content_type: "text/event-stream",
          });
          channel.onmessage({
            type: "headers",
            status: 200,
            content_type: "text/event-stream",
          });
        });
        return new Promise(() => {});
      }
      return Promise.resolve();
    });

    const response = await aiPassNativeFetch("https://aipass.one/oauth2/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "live/model", messages: [] }),
    });

    await expect(response.text()).rejects.toThrow("duplicate headers");
    expect(mocks.invoke).toHaveBeenCalledWith(
      "aipass_cancel_chat",
      expect.objectContaining({ requestId: expect.any(String) }),
    );
  });

  it("does not overwrite a newer status event with a stale status read", async () => {
    let resolveStatus:
      | ((status: { configured: boolean; connected: boolean }) => void)
      | undefined;
    mocks.invoke.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveStatus = resolve;
        }),
    );

    const pending = initializeAiPassStatus();
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("aipass_status"));
    const statusHandler = mocks.listen.mock.calls[0]?.[1] as
      | ((event: { payload: { configured: boolean; connected: boolean } }) => void)
      | undefined;
    expect(statusHandler).toBeDefined();

    statusHandler!({ payload: { configured: true, connected: false } });
    resolveStatus!({ configured: true, connected: true });

    await expect(pending).resolves.toMatchObject({ connected: false });
    expect(getAiPassStatusSnapshot()).toMatchObject({ connected: false });
  });
});
