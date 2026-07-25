import { Channel, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const MAX_REQUEST_BYTES = 4 * 1024 * 1024;

export interface AiPassConnectionStatus {
  configured: boolean;
  connected: boolean;
  displayName?: string | null;
  email?: string | null;
}

type StreamMessage =
  | { type: "headers"; status: number; content_type: string }
  | { type: "data"; data: string }
  | { type: "done" }
  | { type: "error"; message: string };

let connectionStatus: AiPassConnectionStatus = {
  configured: false,
  connected: false,
};
const listeners = new Set<() => void>();
let statusListenerStarted = false;
let statusRevision = 0;

function publishStatus(status: AiPassConnectionStatus) {
  statusRevision += 1;
  connectionStatus = status;
  for (const listener of listeners) listener();
}

function markDisconnected() {
  if (!connectionStatus.connected) return;
  publishStatus({ configured: connectionStatus.configured, connected: false });
}

export function getAiPassStatusSnapshot(): AiPassConnectionStatus {
  return connectionStatus;
}

export function subscribeAiPassStatus(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function isAiPassConnected(): boolean {
  return connectionStatus.connected;
}

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function ensureStatusListener(): Promise<void> {
  if (!inTauri() || statusListenerStarted) return;
  statusListenerStarted = true;
  try {
    await listen<AiPassConnectionStatus>("aipass://status", (event) => {
      publishStatus(event.payload);
    });
  } catch (error) {
    statusListenerStarted = false;
    throw error;
  }
}

export async function initializeAiPassStatus(): Promise<AiPassConnectionStatus> {
  if (!inTauri()) return connectionStatus;
  await ensureStatusListener().catch(() => {});
  const revisionBeforeRead = statusRevision;
  const status = await invoke<AiPassConnectionStatus>("aipass_status");
  // A connect/disconnect event delivered while the read was in flight is newer
  // than its response. Keep the event so startup cannot resurrect stale UI auth.
  if (statusRevision !== revisionBeforeRead) return connectionStatus;
  publishStatus(status);
  return status;
}

export async function connectAiPass(): Promise<AiPassConnectionStatus> {
  if (!inTauri()) throw new Error("AI Pass account connection is available in the desktop app");
  await ensureStatusListener().catch(() => {});
  const status = await invoke<AiPassConnectionStatus>("aipass_connect");
  publishStatus(status);
  return status;
}

export async function disconnectAiPass(): Promise<AiPassConnectionStatus> {
  if (!inTauri()) throw new Error("AI Pass account connection is available in the desktop app");
  await ensureStatusListener().catch(() => {});
  const status = await invoke<AiPassConnectionStatus>("aipass_disconnect");
  publishStatus(status);
  return status;
}

export async function discoverAiPassModels(): Promise<string[]> {
  if (!inTauri()) throw new Error("AI Pass model discovery is available in the desktop app");
  return invoke<string[]>("aipass_models");
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function requestBody(init?: RequestInit): string {
  if ((init?.method ?? "GET").toUpperCase() !== "POST" || typeof init?.body !== "string") {
    throw new Error("AI Pass transport accepts JSON POST requests only");
  }
  if (new TextEncoder().encode(init.body).byteLength > MAX_REQUEST_BYTES) {
    throw new Error("AI Pass request exceeded the size limit");
  }
  return init.body;
}

/**
 * Fetch adapter for the OpenAI-compatible AI SDK provider.
 *
 * The SDK still builds ordinary OpenAI request JSON, but this function never
 * performs browser networking and never receives a bearer token. Rust owns the
 * authenticated request and feeds bounded bytes back through a Tauri Channel.
 */
export const aiPassNativeFetch: typeof globalThis.fetch = async (_input, init) => {
  if (!inTauri()) throw new Error("AI Pass transport is available in the desktop app");
  const body = requestBody(init);
  const requestId = crypto.randomUUID();
  const events = new Channel<StreamMessage>();

  return new Promise<Response>((resolve, reject) => {
    let settledHeaders = false;
    let finished = false;
    let cancellationRequested = false;
    let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
    const cancelNative = () => {
      if (cancellationRequested) return;
      cancellationRequested = true;
      void invoke("aipass_cancel_chat", { requestId });
    };
    const stream = new ReadableStream<Uint8Array>({
      start(value) {
        controller = value;
      },
      cancel() {
        cancelNative();
        finished = true;
        cleanup();
      },
    });

    const cleanup = () => init?.signal?.removeEventListener("abort", onAbort);
    const fail = (message: string, error?: unknown) => {
      if (finished) return;
      finished = true;
      cleanup();
      cancelNative();
      const reason =
        error instanceof Error ? error : new Error(typeof error === "string" ? error : message);
      if (settledHeaders) controller?.error(reason);
      else reject(reason);
    };
    const onAbort = () => {
      fail("AI Pass request cancelled", new DOMException("The operation was aborted", "AbortError"));
    };

    events.onmessage = (message) => {
      if (finished) return;
      try {
        switch (message.type) {
          case "headers": {
            if (settledHeaders) {
              fail("AI Pass transport returned duplicate headers");
              return;
            }
            const response = new Response(stream, {
              status: message.status,
              headers: { "Content-Type": message.content_type },
            });
            settledHeaders = true;
            if (message.status === 401) markDisconnected();
            resolve(response);
            break;
          }
          case "data":
            if (!settledHeaders) {
              fail("AI Pass transport returned data before headers");
              return;
            }
            controller?.enqueue(decodeBase64(message.data));
            break;
          case "done":
            if (!settledHeaders) {
              fail("AI Pass transport ended before headers");
              return;
            }
            finished = true;
            cleanup();
            controller?.close();
            break;
          case "error":
            fail(message.message);
            break;
          default:
            fail("AI Pass transport returned an invalid event");
        }
      } catch (error) {
        fail("AI Pass transport returned invalid response data", error);
      }
    };

    if (init?.signal?.aborted) {
      onAbort();
      return;
    }
    init?.signal?.addEventListener("abort", onAbort, { once: true });
    void invoke("aipass_chat", { body, requestId, onEvent: events })
      .catch((error) => fail("AI Pass request failed", error));
  });
};

export async function cancelAllAiPassWork(): Promise<void> {
  if (!inTauri()) return;
  await invoke("aipass_cancel_all_chat");
}
