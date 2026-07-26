import type { LlmWorkload, Settings } from "../types";
import { PROVIDER_BY_ID } from "./providers";
import { cloudToken } from "../cloud/client";
import { isAiPassConnected } from "../aipass/client";

/** Whether the provider serving `workload` has a usable API key configured. */
export function hasProviderKey(settings: Settings, workload: LlmWorkload): boolean {
  const info = PROVIDER_BY_ID[settings.llmProviders[workload]];
  if (info.id === "aipass") {
    return isAiPassConnected() && !!settings.models.aipass[workload];
  }
  // Hosted "parley" provider: signed-in (a session token) IS the gate — there's
  // no API key; auth rides as the bearer token.
  if (info.id === "parley") return cloudToken() != null;
  // Local providers (Ollama) run without a key.
  if (info.requiresKey === false) return true;
  return !!settings[info.apiKeyField!].trim();
}
