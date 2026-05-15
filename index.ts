import fs from "node:fs";
import { definePluginEntry, type OpenClawPluginApi } from "./runtime-api.js";
import {
  clawAegisPluginConfigDefinition,
  findUserConfigPath,
} from "./src/config.js";
import { createClawAegisRuntime } from "./src/handlers.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- handlers have heterogeneous signatures; `any` is needed for contravariance
type GenericHookHandler = (event: any, ctx: any) => any;

export function wrapHookFailOpen(
  api: OpenClawPluginApi,
  hookName: string,
  handler: GenericHookHandler,
): GenericHookHandler {
  return async (event, ctx) => {
    try {
      return await handler(event, ctx);
    } catch (error) {
      api.logger.error(
        `[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return undefined;
    }
  };
}

const HOT_RELOAD_POLL_MS = 1000;

// Returns the highest mtime across the candidate user_config.json paths so a
// secplane-pushed override is picked up regardless of which directory it
// landed in (rootDir vs ~/.openclaw/workspace/skills/claw-aegis/...).
function snapshotConfigMtime(rootDir: string | undefined): number {
  const target = findUserConfigPath(rootDir);
  if (!target) return 0;
  try {
    return fs.statSync(target).mtimeMs;
  } catch {
    return 0;
  }
}

export function registerClawAegisPlugin(
  api: OpenClawPluginApi,
  createRuntime: typeof createClawAegisRuntime = createClawAegisRuntime,
): void {
  try {
    // `runtime` is a mutable reference. All hook handlers below dispatch
    // through `runtime.hooks.*` indirectly (via arrow wrappers), so when the
    // hot-reload watcher swaps `runtime` to a freshly-resolved one, the next
    // event picks up the new config without OpenClaw restarting.
    let runtime = createRuntime(api);
    let lastMtime = snapshotConfigMtime(api.rootDir);

    const reload = (): void => {
      try {
        const next = createRuntime(api);
        runtime = next;
        api.logger.info(
          `[claw-aegis] hot-reloaded user_config (mtime=${lastMtime})`,
        );
      } catch (error) {
        api.logger.error(
          `[claw-aegis] hot-reload failed; keeping previous runtime: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    };

    const interval = setInterval(() => {
      const mtime = snapshotConfigMtime(api.rootDir);
      if (mtime !== 0 && mtime !== lastMtime) {
        lastMtime = mtime;
        reload();
      }
    }, HOT_RELOAD_POLL_MS);
    // Don't keep the gateway process alive solely for our poll loop.
    if (typeof interval.unref === "function") interval.unref();

    // Per-hook wrappers that always dispatch to the *current* runtime. We
    // wrap with fail-open exactly as before, just delegating to a getter so
    // hot-reload swaps take effect without re-registering hooks.
    const dispatch =
      (name: keyof typeof runtime.hooks): GenericHookHandler =>
      wrapHookFailOpen(api, String(name), (event, ctx) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fn = runtime.hooks[name] as GenericHookHandler | undefined;
        // Compiled handlers.js may lag behind handlers.ts on a few hooks
        // (before_dispatch / before_agent_reply / llm_output). Silently
        // skip when missing — fail-open without log spam every chat.
        if (typeof fn !== "function") return undefined;
        return fn(event, ctx);
      });

    api.on("gateway_start", dispatch("gateway_start"));
    api.on("message_received", dispatch("message_received"));
    api.on("message_sending", dispatch("message_sending"));
    api.on("before_prompt_build", dispatch("before_prompt_build"));
    api.on("before_dispatch", dispatch("before_dispatch"));
    api.on("before_agent_reply", dispatch("before_agent_reply"));
    api.on("before_tool_call", dispatch("before_tool_call"));
    api.on("after_tool_call", dispatch("after_tool_call"));
    api.on("before_message_write", dispatch("before_message_write"));
    api.on("llm_output", dispatch("llm_output"));
    api.on("agent_end", dispatch("agent_end"));
    api.on("session_end", dispatch("session_end"));
  } catch (error) {
    api.logger.error(
      `[claw-aegis] register failed; fail-open keeps OpenClaw running: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export default definePluginEntry({
  id: "claw-aegis",
  name: "Claw Aegis",
  description: "Minimal safety guard plugin for prompt, tool, and tool-result hardening.",
  configSchema: clawAegisPluginConfigDefinition,
  register(api: OpenClawPluginApi) {
    registerClawAegisPlugin(api);
  },
});
