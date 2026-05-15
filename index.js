import fs from "node:fs";
import { definePluginEntry } from "./runtime-api.js";
import { clawAegisPluginConfigDefinition, findUserConfigPath } from "./src/config.js";
import { createClawAegisRuntime } from "./src/handlers.js";

function wrapHookFailOpen(api, hookName, handler) {
  return async (event, ctx) => {
    try {
      return await handler(event, ctx);
    } catch (error) {
      api.logger.error(
        `[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`
      );
      return void 0;
    }
  };
}

const HOT_RELOAD_POLL_MS = 1000;
function snapshotConfigMtime(rootDir) {
  const target = findUserConfigPath(rootDir);
  if (!target) return 0;
  try { return fs.statSync(target).mtimeMs; } catch { return 0; }
}

function registerClawAegisPlugin(api, createRuntime = createClawAegisRuntime) {
  try {
    let runtime = createRuntime(api);
    let lastMtime = snapshotConfigMtime(api.rootDir);

    const reload = () => {
      try {
        runtime = createRuntime(api);
        api.logger.info(`[claw-aegis] hot-reloaded user_config (mtime=${lastMtime})`);
      } catch (error) {
        api.logger.error(
          `[claw-aegis] hot-reload failed; keeping previous runtime: ${error instanceof Error ? error.message : String(error)}`
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
    if (typeof interval.unref === "function") interval.unref();

    const dispatch = (name) =>
      wrapHookFailOpen(api, name, (event, ctx) => {
        const fn = runtime.hooks[name];
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
      `[claw-aegis] register failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

var index_default = definePluginEntry({
  id: "claw-aegis",
  name: "Claw Aegis",
  description: "Minimal safety guard plugin for prompt, tool, and tool-result hardening.",
  configSchema: clawAegisPluginConfigDefinition,
  register(api) {
    registerClawAegisPlugin(api);
  }
});

export {
  index_default as default,
  registerClawAegisPlugin,
  wrapHookFailOpen
};
