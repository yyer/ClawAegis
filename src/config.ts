import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import type { OpenClawPluginApi, OpenClawPluginConfigSchema } from "../runtime-api.js";

export const CLAW_AEGIS_PLUGIN_ID = "clawaegisex";
export const DEFENSE_MODES = ["off", "observe", "enforce"] as const;

export const TURN_STATE_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_ALLOW_COUNT = 3;

export const STARTUP_SCAN_BUDGET_MS = 200;
export const INLINE_EXEC_TEXT_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_LINES = 200;
export const TOOL_RESULT_CHAR_BUDGET = 64 * 1024;
export const TOOL_RESULT_MAX_DEPTH = 4;
export const TOOL_RESULT_MAX_ARRAY_ITEMS = 200;

export const SKILL_SCAN_QUEUE_MAX = 16;
export const SKILL_SCAN_TIMEOUT_MS = 3000;
export const SKILL_SCAN_COOLDOWN_MS = 5 * 60_000;
export const SKILL_SCAN_FAILURE_WINDOW_MS = 60_000;
export const SKILL_SCAN_FAILURE_THRESHOLD = 3;
export const SKILL_SCAN_FILE_MAX_BYTES = 100 * 1024;
export const SKILL_SCAN_TARGET_FILENAME = "SKILL.md";

export const TRUSTED_SKILLS_FILENAME = "trusted-skills.json";
export const SELF_INTEGRITY_FILENAME = "self-integrity.json";
export const DEFENSE_EVENTS_FILENAME = "defense-events.jsonl";
export const SKILL_SCAN_EVENTS_FILENAME = "skill-scan-events.jsonl";

export const BLOCK_REASON_PROTECTED_PATH =
  "安全限制：禁止访问、查询、修改、删除、关闭或绕过受保护的敏感路径、配置、重要 skill 或 clawaegisex 插件目录。";
export const BLOCK_REASON_WORKSPACE_DELETE =
  "安全限制：禁止删除 workspace 之外的路径。";
export const BLOCK_REASON_OPENCLAW_COMMAND =
  "安全限制：禁止执行 openclaw CLI 或控制命令。";
export const BLOCK_REASON_HIGH_RISK_OPERATION = "安全限制：已阻止本次高风险操作请求。";
export const BLOCK_REASON_MEMORY_WRITE = "安全限制：已拒绝本次高风险记忆写入。";
export const BLOCK_REASON_LOOP = "安全限制：检测到重复高风险工具调用，已停止本次操作。";
export const BLOCK_REASON_EXFILTRATION_CHAIN =
  "安全限制：检测到疑似 SSRF 或数据外泄工具调用链，已阻止本次出站请求。";
export const BLOCK_REASON_DISPATCH_GUARD =
  "安全限制：检测到针对受保护资源的危险操作请求，已拦截。所有破坏性操作必须通过标准 tool call 执行。";

export const BLOCK_REASON_COLLAB_IDENTITY =
  "安全限制：协同链路身份校验失败，sender_id 与 stream key 中的 member 不匹配。";
export const BLOCK_REASON_COLLAB_SCHEMA =
  "安全限制：协同消息缺少必需字段（from/to/ts/type）。";
export const BLOCK_REASON_COLLAB_QUOTA =
  "安全限制：协同链路 XADD 速率超过配额阈值，已限流。";
export const BLOCK_REASON_COLLAB_APPROVAL =
  "安全限制：高风险协同操作（广播/跨成员转派）需要审批，已拦截。";

export type DefenseMode = (typeof DEFENSE_MODES)[number];

// OutboundTrustedEndpoint — 单条出站白名单条目。fingerprint 为空 = 仅域名白名单。
// backend secplane_outbound_trusted 表的 domain_pattern / fingerprint_sha256 /
// label 三字段经 compile.go → user_config.outboundTrustedEndpoints[] 灌入。
export type OutboundTrustedEndpoint = {
  domain: string;
  fingerprint?: string;
  label?: string;
};

export type ClawAegisPluginConfig = {
  allDefensesEnabled: boolean;
  defaultBlockingMode: DefenseMode;
  selfProtectionEnabled: boolean;
  selfProtectionMode: DefenseMode;
  commandBlockEnabled: boolean;
  commandBlockMode: DefenseMode;
  encodingGuardEnabled: boolean;
  encodingGuardMode: DefenseMode;
  scriptProvenanceGuardEnabled: boolean;
  scriptProvenanceGuardMode: DefenseMode;
  memoryGuardEnabled: boolean;
  memoryGuardMode: DefenseMode;
  userRiskScanEnabled: boolean;
  skillScanEnabled: boolean;
  toolResultScanEnabled: boolean;
  outputRedactionEnabled: boolean;
  promptGuardEnabled: boolean;
  loopGuardEnabled: boolean;
  loopGuardMode: DefenseMode;
  exfiltrationGuardEnabled: boolean;
  exfiltrationGuardMode: DefenseMode;
  toolCallEnforcementEnabled: boolean;
  dispatchGuardEnabled: boolean;
  dispatchGuardMode: DefenseMode;
  // requireHttps: block http:// ws:// ftp:// URLs in tool params. Default
  // enabled+enforce via allDefensesEnabled. Driven by secplane rule
  // defense.requireHttps.
  requireHttpsEnabled: boolean;
  requireHttpsMode: DefenseMode;
  // outboundTrust: domain allowlist for https/wss URLs in tool params. Empty
  // list = no enforcement (only logs). Driven by secplane rule
  // defense.outboundTrust + secplane_outbound_trusted table injected at
  // dispatch time. fingerprint pin (Phase 2) not yet implemented.
  outboundTrustEnabled: boolean;
  outboundTrustMode: DefenseMode;
  outboundTrustedEndpoints: OutboundTrustedEndpoint[];
  // killSwitch: emergency breaker. When enabled, before_tool_call blocks
  // every tool call immediately. Driven by secplane rule defense.killSwitch.
  killSwitchEnabled: boolean;
  killSwitchReason: string;
  protectedPaths: string[];
  protectedSkills: string[];
  protectedPlugins: string[];
  skillRoots: string[];
  extraProtectedRoots: string[];
  startupSkillScan: boolean;
  // Names of built-in user_risk_scan flags that ClawAegis should suppress.
  // Driven from secplane policy via the per-rule on/off toggles, so each
  // ClawManager rule switch maps to a concrete pod-side behavior change.
  disabledUserRiskFlags: string[];
  // Names of built-in user_risk_scan flags that ClawAegis should record
  // ("observe") but NOT actually enforce. When a flag is in this list, the
  // matched user input still produces a defense event (action=observed)
  // but state.noteUserRisk() is skipped, so the dynamic userRisk prompt
  // guard reminder does NOT get injected and downstream LLM behavior is
  // unchanged. Driven by secplane rule mode=observe.
  observeOnlyUserRiskFlags: string[];
  // Same semantics as disabledUserRiskFlags but for TOOL_RESULT_RISK_RULES
  // flags surfaced by scanToolResultText. Flags listed here are filtered
  // out of `outcome.riskFlags` (both base flags and their encoded-* twin).
  disabledToolResultFlags: string[];
  // Same as observeOnlyUserRiskFlags but for tool_result flags: matching
  // is still recorded but `state.noteRuntimeRisk` is suppressed for the
  // encoded-* derivatives, so the dynamic runtime-risk prompt guard does
  // not nudge the LLM. Driven by secplane rule mode=observe.
  observeOnlyToolResultFlags: string[];
  // Collaboration governance (collab_guard). Master switch + 4 sub-modes.
  // Master CollabGuardMode gates the whole defense; sub-modes control each
  // rule (identity / schema / quota / approval) independently. Driven by
  // the KindCollabPolicy rule dispatched from secplane.
  collabGuardEnabled: boolean;
  collabGuardMode: DefenseMode;
  collabTeamId: string;
  collabIdentityMode: DefenseMode;
  collabSchemaMode: DefenseMode;
  collabQuotaMode: DefenseMode;
  collabApprovalMode: DefenseMode;
  collabXaddRps: number;
  collabStreamMaxLen: number;
  collabMuteOnAnomaly: boolean;
  collabAuditReplay: boolean;
  collabApprovalThreshold: number;
  collabRedisAclPreview: string;
};

const defaultEnabledBooleanSchema = {
  type: "boolean",
  default: true,
} as const;

const defaultDefenseModeSchema = {
  type: "string",
  enum: [...DEFENSE_MODES],
  default: "enforce",
} as const;

export const clawAegisPluginConfigSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    allDefensesEnabled: defaultEnabledBooleanSchema,
    defaultBlockingMode: defaultDefenseModeSchema,
    selfProtectionEnabled: defaultEnabledBooleanSchema,
    selfProtectionMode: defaultDefenseModeSchema,
    commandBlockEnabled: defaultEnabledBooleanSchema,
    commandBlockMode: defaultDefenseModeSchema,
    encodingGuardEnabled: defaultEnabledBooleanSchema,
    encodingGuardMode: defaultDefenseModeSchema,
    scriptProvenanceGuardEnabled: defaultEnabledBooleanSchema,
    scriptProvenanceGuardMode: defaultDefenseModeSchema,
    memoryGuardEnabled: defaultEnabledBooleanSchema,
    memoryGuardMode: defaultDefenseModeSchema,
    userRiskScanEnabled: defaultEnabledBooleanSchema,
    skillScanEnabled: defaultEnabledBooleanSchema,
    toolResultScanEnabled: defaultEnabledBooleanSchema,
    outputRedactionEnabled: defaultEnabledBooleanSchema,
    promptGuardEnabled: defaultEnabledBooleanSchema,
    loopGuardEnabled: defaultEnabledBooleanSchema,
    loopGuardMode: defaultDefenseModeSchema,
    exfiltrationGuardEnabled: defaultEnabledBooleanSchema,
    exfiltrationGuardMode: defaultDefenseModeSchema,
    toolCallEnforcementEnabled: defaultEnabledBooleanSchema,
    dispatchGuardEnabled: defaultEnabledBooleanSchema,
    dispatchGuardMode: defaultDefenseModeSchema,
    requireHttpsEnabled: defaultEnabledBooleanSchema,
    requireHttpsMode: defaultDefenseModeSchema,
    outboundTrustEnabled: defaultEnabledBooleanSchema,
    outboundTrustMode: defaultDefenseModeSchema,
    killSwitchEnabled: { type: "boolean", default: false },
    killSwitchReason: { type: "string", default: "" },
    outboundTrustedEndpoints: {
      type: "array",
      items: {
        type: "object",
        properties: {
          domain: { type: "string" },
          fingerprint: { type: "string" },
          label: { type: "string" },
        },
      },
    },
    protectedPaths: {
      type: "array",
      items: { type: "string" },
    },
    protectedSkills: {
      type: "array",
      items: { type: "string" },
    },
    protectedPlugins: {
      type: "array",
      items: { type: "string" },
    },
    skillRoots: {
      type: "array",
      items: { type: "string" },
    },
    extraProtectedRoots: {
      type: "array",
      items: { type: "string" },
    },
    startupSkillScan: {
      type: "boolean",
      default: true,
    },
    disabledUserRiskFlags: {
      type: "array",
      items: { type: "string" },
    },
    observeOnlyUserRiskFlags: {
      type: "array",
      items: { type: "string" },
    },
    disabledToolResultFlags: {
      type: "array",
      items: { type: "string" },
    },
    observeOnlyToolResultFlags: {
      type: "array",
      items: { type: "string" },
    },
    collabGuardEnabled: defaultEnabledBooleanSchema,
    collabGuardMode: defaultDefenseModeSchema,
    collabTeamId: { type: "string" },
    collabIdentityMode: defaultDefenseModeSchema,
    collabSchemaMode: defaultDefenseModeSchema,
    collabQuotaMode: defaultDefenseModeSchema,
    collabApprovalMode: defaultDefenseModeSchema,
    collabXaddRps: { type: "number", default: 5 },
    collabStreamMaxLen: { type: "number", default: 1000 },
    collabMuteOnAnomaly: { type: "boolean", default: true },
    collabAuditReplay: { type: "boolean", default: true },
    collabApprovalThreshold: { type: "number", default: 85 },
    collabRedisAclPreview: { type: "string" },
  },
} satisfies OpenClawPluginConfigSchema["jsonSchema"];

export const clawAegisPluginUiHints = {
  allDefensesEnabled: {
    label: "Enable All Defenses",
    help: "Master switch for every clawaegisex defense below.",
  },
  defaultBlockingMode: {
    label: "Default Blocking Mode",
    help: 'Default mode for blocking defenses. "enforce" blocks, "observe" only logs, and "off" disables the guard.',
  },
  selfProtectionEnabled: {
    label: "Protect Sensitive Paths",
    help: "Block reads, writes, deletes, and searches that target protected paths, important skills, or try to delete files outside the current workspace.",
  },
  selfProtectionMode: {
    label: "Sensitive Path Mode",
    help: 'Detailed mode for protected-path defenses. "observe" records violations without blocking.',
  },
  commandBlockEnabled: {
    label: "Block High-Risk Commands",
    help: "Block clear high-risk shell patterns such as rm -rf / and curl | sh.",
  },
  commandBlockMode: {
    label: "Command Block Mode",
    help: 'Detailed mode for high-risk command blocking. "observe" only reports detections.',
  },
  encodingGuardEnabled: {
    label: "Guard Encoded Payloads",
    help: "Detect bounded base64/base32/hex/url-encoded payloads that hide risky commands or exfiltration logic.",
  },
  encodingGuardMode: {
    label: "Encoding Guard Mode",
    help: 'Detailed mode for encoded/obfuscated command guards. "observe" keeps the call allowed.',
  },
  scriptProvenanceGuardEnabled: {
    label: "Track Script Provenance",
    help: "Track newly written scripts in the current run and block later execution when they carry risky command or exfiltration signals.",
  },
  scriptProvenanceGuardMode: {
    label: "Script Provenance Mode",
    help: 'Detailed mode for risky script provenance enforcement. "observe" logs the execution attempt only.',
  },
  memoryGuardEnabled: {
    label: "Guard Memory Writes",
    help: "Reject suspicious or oversized writes to memory_store, MEMORY.md, SOUL.md, and memory/.",
  },
  memoryGuardMode: {
    label: "Memory Guard Mode",
    help: 'Detailed mode for risky memory writes. "observe" will keep the write allowed.',
  },
  userRiskScanEnabled: {
    label: "Scan User Intent",
    help: "Detect jailbreak, secret-exfiltration, and plugin-tampering requests in message_received.",
  },
  skillScanEnabled: {
    label: "Scan Skills",
    help: "Enable the lightweight local skill scanner for ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
  },
  toolResultScanEnabled: {
    label: "Scan Tool Results",
    help: "Scan toolResult content for prompt-injection, secret-request, and exfiltration patterns.",
  },
  outputRedactionEnabled: {
    label: "Redact Sensitive Output",
    help: "Mask API keys, tokens, and similar sensitive values before assistant output is sent or persisted.",
  },
  promptGuardEnabled: {
    label: "Inject Prompt Guards",
    help: "Inject static and one-shot safety reminders during before_prompt_build.",
  },
  loopGuardEnabled: {
    label: "Enable Loop Guard",
    help: "Stop repeated mutating tool calls after the allowed retry budget per run.",
  },
  loopGuardMode: {
    label: "Loop Guard Mode",
    help: 'Detailed mode for repeated mutating calls. "observe" warns instead of stopping the run.',
  },
  exfiltrationGuardEnabled: {
    label: "Guard Exfiltration Chains",
    help: "Track prior tool calls per run and block suspicious outbound chains that resemble SSRF or secret exfiltration.",
  },
  exfiltrationGuardMode: {
    label: "Exfiltration Guard Mode",
    help: 'Detailed mode for outbound chain detection. "observe" records the chain without blocking.',
  },
  toolCallEnforcementEnabled: {
    label: "Enforce Tool Call Only",
    help: "Inject prompt rules requiring all destructive operations (file ops, CLI commands, network, process spawning) to go through standard tool calls only.",
  },
  dispatchGuardEnabled: {
    label: "Guard Message Dispatch",
    help: "Intercept user messages and LLM replies before agent processing to block dangerous operations targeting protected resources.",
  },
  dispatchGuardMode: {
    label: "Dispatch Guard Mode",
    help: 'Detailed mode for dispatch guard. "enforce" blocks dangerous messages, "observe" only logs.',
  },
  protectedPaths: {
    label: "Protected Paths",
    help: "Additional absolute or resolved paths that should be treated as protected targets.",
    advanced: true,
    placeholder: "/path/to/protected",
  },
  protectedSkills: {
    label: "Protected Skills",
    help: "Additional skill IDs to protect under ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
    placeholder: "release-guard",
  },
  protectedPlugins: {
    label: "Protected Plugins",
    help: "Additional plugin IDs to protect under extensions/, plugins/ state, and openclaw.json plugin entries.",
    advanced: true,
    placeholder: "audit-guard",
  },
  startupSkillScan: {
    label: "Scan Skills at Startup",
    help: "Run a bounded startup scan for ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
  },
  skillRoots: {
    label: "Additional Skill Roots (Ignored)",
    help: "Deprecated. clawaegisex v1 now scans only ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
    placeholder: "/path/to/skills",
  },
  extraProtectedRoots: {
    label: "Additional Protected Roots",
    help: "Legacy compatibility alias of protectedPaths. Extra directories that clawaegisex should treat as protected paths.",
    advanced: true,
    placeholder: "/path/to/protected",
  },
} satisfies NonNullable<OpenClawPluginConfigSchema["uiHints"]>;

export const clawAegisPluginConfigDefinition = {
  jsonSchema: clawAegisPluginConfigSchema,
  uiHints: clawAegisPluginUiHints,
} satisfies OpenClawPluginConfigSchema;

function normalizeStringList(value: unknown, resolvePath: (input: string) => string): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }
    const resolved = path.resolve(resolvePath(trimmed));
    if (seen.has(resolved)) {
      continue;
    }
    seen.add(resolved);
    results.push(resolved);
  }
  return results;
}

// openclaw 2026.5.4 wraps the plugin api in a guarded proxy
// (createGuardedPluginRegistrationApi) that closes after register() returns.
// Post-register, any function on `api` — including `api.resolvePath` — returns
// undefined. ClawAegis calls resolveClawAegisPluginConfig both during register
// (api.resolvePath works) and from gateway_start/hot-reload (api.resolvePath
// returns undefined). makeResolvePath falls back to a local resolver that
// mirrors resolvePluginPath semantics (absolute/~ stays as-is, relative
// resolves against api.rootDir) so config parsing works in both phases.
function makeResolvePath(api: OpenClawPluginApi): (input: string) => string {
  const rootDir = api.rootDir;
  return (input: string): string => {
    const apiResolve = api.resolvePath;
    if (typeof apiResolve === "function") {
      try {
        const result = apiResolve(input);
        if (typeof result === "string" && result.length > 0) {
          return result;
        }
      } catch {
        // fall through to local resolver
      }
    }
    const trimmed = input.trim();
    if (!trimmed) {
      return path.resolve(input);
    }
    if (path.isAbsolute(trimmed) || trimmed.startsWith("~")) {
      return path.resolve(input);
    }
    return rootDir ? path.resolve(rootDir, trimmed) : path.resolve(input);
  };
}

function normalizeIdentifierList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      continue;
    }
    const normalized = entry.trim().normalize("NFKC").toLowerCase();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    results.push(normalized);
  }
  return results;
}

function readEnabledFlag(
  raw: Record<string, unknown>,
  key: keyof Pick<
    ClawAegisPluginConfig,
    | "selfProtectionEnabled"
    | "commandBlockEnabled"
    | "encodingGuardEnabled"
    | "scriptProvenanceGuardEnabled"
    | "memoryGuardEnabled"
    | "userRiskScanEnabled"
    | "skillScanEnabled"
    | "toolResultScanEnabled"
    | "outputRedactionEnabled"
    | "promptGuardEnabled"
    | "loopGuardEnabled"
    | "exfiltrationGuardEnabled"
    | "toolCallEnforcementEnabled"
    | "dispatchGuardEnabled"
  >,
  allDefensesEnabled: boolean,
): boolean {
  return allDefensesEnabled && raw[key] !== false;
}

function isDefenseMode(value: unknown): value is DefenseMode {
  return typeof value === "string" && (DEFENSE_MODES as readonly string[]).includes(value);
}

// readCollabSubMode reads a standalone DefenseMode field (no paired enabled
// boolean) for the 4 collab sub-rules. Empty/invalid falls back to the
// provided default (typically "observe" for safe rollout).
function readCollabSubMode(
  raw: Record<string, unknown>,
  key: keyof Pick<
    ClawAegisPluginConfig,
    | "collabIdentityMode"
    | "collabSchemaMode"
    | "collabQuotaMode"
    | "collabApprovalMode"
  >,
  fallback: DefenseMode,
): DefenseMode {
  const v = raw[key];
  return isDefenseMode(v) ? v : fallback;
}

function readDefenseMode(
  raw: Record<string, unknown>,
  params: {
    enabledKey: keyof Pick<
      ClawAegisPluginConfig,
      | "selfProtectionEnabled"
      | "commandBlockEnabled"
      | "encodingGuardEnabled"
      | "scriptProvenanceGuardEnabled"
      | "memoryGuardEnabled"
      | "loopGuardEnabled"
      | "exfiltrationGuardEnabled"
      | "dispatchGuardEnabled"
      | "collabGuardEnabled"
      | "requireHttpsEnabled"
      | "outboundTrustEnabled"
    >;
    modeKey: keyof Pick<
      ClawAegisPluginConfig,
      | "selfProtectionMode"
      | "commandBlockMode"
      | "encodingGuardMode"
      | "scriptProvenanceGuardMode"
      | "memoryGuardMode"
      | "loopGuardMode"
      | "exfiltrationGuardMode"
      | "dispatchGuardMode"
      | "collabGuardMode"
      | "requireHttpsMode"
      | "outboundTrustMode"
    >;
    defaultMode: DefenseMode;
    allDefensesEnabled: boolean;
  },
): DefenseMode {
  if (!params.allDefensesEnabled || raw[params.enabledKey] === false) {
    return "off";
  }
  const explicitMode = raw[params.modeKey];
  return isDefenseMode(explicitMode) ? explicitMode : params.defaultMode;
}

// Path 1: read pluginConfig as injected by the OpenClaw host. Path 2 (added
// for secplane policy push): if a `user_config.json` file is present in one
// of the candidate paths, merge it on top — this lets ClawManager
// re-distribute configuration via the existing skill upload + install_skill
// channel:
//   secplane.compile(rules) -> user_config.json -> rezip -> skills/import
//   -> instances/:id/skills (attach) -> agent installs at workspace/skills/
//   -> ClawAegis reads it on the next hook event (mtime-watched reload).
//
// Priority order (first existing wins):
//   1. ~/.openclaw/workspace/skills/clawaegisex/user_config.json
//        — this is where `install_skill` extracts the dispatched bundle.
//          Putting it first means ClawManager dispatches are authoritative.
//   2. <rootDir>/user_config.json
//        — developer-local override next to the loaded plugin source.
//          Useful for poking at config during local development without
//          touching the secplane pipeline.
//   3. ~/.openclaw/skills/clawaegisex/user_config.json
//        — legacy install location, kept for compatibility.
export function userConfigCandidatePaths(rootDir: string | undefined): string[] {
  const out: string[] = [];
  const home = os.homedir();
  if (home) {
    out.push(path.join(home, ".openclaw", "workspace", "skills", "clawaegisex", "user_config.json"));
  }
  if (rootDir) out.push(path.join(rootDir, "user_config.json"));
  if (home) {
    out.push(path.join(home, ".openclaw", "skills", "clawaegisex", "user_config.json"));
  }
  return out;
}

// getUserConfigMtimeMs returns the mtime in ms of the *currently winning*
// user_config.json among the candidate paths, or 0 if none exists.
// Used by callers that want to cheaply detect "dispatch happened, my
// in-memory config is stale" without re-parsing JSON on every event.
export function getUserConfigMtimeMs(rootDir: string | undefined): number {
  const target = findUserConfigPath(rootDir);
  if (!target) return 0;
  try {
    return fs.statSync(target).mtimeMs;
  } catch {
    return 0;
  }
}

export function findUserConfigPath(rootDir: string | undefined): string | undefined {
  for (const candidate of userConfigCandidatePaths(rootDir)) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // ignore and keep searching
    }
  }
  return undefined;
}

function readUserConfigOverride(rootDir: string | undefined): Record<string, unknown> {
  const target = findUserConfigPath(rootDir);
  if (!target) return {};
  try {
    const text = fs.readFileSync(target, "utf8");
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // best-effort: a malformed override should not break the plugin
  }
  return {};
}

export function resolveClawAegisPluginConfig(api: OpenClawPluginApi): ClawAegisPluginConfig {
  const baseConfig = (api.pluginConfig ?? {}) as Record<string, unknown>;
  const override = readUserConfigOverride(api.rootDir);
  const raw: Record<string, unknown> = { ...baseConfig, ...override };
  const resolvePath = makeResolvePath(api);
  const allDefensesEnabled = raw.allDefensesEnabled !== false;
  const defaultBlockingMode = isDefenseMode(raw.defaultBlockingMode)
    ? raw.defaultBlockingMode
    : "enforce";
  const selfProtectionMode = readDefenseMode(raw, {
    enabledKey: "selfProtectionEnabled",
    modeKey: "selfProtectionMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const commandBlockMode = readDefenseMode(raw, {
    enabledKey: "commandBlockEnabled",
    modeKey: "commandBlockMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const encodingGuardMode = readDefenseMode(raw, {
    enabledKey: "encodingGuardEnabled",
    modeKey: "encodingGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const scriptProvenanceGuardMode = readDefenseMode(raw, {
    enabledKey: "scriptProvenanceGuardEnabled",
    modeKey: "scriptProvenanceGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const memoryGuardMode = readDefenseMode(raw, {
    enabledKey: "memoryGuardEnabled",
    modeKey: "memoryGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const loopGuardMode = readDefenseMode(raw, {
    enabledKey: "loopGuardEnabled",
    modeKey: "loopGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const exfiltrationGuardMode = readDefenseMode(raw, {
    enabledKey: "exfiltrationGuardEnabled",
    modeKey: "exfiltrationGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const dispatchGuardMode = readDefenseMode(raw, {
    enabledKey: "dispatchGuardEnabled",
    modeKey: "dispatchGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const requireHttpsMode = readDefenseMode(raw, {
    enabledKey: "requireHttpsEnabled",
    modeKey: "requireHttpsMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const outboundTrustMode = readDefenseMode(raw, {
    enabledKey: "outboundTrustEnabled",
    modeKey: "outboundTrustMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const outboundTrustedEndpoints: OutboundTrustedEndpoint[] = Array.isArray(
    raw.outboundTrustedEndpoints,
  )
    ? raw.outboundTrustedEndpoints
        .filter(
          (e): e is Record<string, unknown> =>
            !!e && typeof e === "object" && typeof (e as Record<string, unknown>).domain === "string" && !!(e as Record<string, unknown>).domain,
        )
        .map((e) => ({
          domain: String((e as Record<string, unknown>).domain).toLowerCase(),
          fingerprint:
            typeof (e as Record<string, unknown>).fingerprint === "string"
              ? ((e as Record<string, unknown>).fingerprint as string).toLowerCase()
              : "",
          label:
            typeof (e as Record<string, unknown>).label === "string"
              ? ((e as Record<string, unknown>).label as string)
              : "",
        }))
    : [];
  const collabGuardMode = readDefenseMode(raw, {
    enabledKey: "collabGuardEnabled",
    modeKey: "collabGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  return {
    allDefensesEnabled,
    defaultBlockingMode,
    selfProtectionEnabled: selfProtectionMode !== "off",
    selfProtectionMode,
    commandBlockEnabled: commandBlockMode !== "off",
    commandBlockMode,
    encodingGuardEnabled: encodingGuardMode !== "off",
    encodingGuardMode,
    scriptProvenanceGuardEnabled: scriptProvenanceGuardMode !== "off",
    scriptProvenanceGuardMode,
    memoryGuardEnabled: memoryGuardMode !== "off",
    memoryGuardMode,
    userRiskScanEnabled: readEnabledFlag(raw, "userRiskScanEnabled", allDefensesEnabled),
    skillScanEnabled: readEnabledFlag(raw, "skillScanEnabled", allDefensesEnabled),
    toolResultScanEnabled: readEnabledFlag(raw, "toolResultScanEnabled", allDefensesEnabled),
    outputRedactionEnabled: readEnabledFlag(raw, "outputRedactionEnabled", allDefensesEnabled),
    promptGuardEnabled: readEnabledFlag(raw, "promptGuardEnabled", allDefensesEnabled),
    loopGuardEnabled: loopGuardMode !== "off",
    loopGuardMode,
    exfiltrationGuardEnabled: exfiltrationGuardMode !== "off",
    exfiltrationGuardMode,
    toolCallEnforcementEnabled: readEnabledFlag(raw, "toolCallEnforcementEnabled", allDefensesEnabled),
    dispatchGuardEnabled: dispatchGuardMode !== "off",
    dispatchGuardMode,
    requireHttpsEnabled: requireHttpsMode !== "off",
    requireHttpsMode,
    outboundTrustEnabled: outboundTrustMode !== "off",
    outboundTrustMode,
    outboundTrustedEndpoints,
    killSwitchEnabled: raw.killSwitchEnabled === true,
    killSwitchReason: typeof raw.killSwitchReason === "string" ? raw.killSwitchReason : "",
    protectedPaths: normalizeStringList(raw.protectedPaths, resolvePath),
    protectedSkills: normalizeIdentifierList(raw.protectedSkills),
    protectedPlugins: normalizeIdentifierList(raw.protectedPlugins),
    skillRoots: normalizeStringList(raw.skillRoots, resolvePath),
    extraProtectedRoots: normalizeStringList(raw.extraProtectedRoots, resolvePath),
    startupSkillScan: raw.startupSkillScan !== false,
    disabledUserRiskFlags: normalizeIdentifierList(raw.disabledUserRiskFlags),
    observeOnlyUserRiskFlags: normalizeIdentifierList(raw.observeOnlyUserRiskFlags),
    disabledToolResultFlags: normalizeIdentifierList(raw.disabledToolResultFlags),
    observeOnlyToolResultFlags: normalizeIdentifierList(raw.observeOnlyToolResultFlags),
    collabGuardEnabled: collabGuardMode !== "off",
    collabGuardMode,
    collabTeamId: typeof raw.collabTeamId === "string" ? raw.collabTeamId : "",
    collabIdentityMode: readCollabSubMode(raw, "collabIdentityMode", "observe"),
    collabSchemaMode: readCollabSubMode(raw, "collabSchemaMode", "observe"),
    collabQuotaMode: readCollabSubMode(raw, "collabQuotaMode", "observe"),
    collabApprovalMode: readCollabSubMode(raw, "collabApprovalMode", "observe"),
    collabXaddRps: typeof raw.collabXaddRps === "number" && raw.collabXaddRps > 0 ? raw.collabXaddRps : 5,
    collabStreamMaxLen:
      typeof raw.collabStreamMaxLen === "number" && raw.collabStreamMaxLen > 0 ? raw.collabStreamMaxLen : 1000,
    collabMuteOnAnomaly: raw.collabMuteOnAnomaly !== false,
    collabAuditReplay: raw.collabAuditReplay !== false,
    collabApprovalThreshold:
      typeof raw.collabApprovalThreshold === "number" && raw.collabApprovalThreshold > 0
        ? raw.collabApprovalThreshold
        : 85,
    collabRedisAclPreview: typeof raw.collabRedisAclPreview === "string" ? raw.collabRedisAclPreview : "",
  };
}

export function resolveClawAegisStateDir(api: OpenClawPluginApi): string {
  return path.join(api.runtime.state.resolveStateDir(), "plugins", CLAW_AEGIS_PLUGIN_ID);
}

export function resolveSkillScanRoots(api: OpenClawPluginApi): string[] {
  const stateRoot = path.resolve(api.runtime.state.resolveStateDir());
  return [path.join(stateRoot, "skills"), path.join(stateRoot, "workspace", "skills")];
}
