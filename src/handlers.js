import { createHash } from "node:crypto";
import { promises as fs, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BLOCK_REASON_DISPATCH_GUARD, CLAW_AEGIS_PLUGIN_ID, DEFENSE_EVENTS_FILENAME, SKILL_SCAN_EVENTS_FILENAME, STARTUP_SCAN_BUDGET_MS, } from "./config.js";
import { getUserConfigMtimeMs, resolveClawAegisPluginConfig, resolveClawAegisStateDir, resolveSkillScanRoots, } from "./config.js";
import { buildDynamicPromptContext, buildLoopGuardStableArgsKey, buildStaticSystemContext, collectScriptArtifactRecords, collectSensitiveOutputValues, collectToolResultScanText, detectCommandObfuscationViolation, AEGIS_REFUSAL_PREFIX, detectDispatchGuardViolation, detectHighRiskCommand, detectUserRiskFlags, isOutboundToolCall, isThirdPartyWebToolResultMessage, normalizeToolName, normalizeToolParamsForGuard, reviewSuspiciousOutboundChain, resolveInlineExecutionViolation, resolveMemoryGuardViolation, resolveOutsideWorkspaceDeletionViolation, resolveProtectedPathCandidates, resolveProtectedPathViolation, resolveScriptProvenanceViolation, resolveSelfProtectionTextViolation, sanitizeAssistantMessage, sanitizeSensitiveOutputText, sanitizeToolResultMessage, scanToolResultText, } from "./rules.js";
import { TOOL_CALL_DEFENSE_STRATEGIES, } from "./security-strategies.js";
import { SkillScanService } from "./scan-service.js";
import { ClawAegisState } from "./state.js";
const SELF_INTEGRITY_FILES = [
    "index.ts",
    "runtime-api.ts",
    "openclaw.plugin.json",
    "package.json",
    "src/config.ts",
    "src/types.ts",
    "src/state.ts",
    "src/rules.ts",
    "src/scan-service.ts",
    "src/scan-worker.ts",
    "src/scan-worker.js",
    "src/handlers.ts",
];
function joinPresentTextSegments(segments) {
    const values = segments.map((segment) => segment?.trim()).filter(Boolean);
    return values.length > 0 ? values.join("\n\n") : undefined;
}
function readCommandText(params) {
    for (const key of ["command", "cmd"]) {
        const value = params[key];
        if (typeof value === "string" && value.trim()) {
            return value.trim();
        }
    }
    return undefined;
}
function buildSecretFingerprints(values, source, timestamp) {
    return [...new Set(values.map((value) => value.trim()).filter(Boolean))]
        .filter((value) => value.length >= 8)
        .map((value) => ({
        hash: createHash("sha256").update(value).digest("hex"),
        length: value.length,
        source,
        updatedAt: timestamp,
    }));
}
function deriveScriptArtifactSignals(artifacts) {
    const sourceSignals = new Set();
    const transformSignals = new Set();
    const sinkSignals = new Set();
    const runtimeRiskFlags = new Set();
    for (const artifact of artifacts) {
        if (artifact.riskFlags.some((flag) => flag.includes("secret") || flag.includes("sensitive"))) {
            sourceSignals.add("script-artifact");
        }
        if (artifact.riskFlags.some((flag) => flag.includes("encoded") || flag.includes("high-risk-command"))) {
            transformSignals.add("script-artifact");
        }
        if (artifact.riskFlags.some((flag) => flag.includes("outbound-sink") || flag.includes("exfiltration"))) {
            sinkSignals.add("script-artifact");
        }
        for (const flag of artifact.riskFlags) {
            runtimeRiskFlags.add(flag);
        }
    }
    return {
        sourceSignals: [...sourceSignals],
        transformSignals: [...transformSignals],
        sinkSignals: [...sinkSignals],
        runtimeRiskFlags: [...runtimeRiskFlags],
    };
}
async function resolveRealPath(input) {
    if (!input?.trim()) {
        return undefined;
    }
    try {
        return await fs.realpath(input);
    }
    catch {
        return path.resolve(input);
    }
}
async function resolveProtectedRoots(api, stateDir, config) {
    const stateRoot = path.resolve(api.runtime.state.resolveStateDir());
    const candidates = new Set();
    const append = async (entry) => {
        if (!entry?.trim()) {
            return;
        }
        const resolved = path.resolve(entry);
        candidates.add(resolved);
        const real = await resolveRealPath(resolved);
        if (real) {
            candidates.add(real);
        }
    };
    await append(api.rootDir);
    await append(stateDir);
    for (const protectedPath of config.protectedPaths) {
        await append(protectedPath);
    }
    for (const extra of config.extraProtectedRoots) {
        await append(extra);
    }
    for (const protectedSkillId of config.protectedSkills) {
        await append(path.join(stateRoot, "skills", protectedSkillId));
        await append(path.join(stateRoot, "workspace", "skills", protectedSkillId));
    }
    for (const protectedPluginId of config.protectedPlugins) {
        await append(path.join(stateRoot, "extensions", protectedPluginId));
        await append(path.join(stateRoot, "plugins", protectedPluginId));
    }
    return [...candidates].sort((left, right) => left.localeCompare(right));
}
async function buildSelfIntegrityRecord(params) {
    const rootDir = params.api.rootDir ? path.resolve(params.api.rootDir) : undefined;
    const rootRealPath = await resolveRealPath(rootDir);
    const fingerprints = {};
    if (rootDir) {
        for (const relativePath of SELF_INTEGRITY_FILES) {
            const absolutePath = path.join(rootDir, relativePath);
            try {
                const content = await fs.readFile(absolutePath);
                fingerprints[relativePath] = createHash("sha256")
                    .update(content)
                    .digest("hex")
                    .slice(0, 16);
            }
            catch {
                continue;
            }
        }
    }
    return {
        pluginId: CLAW_AEGIS_PLUGIN_ID,
        stateDir: params.stateDir,
        rootDir,
        rootRealPath,
        protectedRoots: params.protectedRoots,
        fingerprints,
        updatedAt: Date.now(),
    };
}
function createSyntheticSkillRiskState(params) {
    return {
        userRiskFlags: [],
        hasToolResult: false,
        toolResultRiskFlags: [],
        toolResultSuspicious: false,
        toolResultOversize: false,
        skillRiskFlags: [...params.skillRiskFlags],
        riskySkills: [...params.riskySkills],
        runtimeRiskFlags: [],
        prependNeeded: params.riskySkills.length > 0,
        updatedAt: params.now,
    };
}
function serializeLogMeta(meta) {
    if (!meta || Object.keys(meta).length === 0) {
        return "";
    }
    try {
        return ` ${JSON.stringify(meta)}`;
    }
    catch {
        return ' {"meta":"[unserializable]"}';
    }
}
function createAegisLogger(api) {
    return {
        debug: api.logger.debug
            ? (message, meta) => {
                api.logger.debug?.(`${message}${serializeLogMeta(meta)}`);
            }
            : undefined,
        info: (message, meta) => {
            api.logger.info(`${message}${serializeLogMeta(meta)}`);
        },
        warn: (message, meta) => {
            api.logger.warn(`${message}${serializeLogMeta(meta)}`);
        },
        error: (message, meta) => {
            api.logger.error(`${message}${serializeLogMeta(meta)}`);
        },
    };
}
function warnIfPromptHooksDisabled(api) {
    const pluginEntry = (api.config.plugins?.entries ?? {})[CLAW_AEGIS_PLUGIN_ID];
    if (pluginEntry?.hooks?.allowPromptInjection === false) {
        api.logger.warn('安全插件配置中已关闭提示词注入 hook，提示防护将不会运行');
    }
}
function arePromptHooksEnabled(api) {
    const pluginEntry = (api.config.plugins?.entries ?? {})[CLAW_AEGIS_PLUGIN_ID];
    return pluginEntry?.hooks?.allowPromptInjection !== false;
}
// openclaw 2026.5.4 引入 conversation hook gate: non-bundled plugin 注册
// llm_output / agent_end / llm_input / before_agent_finalize 时,必须显式
// plugins.entries.<id>.hooks.allowConversationAccess=true,否则 hook 注册被
// 静默 block (只 push warn diagnostic)。ClawAegis 用 llm_output (prompt_self_block)
// 和 agent_end (run state cleanup),所以必须确保这个 flag 为 true。
// areConversationHooksEnabled 给 handler 做 defensive guard;真正的修复在
// ensureConversationAccessEnabled (gateway_start 时 patch openclaw.json)。
function areConversationHooksEnabled(api) {
    const pluginEntry = (api.config.plugins?.entries ?? {})[CLAW_AEGIS_PLUGIN_ID];
    return pluginEntry?.hooks?.allowConversationAccess === true;
}
function warnIfConversationAccessDisabled(api) {
    if (areConversationHooksEnabled(api))
        return;
    api.logger.warn('安全插件未启用 allowConversationAccess，llm_output / agent_end hook 将被 openclaw 静默 block；正在尝试自动修复 openclaw.json');
}
// resolveOpenClawConfigPath 推断 openclaw.json 的路径。
// 优先级: OPENCLAW_CONFIG_PATH env > <stateDir>/openclaw.json > ~/.openclaw/openclaw.json。
// 5.4 的 resolveConfigPath 逻辑见 dist/paths-C1_Y0cDn.js:133。
function resolveOpenClawConfigPath(api) {
    const envOverride = process.env.OPENCLAW_CONFIG_PATH?.trim();
    if (envOverride)
        return envOverride;
    try {
        const stateDir = api.runtime.state.resolveStateDir();
        if (stateDir) {
            const candidate = path.join(stateDir, "openclaw.json");
            return candidate;
        }
    }
    catch {
        // fallthrough to home dir
    }
    try {
        const home = process.env.HOME || process.env.USERPROFILE || "";
        if (home)
            return path.join(home, ".openclaw", "openclaw.json");
    }
    catch {
        // give up
    }
    return undefined;
}
// ensureConversationAccessEnabled 在 gateway_start 时检查 openclaw.json 的
// plugins.entries.clawaegisex.hooks.allowConversationAccess。如果不是 true,
// 自动 patch openclaw.json 加上这个字段。openclaw 的 config watcher (chokidar)
// 会监听文件变化并自动 reload plugin,重新注册时 allowConversationAccess=true
// 就生效了,llm_output / agent_end 不再被 block。
// 返回 true 表示已 patch (本次启动需等 reload 生效),false 表示无需 patch。
function ensureConversationAccessEnabled(api) {
    if (areConversationHooksEnabled(api))
        return false;
    const configPath = resolveOpenClawConfigPath(api);
    if (!configPath) {
        api.logger.error('clawaegisex: 无法定位 openclaw.json 路径,allowConversationAccess 未自动修复; llm_output / agent_end 将被 block');
        return false;
    }
    try {
        const raw = readFileSync(configPath, "utf8");
        const cfg = JSON.parse(raw);
        const plugins = (cfg.plugins ?? {});
        const entries = (plugins.entries ?? {});
        const entry = (entries[CLAW_AEGIS_PLUGIN_ID] ?? {});
        const hooks = (entry.hooks ?? {});
        if (hooks.allowConversationAccess === true) {
            // config 已正确,但 api.config 还是旧快照 — 可能 reload 还没触发。
            // 不需要写文件。
            return false;
        }
        hooks.allowConversationAccess = true;
        entry.hooks = hooks;
        entries[CLAW_AEGIS_PLUGIN_ID] = entry;
        plugins.entries = entries;
        cfg.plugins = plugins;
        writeFileSync(configPath, JSON.stringify(cfg, null, 2) + "\n", "utf8");
        api.logger.info(`clawaegisex: 已自动设置 plugins.entries.${CLAW_AEGIS_PLUGIN_ID}.hooks.allowConversationAccess=true (${configPath}); openclaw 将自动 reload`);
        return true;
    }
    catch (error) {
        api.logger.error(`clawaegisex: 自动设置 allowConversationAccess 失败 (${configPath}): ${error instanceof Error ? error.message : String(error)}`);
        return false;
    }
}
function logDefenseStart(logger, meta) {
    logger.info("clawaegisex: 开始执行防御检查", {
        event: "defense_check_started",
        ...meta,
    });
}
function logDefenseFinish(logger, meta) {
    logger.info("clawaegisex: 防御检查结束", {
        event: "defense_check_finished",
        ...meta,
    });
}
function logDefenseResult(logger, meta, level = "info") {
    const message = "clawaegisex: 防御检查结果";
    const payload = {
        event: "defense_check_result",
        ...meta,
    };
    if (level === "warn") {
        logger.warn(message, payload);
        return;
    }
    logger.info(message, payload);
}
function mergeDefenseModes(...modes) {
    if (modes.includes("enforce")) {
        return "enforce";
    }
    if (modes.includes("observe")) {
        return "observe";
    }
    return "off";
}
function resolveToolCallDefenseMode(modes, source) {
    const sources = Array.isArray(source) ? source : [source];
    return mergeDefenseModes(...sources.map((entry) => modes[entry]));
}
function isDefenseEnabled(mode) {
    return mode !== "off";
}
// secplane HTTP shipper. Reads ClawManager backend address + agent session
// token from env vars that the openclaw-agent in the OpenClaw image already
// injects (CLAWMANAGER_AGENT_BASE_URL, CLAWMANAGER_INSTANCE_TOKEN). When any
// defense event lands on disk we POST the same record to ClawManager's
// secplane ingest endpoint. Failures are swallowed silently — the JSONL on
// disk remains the source of truth and ops can re-ingest later if needed.
const SECPLANE_INGEST_PATH = "/api/v1/secplane/agent/sec_events/batch";
function postEventToSecplane(record) {
    const baseURL = process.env.CLAWMANAGER_AGENT_BASE_URL;
    const token = process.env.CLAWMANAGER_INSTANCE_TOKEN || process.env.CLAWMANAGER_LLM_API_KEY;
    if (!baseURL || !token)
        return;
    // Map the ClawAegis-internal record into the wire shape secplane's ingest
    // handler (internal/secplane/ingest/handler.go IngestEvent) expects.
    const event = {
        event_id: `aegis-${record.timestamp}-${Math.random().toString(36).slice(2, 8)}`,
        ts: new Date(record.timestamp).toISOString(),
        hook: "clawaegisex",
        defense: record.defense,
        rule_id: record.defense,
        rule_name: record.defense,
        severity: record.result === "blocked" ? "high" : "medium",
        result: record.result,
        reason: record.reason ?? "",
        subject: record.toolName !== undefined
            ? `tool.${record.toolName}`
            : "clawaegisex.event",
        evidence: record.commandText ?? record.userInput ?? "",
        raw_payload: JSON.stringify({
            details: record.details,
            toolParams: record.toolParams,
        }).slice(0, 2048),
    };
    const url = baseURL.replace(/\/$/, "") + SECPLANE_INGEST_PATH;
    const body = JSON.stringify({ source: record.source ?? "aegis", events: [event] });
    // Use globalThis.fetch (Node 22 in the OpenClaw image has native fetch).
    // 30s timeout: ClawManager's secplane ingest endpoint can take 5–6s per
    // single event under load (auth lookup + rule re-eval + alert persist).
    // 3s aborted every legitimate post and the .catch() swallowed it silently,
    // so alerts disappeared without trace. 30s gives plenty of headroom while
    // still capping genuinely stuck network calls. Keep in sync with handlers.js.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 30000);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const f = globalThis.fetch;
    if (!f) {
        clearTimeout(timer);
        return;
    }
    f(url, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
        },
        body,
        signal: ac.signal,
    })
        .catch(() => {
        /* fail-open: disk JSONL stays as source of truth */
    })
        .finally(() => clearTimeout(timer));
}
function createDefenseEventWriter(stateDir) {
    const eventsPath = path.join(stateDir, DEFENSE_EVENTS_FILENAME);
    let ensured = false;
    return (record) => {
        const line = JSON.stringify(record) + "\n";
        const doWrite = async () => {
            if (!ensured) {
                await fs.mkdir(stateDir, { recursive: true });
                ensured = true;
            }
            await fs.appendFile(eventsPath, line, "utf8");
        };
        doWrite().catch(() => { });
        // Fire-and-forget HTTP shipping. Never await — the hook caller must not
        // be slowed down or fail if ClawManager is unreachable.
        try {
            postEventToSecplane(record);
        }
        catch {
            // ignore — fail-open
        }
    };
}
function createSkillScanEventWriter(stateDir) {
    const eventsPath = path.join(stateDir, SKILL_SCAN_EVENTS_FILENAME);
    let ensured = false;
    return (record) => {
        const line = JSON.stringify(record) + "\n";
        const doWrite = async () => {
            if (!ensured) {
                await fs.mkdir(stateDir, { recursive: true });
                ensured = true;
            }
            await fs.appendFile(eventsPath, line, "utf8");
        };
        doWrite().catch(() => { });
    };
}
function logObservedToolCall(params) {
    params.logger.warn(params.message, {
        event: "tool_call_observed",
        hook: "before_tool_call",
        mechanism: params.mechanism,
        toolName: params.toolName,
        sessionKey: params.sessionKey,
        runId: params.runId,
        reason: params.reason,
        mode: "observe",
        durationMs: params.durationMs,
        ...(params.extra ?? {}),
    });
}
export function createClawAegisRuntime(api, options) {
    const logger = createAegisLogger(api);
    const now = options?.now ?? Date.now;
    const stateDir = resolveClawAegisStateDir(api);
    const emitDefenseEvent = createDefenseEventWriter(stateDir);
    const config = resolveClawAegisPluginConfig(api);
    // Live-reloading view of the same config. Hot path handlers (e.g. the
    // per-message user_risk_scan) call getLiveConfig() instead of reading
    // `config` so that a freshly-dispatched user_config.json takes effect on
    // the NEXT hook event, without requiring an openclaw gateway restart.
    // Re-parse cost is gated behind a cheap fs.statSync that only triggers
    // when the file's mtime moved.
    let liveConfig = config;
    let liveConfigMtimeMs = getUserConfigMtimeMs(api.rootDir);
    const getLiveConfig = () => {
        const mt = getUserConfigMtimeMs(api.rootDir);
        if (mt !== 0 && mt !== liveConfigMtimeMs) {
            try {
                liveConfig = resolveClawAegisPluginConfig(api);
                liveConfigMtimeMs = mt;
                logger.info("clawaegisex: user_config.json 已热重载", {
                    event: "user_config_hot_reload",
                    mtimeMs: mt,
                    userRiskScanEnabled: liveConfig.userRiskScanEnabled,
                    disabledUserRiskFlags: liveConfig.disabledUserRiskFlags,
                });
            }
            catch (error) {
                logger.warn("clawaegisex: user_config.json 热重载失败，沿用上次配置", {
                    event: "user_config_hot_reload_failed",
                    reason: error instanceof Error ? error.message : String(error),
                });
            }
        }
        return liveConfig;
    };
    const skillScanRoots = resolveSkillScanRoots(api);
    const state = new ClawAegisState({ stateDir, logger, now: options?.now });
    const emitSkillScanEvent = createSkillScanEventWriter(stateDir);
    const scanService = new SkillScanService({
        state,
        logger,
        now: options?.now,
        runner: options?.scanRunner,
        onScanComplete: emitSkillScanEvent,
    });
    const toolCallDefenseStrategies = options?.toolCallDefenseStrategies ?? TOOL_CALL_DEFENSE_STRATEGIES;
    const staticSystemContext = config.promptGuardEnabled
        ? buildStaticSystemContext({
            selfProtectionEnabled: config.selfProtectionEnabled,
            toolCallEnforcementEnabled: config.toolCallEnforcementEnabled,
            protectedPaths: config.protectedPaths,
        })
        : undefined;
    const promptHooksEnabled = arePromptHooksEnabled(api);
    warnIfPromptHooksDisabled(api);
    return {
        state,
        scanService,
        hooks: {
            gateway_start: async () => {
                logger.info("clawaegisex: 网关启动", {
                    event: "gateway_start",
                });
                // openclaw 2026.5.4+ 引入 conversation hook gate: non-bundled plugin
                // 注册 llm_output / agent_end 时必须 plugins.entries.<id>.hooks.
                // allowConversationAccess=true, 否则 hook 被静默 block。ClawAegis 用
                // llm_output (prompt_self_block) 和 agent_end (run state cleanup),
                // 所以 gateway_start 时自动 patch openclaw.json。openclaw 的 config
                // watcher 会监听文件变化并自动 reload,重新注册时 flag 已生效。
                warnIfConversationAccessDisabled(api);
                ensureConversationAccessEnabled(api);
                try {
                    await state.loadPersistentState();
                    logger.info("clawaegisex: 已恢复持久化状态", {
                        event: "state_restored",
                    });
                }
                catch (error) {
                    logger.error("clawaegisex: 恢复持久化状态失败", {
                        event: "state_restore_failed",
                        reason: error instanceof Error ? error.message : String(error),
                    });
                }
                try {
                    const protectedRoots = config.selfProtectionEnabled
                        ? await resolveProtectedRoots(api, stateDir, config)
                        : [];
                    state.setProtectedRoots(protectedRoots);
                    logger.info("clawaegisex: 已解析受保护路径", {
                        event: "protected_roots_ready",
                        count: protectedRoots.length,
                        enabled: config.selfProtectionEnabled,
                    });
                }
                catch (error) {
                    logger.error("clawaegisex: 解析受保护路径失败", {
                        event: "protected_roots_failed",
                        reason: error instanceof Error ? error.message : String(error),
                    });
                }
                if (config.selfProtectionEnabled) {
                    try {
                        const integrityRecord = await buildSelfIntegrityRecord({
                            api,
                            stateDir,
                            protectedRoots: state.getProtectedRoots(),
                        });
                        state.setSelfIntegrityRecord(integrityRecord);
                        await state.persistSelfIntegrity();
                        logger.info("clawaegisex: 已刷新自完整性记录", {
                            event: "self_integrity_refreshed",
                        });
                    }
                    catch (error) {
                        logger.error("clawaegisex: 刷新自完整性记录失败", {
                            event: "self_integrity_failed",
                            reason: error instanceof Error ? error.message : String(error),
                        });
                    }
                }
                try {
                    if (!config.skillScanEnabled) {
                        logger.info("clawaegisex: 配置已关闭 skill 扫描", {
                            event: "skill_scan_disabled",
                        });
                        return;
                    }
                    if (config.skillRoots.length > 0) {
                        logger.warn("clawaegisex: 已忽略过时的 skillRoots 配置", {
                            event: "skill_scan_legacy_roots_ignored",
                            ignoredCount: config.skillRoots.length,
                        });
                    }
                    scanService.start();
                    if (config.startupSkillScan) {
                        void scanService
                            .scanRoots({ roots: skillScanRoots, budgetMs: STARTUP_SCAN_BUDGET_MS })
                            .catch((error) => {
                            logger.warn("clawaegisex: 启动阶段的 skill 扫描已降级", {
                                event: "startup_skill_scan_failed",
                                reason: error instanceof Error ? error.message : String(error),
                            });
                        });
                    }
                }
                catch (error) {
                    logger.error("clawaegisex: 启动 skill 扫描服务失败", {
                        event: "skill_scan_start_failed",
                        reason: error instanceof Error ? error.message : String(error),
                    });
                }
            },
            message_received: (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                if (sessionKey && event.content) {
                    state.noteLastUserInput(sessionKey, event.content);
                }
                logDefenseStart(logger, {
                    hook: "message_received",
                    mechanism: "user_risk_scan",
                    sessionKey,
                });
                const liveCfg = getLiveConfig();
                if (!liveCfg.userRiskScanEnabled) {
                    const durationMs = now() - startedAt;
                    logDefenseResult(logger, {
                        hook: "message_received",
                        mechanism: "user_risk_scan",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "message_received",
                        mechanism: "user_risk_scan",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    return;
                }
                // OpenClaw doesn't always populate ctx.sessionKey at the
                // message_received timing (it lands later, by before_message_write).
                // Still scan and emit defense events so a malicious user input is
                // never silently dropped — only state-tracking is skipped.
                const effectiveSessionKey = sessionKey ?? "anonymous";
                const match = detectUserRiskFlags(event.content ?? "", liveCfg.disabledUserRiskFlags);
                const durationMs = now() - startedAt;
                if (match.flags.length === 0) {
                    logDefenseResult(logger, {
                        hook: "message_received",
                        mechanism: "user_risk_scan",
                        sessionKey: effectiveSessionKey,
                        result: "clear",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "message_received",
                        mechanism: "user_risk_scan",
                        sessionKey: effectiveSessionKey,
                        result: "clear",
                        durationMs,
                    });
                    return;
                }
                // Per-flag mode partition: flags in observeOnlyUserRiskFlags get
                // recorded but do NOT propagate into state (so no dynamic prompt
                // guard is injected downstream); other matched flags are full
                // enforcement (note state + inject reminder).
                const observeOnlySet = new Set(liveCfg.observeOnlyUserRiskFlags ?? []);
                const enforceFlags = [];
                const observeFlags = [];
                for (const flag of match.flags) {
                    if (observeOnlySet.has(flag)) {
                        observeFlags.push(flag);
                    }
                    else {
                        enforceFlags.push(flag);
                    }
                }
                if (sessionKey && enforceFlags.length > 0) {
                    state.noteUserRisk(sessionKey, enforceFlags);
                }
                // If we have any enforce-mode match, the alert is blocked; otherwise
                // (purely observe-mode matches) keep the historical "observed" label.
                const eventResult = enforceFlags.length > 0 ? "blocked" : "observed";
                emitDefenseEvent({
                    timestamp: now(),
                    defense: "user_risk_scan",
                    result: eventResult,
                    reason: `检测到风险标记: ${match.flags.join(", ")}`,
                    details: {
                        flags: match.flags,
                        enforceFlags,
                        observeFlags,
                    },
                    userInput: (event.content ?? "").slice(0, 500),
                });
                logger.warn("clawaegisex: 检测到用户风险请求", {
                    event: "user_risk_detected",
                    hook: "message_received",
                    sessionKey,
                    flags: match.flags,
                    enforceFlags,
                    observeFlags,
                    result: eventResult,
                });
                logDefenseResult(logger, {
                    hook: "message_received",
                    mechanism: "user_risk_scan",
                    sessionKey,
                    result: "risk_detected",
                    durationMs,
                    flagCount: match.flags.length,
                }, "warn");
                logDefenseFinish(logger, {
                    hook: "message_received",
                    mechanism: "user_risk_scan",
                    sessionKey,
                    result: "risk_detected",
                    durationMs,
                    flagCount: match.flags.length,
                });
            },
            message_sending: (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                logDefenseStart(logger, {
                    hook: "message_sending",
                    mechanism: "output_redaction",
                    sessionKey,
                });
                if (!config.outputRedactionEnabled) {
                    const durationMs = now() - startedAt;
                    logDefenseResult(logger, {
                        hook: "message_sending",
                        mechanism: "output_redaction",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "message_sending",
                        mechanism: "output_redaction",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    return undefined;
                }
                const observedSecrets = sessionKey ? state.peekObservedSecrets(sessionKey) : [];
                const sanitized = sanitizeSensitiveOutputText(event.content, { observedSecrets });
                const durationMs = now() - startedAt;
                if (sanitized.changed) {
                    emitDefenseEvent({
                        timestamp: now(),
                        defense: "output_redaction",
                        result: "observed",
                        reason: `脱敏 ${sanitized.redactionCount} 处敏感内容`,
                        details: { redactionCount: sanitized.redactionCount, matchedKeywords: sanitized.matchedKeywords },
                    });
                    logger.warn("clawaegisex: 已脱敏对外发送消息中的敏感内容", {
                        event: "outbound_message_redacted",
                        hook: "message_sending",
                        sessionKey,
                        to: event.to,
                        redactionCount: sanitized.redactionCount,
                        matchedKeywords: sanitized.matchedKeywords,
                        durationMs,
                    });
                }
                logDefenseResult(logger, {
                    hook: "message_sending",
                    mechanism: "output_redaction",
                    sessionKey,
                    result: sanitized.changed ? "redacted" : "clear",
                    durationMs,
                    redactionCount: sanitized.redactionCount,
                });
                logDefenseFinish(logger, {
                    hook: "message_sending",
                    mechanism: "output_redaction",
                    sessionKey,
                    result: sanitized.changed ? "redacted" : "clear",
                    durationMs,
                    redactionCount: sanitized.redactionCount,
                });
                return sanitized.changed ? { content: sanitized.value } : undefined;
            },
            before_prompt_build: async (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                let syntheticState;
                const prompt = typeof event.prompt === "string" ? event.prompt : undefined;
                if (sessionKey && prompt?.trim()) {
                    state.notePromptSnapshot(sessionKey, prompt);
                }
                logDefenseStart(logger, {
                    hook: "before_prompt_build",
                    mechanism: "prompt_guard",
                    sessionKey,
                });
                if (!config.promptGuardEnabled || !promptHooksEnabled) {
                    const result = !config.promptGuardEnabled ? "disabled" : "prompt_hooks_disabled";
                    const durationMs = now() - startedAt;
                    logDefenseResult(logger, {
                        hook: "before_prompt_build",
                        mechanism: "prompt_guard",
                        sessionKey,
                        result,
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_prompt_build",
                        mechanism: "prompt_guard",
                        sessionKey,
                        result,
                        durationMs,
                    });
                    return undefined;
                }
                if (config.skillScanEnabled) {
                    try {
                        const skillReview = await scanService.inspectTurnSkillRisks({ roots: skillScanRoots });
                        if (skillReview.riskyAssessments.length > 0) {
                            const skillRiskFlags = [
                                ...new Set(skillReview.riskyAssessments.flatMap((assessment) => assessment.findings)),
                            ];
                            const riskySkills = [
                                ...new Set(skillReview.riskyAssessments.map((assessment) => assessment.skillId)),
                            ];
                            logger.warn("clawaegisex: 已将高风险 skill 提升为提示防护", {
                                event: "skill_prompt_guard_triggered",
                                hook: "before_prompt_build",
                                sessionKey,
                                riskySkillCount: riskySkills.length,
                                riskySkills,
                                skillRiskFlags,
                                reviewedCount: skillReview.reviewedCount,
                                rescannedCount: skillReview.rescannedCount,
                                reusedCount: skillReview.reusedCount,
                            });
                            if (sessionKey) {
                                state.noteSkillRisk(sessionKey, {
                                    flags: skillRiskFlags,
                                    skillIds: riskySkills,
                                });
                            }
                            else {
                                syntheticState = createSyntheticSkillRiskState({
                                    now: now(),
                                    skillRiskFlags,
                                    riskySkills,
                                });
                            }
                        }
                    }
                    catch (error) {
                        logger.error("clawaegisex: 本轮 skill 风险复核失败", {
                            event: "skill_prompt_guard_failed",
                            hook: "before_prompt_build",
                            reason: error instanceof Error ? error.message : String(error),
                        });
                    }
                }
                const currentState = sessionKey ? state.consumePromptState(sessionKey) : syntheticState;
                const dynamicPromptContext = buildDynamicPromptContext(currentState);
                const prependSystemContext = joinPresentTextSegments([
                    staticSystemContext,
                    dynamicPromptContext,
                ]);
                const durationMs = now() - startedAt;
                if (currentState?.prependNeeded) {
                    logger.info("clawaegisex: 已注入提示防护", {
                        event: "prompt_safeguards_injected",
                        hook: "before_prompt_build",
                        sessionKey,
                        userRiskFlags: currentState.userRiskFlags.length,
                        toolResultFlags: currentState.toolResultRiskFlags.length,
                        toolResultSuspicious: currentState.toolResultSuspicious,
                        skillRiskFlags: currentState.skillRiskFlags.length,
                        riskySkills: currentState.riskySkills.length,
                    });
                }
                if (dynamicPromptContext && currentState) {
                    const triggeredFlags = [];
                    if (currentState.userRiskFlags.length > 0) {
                        triggeredFlags.push(...currentState.userRiskFlags);
                    }
                    if (currentState.runtimeRiskFlags.length > 0) {
                        triggeredFlags.push(...currentState.runtimeRiskFlags);
                    }
                    if (currentState.toolResultSuspicious) {
                        triggeredFlags.push("tool_result_suspicious");
                    }
                    if (currentState.toolResultOversize) {
                        triggeredFlags.push("tool_result_oversize");
                    }
                    if (currentState.toolResultRiskFlags.length > 0) {
                        triggeredFlags.push(...currentState.toolResultRiskFlags);
                    }
                    if (currentState.riskySkills.length > 0) {
                        triggeredFlags.push(...currentState.riskySkills.map((s) => `risky_skill:${s}`));
                    }
                    emitDefenseEvent({
                        timestamp: now(),
                        defense: "prompt_guard",
                        result: "observed",
                        reason: `提示防护已注入安全规则: ${triggeredFlags.join(", ")}`,
                        details: {
                            hook: "before_prompt_build",
                            userRiskFlags: currentState.userRiskFlags,
                            runtimeRiskFlags: currentState.runtimeRiskFlags,
                            toolResultSuspicious: currentState.toolResultSuspicious,
                            toolResultOversize: currentState.toolResultOversize,
                            toolResultRiskFlags: currentState.toolResultRiskFlags,
                            skillRiskFlags: currentState.skillRiskFlags,
                            riskySkills: currentState.riskySkills,
                        },
                        userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                    });
                }
                if (!prependSystemContext) {
                    logDefenseResult(logger, {
                        hook: "before_prompt_build",
                        mechanism: "prompt_guard",
                        sessionKey,
                        result: "no_context_injected",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_prompt_build",
                        mechanism: "prompt_guard",
                        sessionKey,
                        result: "no_context_injected",
                        durationMs,
                    });
                    return undefined;
                }
                const promptGuardResult = staticSystemContext && dynamicPromptContext
                    ? "static_and_dynamic_injected"
                    : staticSystemContext
                        ? "static_only_injected"
                        : "dynamic_only_injected";
                logDefenseResult(logger, {
                    hook: "before_prompt_build",
                    mechanism: "prompt_guard",
                    sessionKey,
                    result: promptGuardResult,
                    durationMs,
                    userRiskFlags: currentState?.userRiskFlags.length ?? 0,
                    toolResultFlags: currentState?.toolResultRiskFlags.length ?? 0,
                    skillRiskFlags: currentState?.skillRiskFlags.length ?? 0,
                    riskySkills: currentState?.riskySkills.length ?? 0,
                }, "info");
                logDefenseFinish(logger, {
                    hook: "before_prompt_build",
                    mechanism: "prompt_guard",
                    sessionKey,
                    result: promptGuardResult,
                    durationMs,
                });
                return {
                    prependSystemContext,
                };
            },
            before_dispatch: async (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                logDefenseStart(logger, {
                    hook: "before_dispatch",
                    mechanism: "dispatch_guard",
                    sessionKey,
                });
                if (!config.dispatchGuardEnabled) {
                    logDefenseFinish(logger, {
                        hook: "before_dispatch",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "disabled",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const content = event.content?.trim();
                if (!content) {
                    logDefenseFinish(logger, {
                        hook: "before_dispatch",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "empty_content",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const violation = detectDispatchGuardViolation(content, config.protectedPaths);
                if (!violation.blocked) {
                    logDefenseFinish(logger, {
                        hook: "before_dispatch",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "clear",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const durationMs = now() - startedAt;
                const reason = violation.reason ?? BLOCK_REASON_DISPATCH_GUARD;
                emitDefenseEvent({
                    timestamp: now(),
                    defense: "dispatch_guard",
                    result: config.dispatchGuardMode === "enforce" ? "blocked" : "observed",
                    reason,
                    details: {
                        hook: "before_dispatch",
                        flags: violation.flags,
                        mode: config.dispatchGuardMode,
                    },
                    userInput: content,
                });
                if (config.dispatchGuardMode === "enforce") {
                    logger.warn("clawaegisex: before_dispatch 已拦截危险操作请求", {
                        event: "dispatch_guard_blocked",
                        hook: "before_dispatch",
                        sessionKey,
                        flags: violation.flags,
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_dispatch",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "blocked",
                        durationMs,
                    });
                    return {
                        handled: true,
                        text: `[ClawAegisEx] ${reason}\n\n所有破坏性操作必须通过标准 tool call 执行，不能绕过安全 hook。如确需执行，请联系管理员调整安全策略。`,
                    };
                }
                logger.info("clawaegisex: before_dispatch 已观测到危险操作请求（observe 模式）", {
                    event: "dispatch_guard_observed",
                    hook: "before_dispatch",
                    sessionKey,
                    flags: violation.flags,
                    durationMs,
                });
                logDefenseFinish(logger, {
                    hook: "before_dispatch",
                    mechanism: "dispatch_guard",
                    sessionKey,
                    result: "observed",
                    durationMs,
                });
                return undefined;
            },
            before_agent_reply: async (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                logDefenseStart(logger, {
                    hook: "before_agent_reply",
                    mechanism: "dispatch_guard",
                    sessionKey,
                });
                if (!config.dispatchGuardEnabled) {
                    logDefenseFinish(logger, {
                        hook: "before_agent_reply",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "disabled",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const cleanedBody = event.cleanedBody?.trim();
                if (!cleanedBody) {
                    logDefenseFinish(logger, {
                        hook: "before_agent_reply",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "empty_content",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const violation = detectDispatchGuardViolation(cleanedBody, config.protectedPaths);
                if (!violation.blocked) {
                    logDefenseFinish(logger, {
                        hook: "before_agent_reply",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "clear",
                        durationMs: now() - startedAt,
                    });
                    return undefined;
                }
                const durationMs = now() - startedAt;
                const reason = violation.reason ?? BLOCK_REASON_DISPATCH_GUARD;
                emitDefenseEvent({
                    timestamp: now(),
                    defense: "dispatch_guard",
                    result: config.dispatchGuardMode === "enforce" ? "blocked" : "observed",
                    reason,
                    details: {
                        hook: "before_agent_reply",
                        flags: violation.flags,
                        mode: config.dispatchGuardMode,
                    },
                    userInput: cleanedBody,
                });
                if (config.dispatchGuardMode === "enforce") {
                    logger.warn("clawaegisex: before_agent_reply 已拦截危险操作请求", {
                        event: "dispatch_guard_blocked",
                        hook: "before_agent_reply",
                        sessionKey,
                        flags: violation.flags,
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_agent_reply",
                        mechanism: "dispatch_guard",
                        sessionKey,
                        result: "blocked",
                        durationMs,
                    });
                    return {
                        handled: true,
                        reply: {
                            text: `[ClawAegisEx] ${reason}\n\n所有破坏性操作必须通过标准 tool call 执行，不能绕过安全 hook。如确需执行，请联系管理员调整安全策略。`,
                        },
                        reason: "dispatch_guard",
                    };
                }
                logger.info("clawaegisex: before_agent_reply 已观测到危险操作请求（observe 模式）", {
                    event: "dispatch_guard_observed",
                    hook: "before_agent_reply",
                    sessionKey,
                    flags: violation.flags,
                    durationMs,
                });
                logDefenseFinish(logger, {
                    hook: "before_agent_reply",
                    mechanism: "dispatch_guard",
                    sessionKey,
                    result: "observed",
                    durationMs,
                });
                return undefined;
            },
            before_tool_call: (event, ctx) => {
                const normalizedToolName = normalizeToolName(event.toolName);
                const normalizedParams = normalizeToolParamsForGuard(event.params ?? {});
                const sessionKey = ctx.sessionKey?.trim();
                const runId = ctx.runId?.trim();
                const selfProtectionMode = config.selfProtectionMode;
                const commandBlockMode = config.commandBlockMode;
                const encodingGuardMode = config.encodingGuardMode;
                const scriptProvenanceGuardMode = config.scriptProvenanceGuardMode;
                const memoryGuardMode = config.memoryGuardMode;
                const loopGuardMode = config.loopGuardMode;
                const exfiltrationGuardMode = config.exfiltrationGuardMode;
                const toolCallModes = {
                    selfProtection: selfProtectionMode,
                    commandBlock: commandBlockMode,
                    encodingGuard: encodingGuardMode,
                    commandObfuscation: mergeDefenseModes(commandBlockMode, encodingGuardMode),
                    scriptProvenanceGuard: scriptProvenanceGuardMode,
                    memoryGuard: memoryGuardMode,
                    loopGuard: loopGuardMode,
                    exfiltrationGuard: exfiltrationGuardMode,
                    collabGuard: config.collabGuardMode,
                };
                const toolGuardStartedAt = now();
                logDefenseStart(logger, {
                    hook: "before_tool_call",
                    mechanism: "tool_call_guard",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                });
                // --- kill switch (应急熔断): 启用时无条件阻断所有工具调用 ---
                // 这是最优先的拦截，跑在所有 defense strategies 之前。
                const liveCfgKill = getLiveConfig();
                if (liveCfgKill.killSwitchEnabled === true) {
                    const killReason = liveCfgKill.killSwitchReason || "";
                    const reason = `应急熔断已启用${killReason ? `：${killReason}` : ""}`;
                    emitDefenseEvent({
                        timestamp: now(),
                        defense: "kill_switch",
                        result: "blocked",
                        reason,
                        toolName: normalizedToolName,
                        details: { killSwitchReason: killReason },
                        toolParams: normalizedParams,
                        userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                    });
                    logger.warn("clawaegisex: 应急熔断阻断工具调用", {
                        event: "kill_switch_blocked",
                        hook: "before_tool_call",
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                        reason: killReason,
                    });
                    const killDurationMs = now() - toolGuardStartedAt;
                    logDefenseFinish(logger, {
                        hook: "before_tool_call",
                        mechanism: "tool_call_guard",
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                        result: "blocked",
                        durationMs: killDurationMs,
                        blockedBy: "kill_switch",
                    });
                    return { block: true, blockReason: reason };
                }
                // --- require-https: 阻止 http:// ws:// ftp:// 等明文出站 ---
                // mode: enforce 阻断 + 告警，observe 仅告警，off 跳过。
                const liveCfgHttps = getLiveConfig();
                const requireHttpsMode = liveCfgHttps.requireHttpsMode ?? "off";
                if (requireHttpsMode === "enforce" || requireHttpsMode === "observe") {
                    const paramsBlob = JSON.stringify(normalizedParams ?? {});
                    const insecureRe = /\b(http|ws|ftp):\/\/[^\s'"`<>]+/gi;
                    const allMatches = paramsBlob.match(insecureRe) ?? [];
                    const insecure = allMatches.filter((u) => /^(http|ws|ftp):\/\//i.test(u));
                    if (insecure.length > 0) {
                        const sample = insecure.slice(0, 5);
                        const reason = `明文协议 (${sample.map((u) => u.split(/[?#]/)[0]).join(", ")})，必须改用 https/wss`;
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: "require_https",
                            result: requireHttpsMode === "enforce" ? "blocked" : "observed",
                            reason,
                            toolName: normalizedToolName,
                            details: { urls: sample, count: insecure.length },
                            toolParams: normalizedParams,
                            userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                        });
                        logger.warn(requireHttpsMode === "enforce"
                            ? "clawaegisex: 阻断明文网络调用"
                            : "clawaegisex: 观察到明文网络调用", {
                            event: requireHttpsMode === "enforce" ? "require_https_blocked" : "require_https_observed",
                            hook: "before_tool_call",
                            sessionKey,
                            runId,
                            toolName: normalizedToolName,
                            mode: requireHttpsMode,
                            urls: sample,
                        });
                        if (requireHttpsMode === "enforce") {
                            const httpsDurationMs = now() - toolGuardStartedAt;
                            logDefenseFinish(logger, {
                                hook: "before_tool_call",
                                mechanism: "tool_call_guard",
                                sessionKey,
                                runId,
                                toolName: normalizedToolName,
                                result: "blocked",
                                durationMs: httpsDurationMs,
                                blockedBy: "require_https",
                            });
                            return { block: true, blockReason: reason };
                        }
                    }
                }
                // --- outbound-trust: 域名白名单 (Phase 1 — fingerprint pin 留待 Phase 2) ---
                const outboundTrustMode = liveCfgHttps.outboundTrustMode ?? "off";
                const trustedList = liveCfgHttps.outboundTrustedEndpoints ?? [];
                if ((outboundTrustMode === "enforce" || outboundTrustMode === "observe") &&
                    trustedList.length > 0) {
                    const paramsBlobHosts = JSON.stringify(normalizedParams ?? {});
                    const httpsUrls = paramsBlobHosts.match(/\b(https|wss):\/\/[^\s'"`<>]+/gi) ?? [];
                    const matchHost = (hostname, pattern) => {
                        const h = hostname.toLowerCase();
                        const p = pattern.toLowerCase();
                        if (p.startsWith("*."))
                            return h === p.slice(2) || h.endsWith(p.slice(1));
                        return h === p;
                    };
                    const blockedUrls = [];
                    for (const u of httpsUrls) {
                        let host = "";
                        try {
                            host = new URL(u).hostname;
                        }
                        catch {
                            host = "";
                        }
                        if (!host)
                            continue;
                        const allowed = trustedList.some((e) => matchHost(host, e.domain));
                        if (!allowed)
                            blockedUrls.push(`${host} (${u.split(/[?#]/)[0]})`);
                    }
                    if (blockedUrls.length > 0) {
                        const sample = blockedUrls.slice(0, 5);
                        const reason = `未在出站白名单：${sample.join("; ")}`;
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: "outbound_trust",
                            result: outboundTrustMode === "enforce" ? "blocked" : "observed",
                            reason,
                            toolName: normalizedToolName,
                            details: {
                                unauthorized: sample,
                                count: blockedUrls.length,
                                trustedCount: trustedList.length,
                            },
                            toolParams: normalizedParams,
                            userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                        });
                        logger.warn(outboundTrustMode === "enforce"
                            ? "clawaegisex: 阻断未授权出站"
                            : "clawaegisex: 观察到未授权出站", {
                            event: outboundTrustMode === "enforce" ? "outbound_trust_blocked" : "outbound_trust_observed",
                            hook: "before_tool_call",
                            sessionKey,
                            runId,
                            toolName: normalizedToolName,
                            mode: outboundTrustMode,
                            hosts: sample,
                        });
                        if (outboundTrustMode === "enforce") {
                            const trustDurationMs = now() - toolGuardStartedAt;
                            logDefenseFinish(logger, {
                                hook: "before_tool_call",
                                mechanism: "tool_call_guard",
                                sessionKey,
                                runId,
                                toolName: normalizedToolName,
                                result: "blocked",
                                durationMs: trustDurationMs,
                                blockedBy: "outbound_trust",
                            });
                            return { block: true, blockReason: reason };
                        }
                    }
                }
                const hasAnyEnabledStrategy = toolCallDefenseStrategies.some((strategy) => isDefenseEnabled(resolveToolCallDefenseMode(toolCallModes, strategy.modeSource)));
                if (!hasAnyEnabledStrategy) {
                    const durationMs = now() - toolGuardStartedAt;
                    logDefenseResult(logger, {
                        hook: "before_tool_call",
                        mechanism: "tool_call_guard",
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                        result: "disabled",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_tool_call",
                        mechanism: "tool_call_guard",
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                        result: "disabled",
                        durationMs,
                    });
                    return undefined;
                }
                const baseDir = process.cwd();
                const protectedRoots = isDefenseEnabled(selfProtectionMode) ? state.getProtectedRoots() : [];
                const pathCandidates = resolveProtectedPathCandidates(normalizedToolName, normalizedParams, baseDir);
                logger.debug?.("clawaegisex: 已规范化工具调用", {
                    event: "tool_call_normalized",
                    hook: "before_tool_call",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                    candidateCount: pathCandidates.length,
                });
                const previousToolCalls = runId ? state.peekRunToolCalls(runId) : [];
                const observedSecrets = sessionKey ? state.peekObservedSecrets(sessionKey) : [];
                const fingerprintTimestamp = now();
                if (runId && observedSecrets.length > 0) {
                    state.noteRunSecretFingerprints(runId, {
                        sessionKey,
                        fingerprints: buildSecretFingerprints(observedSecrets, "observed-secret", fingerprintTimestamp),
                    });
                }
                const runSecurityState = runId ? state.peekRunSecurityState(runId) : undefined;
                const promptSnapshot = sessionKey ? state.peekPromptSnapshot(sessionKey) : undefined;
                const commandText = readCommandText(normalizedParams);
                const toolCallContext = {
                    toolName: normalizedToolName,
                    params: normalizedParams,
                    commandText,
                    sessionKey,
                    runId,
                    baseDir,
                    protectedRoots,
                    pathCandidates,
                    previousToolCalls,
                    observedSecrets,
                    runSecurityState,
                    promptSnapshot,
                    protectedSkills: config.protectedSkills,
                    protectedPlugins: config.protectedPlugins,
                    now,
                    modes: toolCallModes,
                    helpers: {
                        resolveSelfProtectionTextViolation,
                        resolveOutsideWorkspaceDeletionViolation,
                        resolveProtectedPathViolation,
                        detectCommandObfuscationViolation,
                        detectHighRiskCommand,
                        resolveInlineExecutionViolation,
                        resolveMemoryGuardViolation,
                        resolveScriptProvenanceViolation,
                        reviewSuspiciousOutboundChain,
                        buildLoopGuardStableArgsKey,
                        isOutboundToolCall,
                    },
                    state: {
                        incrementLoopCounter: (nextSessionKey, nextRunId, stableArgsKey) => state.incrementLoopCounter(nextSessionKey, nextRunId, stableArgsKey),
                        noteRunSecuritySignals: (nextRunId, payload) => state.noteRunSecuritySignals(nextRunId, payload),
                        noteRuntimeRisk: (nextSessionKey, flags) => state.noteRuntimeRisk(nextSessionKey, flags),
                        noteRunToolCall: (nextRunId, record) => state.noteRunToolCall(nextRunId, record),
                        peekSessionScriptArtifacts: (nextSessionKey) => state.peekSessionScriptArtifacts(nextSessionKey),
                    },
                    collabConfig: config.collabGuardEnabled && config.collabTeamId
                        ? {
                            teamId: config.collabTeamId,
                            identityMode: config.collabIdentityMode,
                            schemaMode: config.collabSchemaMode,
                            quotaMode: config.collabQuotaMode,
                            approvalMode: config.collabApprovalMode,
                            xaddRps: config.collabXaddRps,
                            streamMaxLen: config.collabStreamMaxLen,
                            approvalThreshold: config.collabApprovalThreshold,
                        }
                        : undefined,
                };
                for (const strategy of toolCallDefenseStrategies) {
                    if (!strategy.appliesTo(toolCallContext)) {
                        continue;
                    }
                    const startedAt = now();
                    logDefenseStart(logger, {
                        hook: "before_tool_call",
                        mechanism: strategy.id,
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                    });
                    const evaluation = strategy.evaluate(toolCallContext);
                    const durationMs = now() - startedAt;
                    const resultMeta = {
                        hook: "before_tool_call",
                        mechanism: strategy.id,
                        sessionKey,
                        runId,
                        toolName: normalizedToolName,
                        result: evaluation.result,
                        durationMs,
                        ...(evaluation.extra ?? {}),
                    };
                    if (evaluation.result === "blocked") {
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: strategy.id,
                            result: "blocked",
                            toolName: normalizedToolName,
                            reason: evaluation.reason,
                            details: evaluation.extra,
                            commandText,
                            toolParams: normalizedParams,
                            userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                            source: strategy.id === "collab_guard" ? "collab_governance" : undefined,
                        });
                        logger.warn(strategy.blockedMessage ?? "clawaegisex: 已阻止风险工具调用", {
                            event: "tool_call_blocked",
                            hook: "before_tool_call",
                            toolName: normalizedToolName,
                            sessionKey,
                            runId,
                            reason: evaluation.reason,
                            ...(evaluation.extra ?? {}),
                        });
                        logDefenseFinish(logger, resultMeta);
                        const totalDurationMs = now() - toolGuardStartedAt;
                        logDefenseFinish(logger, {
                            hook: "before_tool_call",
                            mechanism: "tool_call_guard",
                            sessionKey,
                            runId,
                            toolName: normalizedToolName,
                            result: "blocked",
                            durationMs: totalDurationMs,
                            blockedBy: strategy.id,
                        });
                        return {
                            block: true,
                            blockReason: evaluation.reason,
                        };
                    }
                    if (evaluation.result === "observed") {
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: strategy.id,
                            result: "observed",
                            toolName: normalizedToolName,
                            reason: evaluation.reason ?? "unknown",
                            details: evaluation.extra,
                            commandText,
                            toolParams: normalizedParams,
                            userInput: sessionKey ? state.peekLastUserInput(sessionKey) : undefined,
                            source: strategy.id === "collab_guard" ? "collab_governance" : undefined,
                        });
                        logObservedToolCall({
                            logger,
                            mechanism: strategy.id,
                            message: strategy.observedMessage ?? "clawaegisex: 观察者模式命中风险工具调用，已放行",
                            sessionKey,
                            runId,
                            toolName: normalizedToolName,
                            reason: evaluation.reason ?? "unknown",
                            durationMs,
                            extra: evaluation.extra,
                        });
                        if (evaluation.emitResultLog) {
                            logDefenseResult(logger, resultMeta, evaluation.level ?? "warn");
                        }
                        logDefenseFinish(logger, resultMeta);
                        continue;
                    }
                    logDefenseResult(logger, resultMeta, evaluation.level ?? "info");
                    logDefenseFinish(logger, resultMeta);
                }
                if (runId) {
                    state.noteRunToolCall(runId, {
                        runId,
                        sessionKey,
                        toolName: normalizedToolName,
                        params: normalizedParams,
                        timestamp: now(),
                    });
                }
                const totalDurationMs = now() - toolGuardStartedAt;
                logDefenseResult(logger, {
                    hook: "before_tool_call",
                    mechanism: "tool_call_guard",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                    result: "allowed",
                    durationMs: totalDurationMs,
                });
                logDefenseFinish(logger, {
                    hook: "before_tool_call",
                    mechanism: "tool_call_guard",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                    result: "allowed",
                    durationMs: totalDurationMs,
                });
                return undefined;
            },
            after_tool_call: (event, ctx) => {
                const sessionKey = ctx.sessionKey?.trim();
                const runId = ctx.runId?.trim();
                const normalizedToolName = normalizeToolName(event.toolName);
                const normalizedParams = normalizeToolParamsForGuard(event.params ?? {});
                if (!runId) {
                    return;
                }
                if (!event.error && config.scriptProvenanceGuardEnabled) {
                    const artifacts = collectScriptArtifactRecords(normalizedToolName, normalizedParams, {
                        runId,
                        sessionKey,
                        timestamp: now(),
                        baseDir: process.cwd(),
                    });
                    if (artifacts.length > 0) {
                        state.noteRunScriptArtifacts(runId, {
                            sessionKey,
                            artifacts,
                        });
                        const derivedSignals = deriveScriptArtifactSignals(artifacts);
                        state.noteRunSecuritySignals(runId, {
                            sessionKey,
                            sourceSignals: derivedSignals.sourceSignals,
                            transformSignals: derivedSignals.transformSignals,
                            sinkSignals: derivedSignals.sinkSignals,
                            runtimeRiskFlags: derivedSignals.runtimeRiskFlags,
                        });
                        if (sessionKey && derivedSignals.runtimeRiskFlags.length > 0) {
                            state.noteRuntimeRisk(sessionKey, derivedSignals.runtimeRiskFlags);
                        }
                        logger.info("clawaegisex: 已记录本轮新产生的脚本产物", {
                            event: "script_artifacts_recorded",
                            hook: "after_tool_call",
                            sessionKey,
                            runId,
                            toolName: normalizedToolName,
                            artifactCount: artifacts.length,
                        });
                    }
                }
                const calls = state.peekRunToolCalls(runId);
                if (calls.length === 0) {
                    return;
                }
                const blockedCount = calls.filter((call) => call.blocked).length;
                logger.info("clawaegisex: 已更新同 run 工具调用链", {
                    event: "tool_call_chain_updated",
                    hook: "after_tool_call",
                    sessionKey,
                    runId,
                    totalCalls: calls.length,
                    blockedCalls: blockedCount,
                });
            },
            llm_output: (event, _ctx) => {
                if (!config.allDefensesEnabled)
                    return;
                for (const text of event.assistantTexts) {
                    if (!text.includes(AEGIS_REFUSAL_PREFIX))
                        continue;
                    // Extract refusal reason: text after "[ClawAegisEx]" on the same line
                    const idx = text.indexOf(AEGIS_REFUSAL_PREFIX);
                    const afterPrefix = text
                        .slice(idx + AEGIS_REFUSAL_PREFIX.length)
                        .split("\n")[0]
                        .trim();
                    const reason = afterPrefix || "LLM 自行拒绝（未提供具体原因）";
                    emitDefenseEvent({
                        timestamp: now(),
                        defense: "prompt_self_block",
                        result: "blocked",
                        reason,
                        details: {
                            hook: "llm_output",
                            model: event.model,
                            provider: event.provider,
                        },
                    });
                    logger.info("clawaegisex: LLM 输出包含 Aegis 拒绝标记", {
                        event: "prompt_self_block_detected",
                        hook: "llm_output",
                        model: event.model,
                        provider: event.provider,
                        reason,
                    });
                    // Only emit one event per LLM output, even if multiple texts match
                    break;
                }
            },
            agent_end: (_event, ctx) => {
                const sessionKey = ctx.sessionKey?.trim();
                const runId = ctx.runId?.trim();
                if (runId) {
                    state.clearRunToolCalls(runId);
                    state.clearRunSecurityState(runId);
                }
                if (sessionKey) {
                    state.clearSessionRuntimeState(sessionKey);
                }
                if (runId || sessionKey) {
                    logger.info("clawaegisex: 已清理本轮临时安全状态", {
                        event: "agent_runtime_state_cleared",
                        hook: "agent_end",
                        sessionKey,
                        runId,
                    });
                }
            },
            session_end: (_event, ctx) => {
                const sessionKey = ctx.sessionKey?.trim();
                if (!sessionKey) {
                    return;
                }
                state.clearSessionRuntimeState(sessionKey);
                // session 真正结束时才清 script artifacts（agent_end 每 turn 触发，
                // 不能清，否则跨 turn 的 write→exec 攻击无法拦截）。
                state.clearSessionScriptArtifacts(sessionKey);
                logger.info("clawaegisex: 已清理 session 级临时安全状态", {
                    event: "session_runtime_state_cleared",
                    hook: "session_end",
                    sessionKey,
                });
            },
            before_message_write: (event, ctx) => {
                const startedAt = now();
                const sessionKey = ctx.sessionKey?.trim();
                const message = event.message;
                if (message.role === "assistant") {
                    logDefenseStart(logger, {
                        hook: "before_message_write",
                        mechanism: "output_redaction",
                        sessionKey,
                    });
                    if (!config.outputRedactionEnabled) {
                        const durationMs = now() - startedAt;
                        logDefenseResult(logger, {
                            hook: "before_message_write",
                            mechanism: "output_redaction",
                            sessionKey,
                            result: "disabled",
                            durationMs,
                        });
                        logDefenseFinish(logger, {
                            hook: "before_message_write",
                            mechanism: "output_redaction",
                            sessionKey,
                            result: "disabled",
                            durationMs,
                        });
                        return undefined;
                    }
                    const observedSecrets = sessionKey ? state.peekObservedSecrets(sessionKey) : [];
                    const sanitized = sanitizeAssistantMessage(message, { observedSecrets });
                    const durationMs = now() - startedAt;
                    if (sanitized.changed) {
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: "output_redaction",
                            result: "observed",
                            reason: `脱敏 assistant 输出 ${sanitized.redactionCount} 处`,
                            details: { redactionCount: sanitized.redactionCount, matchedKeywords: sanitized.matchedKeywords },
                        });
                        logger.warn("clawaegisex: 已脱敏 assistant 输出中的敏感内容", {
                            event: "assistant_output_redacted",
                            hook: "before_message_write",
                            sessionKey,
                            redactionCount: sanitized.redactionCount,
                            matchedKeywords: sanitized.matchedKeywords,
                            durationMs,
                        });
                    }
                    logDefenseResult(logger, {
                        hook: "before_message_write",
                        mechanism: "output_redaction",
                        sessionKey,
                        result: sanitized.changed ? "redacted" : "clear",
                        durationMs,
                        redactionCount: sanitized.redactionCount,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_message_write",
                        mechanism: "output_redaction",
                        sessionKey,
                        result: sanitized.changed ? "redacted" : "clear",
                        durationMs,
                        redactionCount: sanitized.redactionCount,
                    });
                    return sanitized.changed ? { message: sanitized.message } : undefined;
                }
                logDefenseStart(logger, {
                    hook: "before_message_write",
                    mechanism: "tool_result_scan",
                    sessionKey,
                });
                const liveCfg = getLiveConfig();
                if (!liveCfg.toolResultScanEnabled) {
                    const durationMs = now() - startedAt;
                    logDefenseResult(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: "disabled",
                        durationMs,
                    });
                    return undefined;
                }
                if (!sessionKey || message.role !== "toolResult") {
                    const durationMs = now() - startedAt;
                    logDefenseResult(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: !sessionKey ? "skipped_missing_session" : "skipped_non_tool_result",
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: !sessionKey ? "skipped_missing_session" : "skipped_non_tool_result",
                        durationMs,
                    });
                    return undefined;
                }
                try {
                    const thirdPartyWebContent = isThirdPartyWebToolResultMessage(message);
                    const toolName = typeof message.toolName === "string" ? message.toolName : undefined;
                    const rawExtracted = thirdPartyWebContent
                        ? collectToolResultScanText(message)
                        : undefined;
                    if (thirdPartyWebContent) {
                        logger.info("clawaegisex: 开始处理第三方网页内容", {
                            event: "third_party_web_content_processing_started",
                            hook: "before_message_write",
                            sessionKey,
                            toolName,
                            contentCharsBefore: rawExtracted?.text.length ?? 0,
                            oversizeBefore: rawExtracted?.oversize ?? false,
                        });
                    }
                    const sanitized = sanitizeToolResultMessage(message);
                    const extracted = collectToolResultScanText(sanitized.message);
                    const observedSecrets = collectSensitiveOutputValues(extracted.text);
                    if (observedSecrets.length > 0) {
                        state.noteObservedSecrets(sessionKey, observedSecrets);
                    }
                    if (thirdPartyWebContent || sanitized.externalContent) {
                        logger.info("clawaegisex: 完成处理第三方网页内容", {
                            event: "third_party_web_content_processing_finished",
                            hook: "before_message_write",
                            sessionKey,
                            toolName,
                            contentCharsBefore: rawExtracted?.text.length ?? 0,
                            contentCharsAfter: extracted.text.length,
                            oversizeBefore: rawExtracted?.oversize ?? false,
                            oversizeAfter: extracted.oversize,
                            specialTokensRemoved: sanitized.removedTokenCount,
                            markerInjected: sanitized.markerInjected,
                            rewritten: sanitized.changed,
                        });
                    }
                    const outcome = scanToolResultText(extracted.text, extracted.oversize, liveCfg.disabledToolResultFlags);
                    // Partition flags by observe-only mode: enforce-mode flags drive
                    // turn state + dynamic runtime-risk reminders; observe-mode flags
                    // are still emitted as defense events for visibility but do NOT
                    // propagate into state, so the LLM is not nudged.
                    const trObserveSet = new Set(liveCfg.observeOnlyToolResultFlags ?? []);
                    const enforceFlags = outcome.riskFlags.filter((flag) => {
                        const base = flag.startsWith("encoded-") ? flag.slice("encoded-".length) : flag;
                        return !trObserveSet.has(base);
                    });
                    const stateOutcome = enforceFlags.length === outcome.riskFlags.length
                        ? outcome
                        : { ...outcome, riskFlags: enforceFlags };
                    state.noteToolResult(sessionKey, stateOutcome);
                    const encodedRiskFlags = enforceFlags.filter((flag) => flag.startsWith("encoded-"));
                    if (encodedRiskFlags.length > 0) {
                        state.noteRuntimeRisk(sessionKey, encodedRiskFlags);
                    }
                    const durationMs = now() - startedAt;
                    const logMeta = {
                        event: "tool_result_reviewed",
                        hook: "before_message_write",
                        sessionKey,
                        suspicious: outcome.suspicious,
                        oversize: outcome.oversize,
                        flags: outcome.riskFlags,
                        externalContent: sanitized.externalContent,
                        specialTokensRemoved: sanitized.removedTokenCount,
                        markerInjected: sanitized.markerInjected,
                        rewritten: sanitized.changed,
                        durationMs,
                    };
                    if (outcome.suspicious ||
                        outcome.oversize ||
                        outcome.riskFlags.length > 0 ||
                        sanitized.removedTokenCount > 0) {
                        emitDefenseEvent({
                            timestamp: now(),
                            defense: "tool_result_scan",
                            result: "observed",
                            toolName: typeof message.toolName === "string" ? message.toolName : undefined,
                            reason: `风险标记: ${outcome.riskFlags.join(", ") || "suspicious/oversize"}`,
                            details: { flags: outcome.riskFlags, suspicious: outcome.suspicious, oversize: outcome.oversize },
                        });
                        logger.warn("clawaegisex: 已完成工具结果审查", logMeta);
                    }
                    else {
                        logger.debug?.("clawaegisex: 已完成工具结果审查", logMeta);
                    }
                    logDefenseFinish(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: outcome.suspicious ||
                            outcome.oversize ||
                            outcome.riskFlags.length > 0 ||
                            sanitized.removedTokenCount > 0
                            ? "risk_detected"
                            : "clear",
                        durationMs,
                        flagCount: outcome.riskFlags.length,
                        specialTokensRemoved: sanitized.removedTokenCount,
                        markerInjected: sanitized.markerInjected,
                    });
                    return sanitized.changed ? { message: sanitized.message } : undefined;
                }
                catch (error) {
                    state.markToolResultSeen(sessionKey);
                    const durationMs = now() - startedAt;
                    logger.error("clawaegisex: 工具结果扫描已降级", {
                        event: "tool_result_scan_failed",
                        hook: "before_message_write",
                        sessionKey,
                        reason: error instanceof Error ? error.message : String(error),
                        durationMs,
                    });
                    logDefenseFinish(logger, {
                        hook: "before_message_write",
                        mechanism: "tool_result_scan",
                        sessionKey,
                        result: "degraded",
                        durationMs,
                    });
                }
                return undefined;
            },
        },
    };
}
