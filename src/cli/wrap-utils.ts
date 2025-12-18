/**
 * Wrap utilities for Veil CLI
 *
 * Handles config file discovery and loading for the shell wrapper.
 * Extracted for testability.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import type { VeilConfig } from "../types.js";

export const CONFIG_FILENAME = ".veilrc.json";

/**
 * Find veil config file by searching up the directory tree
 * Checks for both JS/TS config files and .veilrc.json
 */
export function findConfigDir(startDir: string): string | null {
    let dir = startDir;
    // Check for .veilrc.json first, then JS/TS configs
    const configFiles = [CONFIG_FILENAME, "veil.config.ts", "veil.config.js", "veil.config.mjs"];

    while (dir !== dirname(dir)) {
        for (const configFile of configFiles) {
            if (existsSync(join(dir, configFile))) {
                return dir;
            }
        }
        dir = dirname(dir);
    }

    return null;
}

/**
 * Determine which config file exists in a directory
 */
export function getConfigFilePath(configDir: string): { path: string; type: "json" | "js" } | null {
    // Check .veilrc.json first
    const jsonPath = join(configDir, CONFIG_FILENAME);
    if (existsSync(jsonPath)) {
        return { path: jsonPath, type: "json" };
    }

    // Check JS/TS configs
    const jsConfigs = ["veil.config.js", "veil.config.mjs", "veil.config.ts"];
    for (const configFile of jsConfigs) {
        const fullPath = join(configDir, configFile);
        if (existsSync(fullPath)) {
            return { path: fullPath, type: "js" };
        }
    }

    return null;
}

/**
 * Parse a .veilrc.json file and convert string patterns to RegExp where appropriate
 */
export function parseJsonConfig(content: string): VeilConfig {
    const parsed = JSON.parse(content) as VeilConfig;

    // Convert string patterns back to RegExp where appropriate
    const convertMatch = (match: string | RegExp): string | RegExp => {
        if (typeof match !== "string") return match;
        return match.startsWith("^") || match.includes("|") ? new RegExp(match, "i") : match;
    };

    const result: VeilConfig = {};

    if (parsed.fileRules) {
        result.fileRules = parsed.fileRules.map((rule) => ({
            ...rule,
            match: convertMatch(rule.match),
        }));
    }

    if (parsed.envRules) {
        result.envRules = parsed.envRules.map((rule) => ({
            ...rule,
            match: convertMatch(rule.match),
        }));
    }

    if (parsed.cliRules) {
        result.cliRules = parsed.cliRules.map((rule) => ({
            ...rule,
            match: convertMatch(rule.match),
        }));
    }

    return result;
}

/**
 * Load veil config from a directory
 * Supports both .veilrc.json and veil.config.ts/js/mjs
 */
export async function loadConfig(configDir: string): Promise<VeilConfig | undefined> {
    const configInfo = getConfigFilePath(configDir);

    if (!configInfo) {
        return undefined;
    }

    if (configInfo.type === "json") {
        try {
            const content = readFileSync(configInfo.path, "utf-8");
            return parseJsonConfig(content);
        } catch (error) {
            console.error(`[veil-wrap] Failed to load ${configInfo.path}: ${error instanceof Error ? error.message : String(error)}`);
            return undefined;
        }
    }

    // JS/TS config - use dynamic import
    try {
        const loaded = (await import(pathToFileURL(configInfo.path).href)) as {
            default?: VeilConfig;
        } & VeilConfig;
        return loaded.default ?? loaded;
    } catch (error) {
        // Log the error instead of silently failing
        console.error(`[veil-wrap] Failed to load ${configInfo.path}: ${error instanceof Error ? error.message : String(error)}`);
        return undefined;
    }
}
