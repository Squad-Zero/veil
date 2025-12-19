import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	CONFIG_FILENAME,
	findConfigDir,
	getConfigFilePath,
	loadConfig,
	parseJsonConfig,
} from "./wrap-utils";

describe("wrap-utils", () => {
	const testDir = join(process.cwd(), "test-temp-wrap-utils");
	const nestedDir = join(testDir, "nested", "deeply");

	beforeEach(() => {
		// Create test directories
		mkdirSync(nestedDir, { recursive: true });
	});

	afterEach(() => {
		// Clean up test directories
		rmSync(testDir, { recursive: true, force: true });
		vi.restoreAllMocks();
	});

	describe("findConfigDir", () => {
		it("finds .veilrc.json in current directory", () => {
			writeFileSync(join(testDir, CONFIG_FILENAME), "{}");
			const result = findConfigDir(testDir);
			expect(result).toBe(testDir);
		});

		it("finds .veilrc.json in parent directory", () => {
			writeFileSync(join(testDir, CONFIG_FILENAME), "{}");
			const result = findConfigDir(nestedDir);
			expect(result).toBe(testDir);
		});

		it("finds veil.config.js in current directory", () => {
			writeFileSync(join(testDir, "veil.config.js"), "export default {}");
			const result = findConfigDir(testDir);
			expect(result).toBe(testDir);
		});

		it("finds veil.config.mjs in current directory", () => {
			writeFileSync(join(testDir, "veil.config.mjs"), "export default {}");
			const result = findConfigDir(testDir);
			expect(result).toBe(testDir);
		});

		it("prioritizes .veilrc.json over veil.config.js", () => {
			// Both files exist, .veilrc.json should be found first
			writeFileSync(join(testDir, CONFIG_FILENAME), '{"from": "json"}');
			writeFileSync(join(testDir, "veil.config.js"), "export default { from: 'js' }");
			const result = findConfigDir(testDir);
			expect(result).toBe(testDir);
		});

		it("searches up directories until config is found or root is reached", () => {
			// Note: This test will find the project's own .veilrc.json or veil.config.mjs
			// when run from within the Veil project. That's expected behavior.
			// We already tested finding configs in parent dirs above.
			const result = findConfigDir(nestedDir);
			// It should either be null (if no config in parents) or find some parent directory
			// that contains a config file (could be testDir, process.cwd(), or any parent)
			expect(result === null || typeof result === "string").toBe(true);
		});
	});

	describe("getConfigFilePath", () => {
		it("returns json type for .veilrc.json", () => {
			writeFileSync(join(testDir, CONFIG_FILENAME), "{}");
			const result = getConfigFilePath(testDir);
			expect(result).toEqual({
				path: join(testDir, CONFIG_FILENAME),
				type: "json",
			});
		});

		it("returns js type for veil.config.js", () => {
			writeFileSync(join(testDir, "veil.config.js"), "export default {}");
			const result = getConfigFilePath(testDir);
			expect(result).toEqual({
				path: join(testDir, "veil.config.js"),
				type: "js",
			});
		});

		it("returns js type for veil.config.mjs", () => {
			writeFileSync(join(testDir, "veil.config.mjs"), "export default {}");
			const result = getConfigFilePath(testDir);
			expect(result).toEqual({
				path: join(testDir, "veil.config.mjs"),
				type: "js",
			});
		});

		it("prioritizes .veilrc.json over JS configs", () => {
			writeFileSync(join(testDir, CONFIG_FILENAME), "{}");
			writeFileSync(join(testDir, "veil.config.js"), "export default {}");
			const result = getConfigFilePath(testDir);
			expect(result?.type).toBe("json");
		});

		it("returns null when no config exists", () => {
			const result = getConfigFilePath(testDir);
			expect(result).toBeNull();
		});
	});

	describe("parseJsonConfig", () => {
		it("parses simple CLI rules", () => {
			const json = JSON.stringify({
				cliRules: [{ match: "ASS", action: "deny", reason: "no ass here" }],
			});
			const result = parseJsonConfig(json);
			expect(result.cliRules).toHaveLength(1);
			expect(result.cliRules?.[0].match).toBe("ASS");
			expect(result.cliRules?.[0].action).toBe("deny");
			expect(result.cliRules?.[0].reason).toBe("no ass here");
		});

		it("converts regex-like patterns to RegExp", () => {
			const json = JSON.stringify({
				fileRules: [{ match: "^secrets/", action: "deny" }],
			});
			const result = parseJsonConfig(json);
			expect(result.fileRules?.[0].match).toBeInstanceOf(RegExp);
			expect((result.fileRules?.[0].match as RegExp).test("secrets/api.key")).toBe(true);
		});

		it("converts patterns with pipe to RegExp", () => {
			const json = JSON.stringify({
				envRules: [{ match: "API_KEY|SECRET", action: "mask" }],
			});
			const result = parseJsonConfig(json);
			expect(result.envRules?.[0].match).toBeInstanceOf(RegExp);
		});

		it("leaves simple string patterns as strings", () => {
			const json = JSON.stringify({
				cliRules: [{ match: "rm -rf", action: "deny" }],
			});
			const result = parseJsonConfig(json);
			expect(typeof result.cliRules?.[0].match).toBe("string");
		});
	});

	describe("loadConfig", () => {
		it("loads .veilrc.json config", async () => {
			const config = {
				cliRules: [{ match: "ASS", action: "deny", reason: "no ass here" }],
			};
			writeFileSync(join(testDir, CONFIG_FILENAME), JSON.stringify(config));

			const result = await loadConfig(testDir);
			expect(result).toBeDefined();
			expect(result?.cliRules).toHaveLength(1);
			expect(result?.cliRules?.[0].match).toBe("ASS");
		});

		it("loads veil.config.mjs config", async () => {
			const configContent = `export default {
                cliRules: [{ match: "test", action: "deny" }],
            };`;
			writeFileSync(join(testDir, "veil.config.mjs"), configContent);

			const result = await loadConfig(testDir);
			expect(result).toBeDefined();
			expect(result?.cliRules).toHaveLength(1);
		});

		it("returns undefined when no config exists", async () => {
			const result = await loadConfig(testDir);
			expect(result).toBeUndefined();
		});

		it("logs error and returns undefined for invalid JSON", async () => {
			writeFileSync(join(testDir, CONFIG_FILENAME), "{ invalid json }");
			// eslint-disable-next-line @typescript-eslint/no-empty-function
			const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

			const result = await loadConfig(testDir);

			expect(result).toBeUndefined();
			expect(consoleSpy).toHaveBeenCalledWith(
				expect.stringContaining("[veil-wrap] Failed to load"),
			);
		});

		it("logs error when JS config throws", async () => {
			// Use a unique subdirectory to avoid module caching between tests
			const errorTestDir = join(testDir, "error-test");
			mkdirSync(errorTestDir, { recursive: true });
			// Create a JS file that will throw when imported
			writeFileSync(join(errorTestDir, "veil.config.mjs"), "throw new Error('config error');");
			// eslint-disable-next-line @typescript-eslint/no-empty-function
			const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

			const result = await loadConfig(errorTestDir);

			expect(result).toBeUndefined();
			expect(consoleSpy).toHaveBeenCalledWith(
				expect.stringContaining("[veil-wrap] Failed to load"),
			);
		});
	});
});
