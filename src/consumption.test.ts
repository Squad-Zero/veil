/**
 * Package Consumption Tests
 *
 * These tests verify that the package works correctly when consumed
 * as an NPM package. They test the public API, exports, and types.
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
	// Individual rule sets
	COMMON_HIDDEN_DIRS,
	CREDENTIAL_LEAK_COMMANDS,
	type CliRule,
	DANGEROUS_COMMANDS,
	type EnvRule,
	type FileRule,
	PRESET_CI,
	PRESET_MINIMAL,
	// Presets
	PRESET_RECOMMENDED,
	PRESET_STRICT,
	type RuleAction,
	SENSITIVE_ENV_VARS,
	SENSITIVE_FILES,
	type Veil,
	type VeilBlocked,
	// Types (should be importable)
	type VeilConfig,
	type VeilSuccess,
	applyMask,
	// Main factory
	createVeil,
	evaluateRules,
	findMatchingRule,
	matchesPattern,
	// Utilities
	mergeConfigs,
} from "./index";

describe("Package Consumption", () => {
	describe("Exports", () => {
		it("exports createVeil factory function", () => {
			expect(createVeil).toBeDefined();
			expect(typeof createVeil).toBe("function");
		});

		it("exports all preset configurations", () => {
			expect(PRESET_RECOMMENDED).toBeDefined();
			expect(PRESET_STRICT).toBeDefined();
			expect(PRESET_MINIMAL).toBeDefined();
			expect(PRESET_CI).toBeDefined();
		});

		it("exports individual rule sets", () => {
			expect(COMMON_HIDDEN_DIRS).toBeDefined();
			expect(SENSITIVE_FILES).toBeDefined();
			expect(SENSITIVE_ENV_VARS).toBeDefined();
			expect(DANGEROUS_COMMANDS).toBeDefined();
			expect(CREDENTIAL_LEAK_COMMANDS).toBeDefined();
		});

		it("exports utility functions", () => {
			expect(mergeConfigs).toBeDefined();
			expect(matchesPattern).toBeDefined();
			expect(findMatchingRule).toBeDefined();
			expect(evaluateRules).toBeDefined();
			expect(applyMask).toBeDefined();
		});
	});

	describe("Basic Usage Pattern", () => {
		let veil: Veil;

		beforeEach(() => {
			const config: VeilConfig = {
				fileRules: [
					{ match: "node_modules", action: "deny" },
					{ match: /\.env/, action: "deny" },
				],
				envRules: [
					{ match: /^AWS_/, action: "mask" },
					{ match: "DATABASE_URL", action: "deny" },
				],
				cliRules: [{ match: /^rm\s+-rf/, action: "deny", safeAlternatives: ["rm -i"] }],
			};

			veil = createVeil(config);
		});

		it("creates a Veil instance with all expected methods", () => {
			expect(veil.checkFile).toBeDefined();
			expect(veil.checkDirectory).toBeDefined();
			expect(veil.filterPaths).toBeDefined();
			expect(veil.getEnv).toBeDefined();
			expect(veil.getVisibleEnv).toBeDefined();
			expect(veil.checkCommand).toBeDefined();
			expect(veil.guard).toBeDefined();
			expect(veil.scope).toBeDefined();
			expect(veil.getContext).toBeDefined();
			expect(veil.getInterceptedCalls).toBeDefined();
			expect(veil.clearInterceptedCalls).toBeDefined();
		});

		it("checkFile returns expected result types", () => {
			const allowed = veil.checkFile("src/index.ts");
			expect(allowed.ok).toBe(true);

			const blocked = veil.checkFile(".env");
			expect(blocked.ok).toBe(false);
			if (!blocked.ok) {
				expect(blocked.blocked).toBe(true);
				expect(blocked.reason).toBeDefined();
				expect(blocked.details).toBeDefined();
				expect(blocked.details.target).toBe(".env");
				expect(blocked.details.action).toBe("deny");
			}
		});

		it("filterPaths filters out blocked paths", () => {
			const paths = ["src/app.ts", "node_modules/pkg", ".env", "README.md"];
			const visible = veil.filterPaths(paths);
			expect(visible).toEqual(["src/app.ts", "README.md"]);
		});

		it("getEnv returns expected result types", () => {
			process.env.AWS_SECRET_KEY = "test-secret";
			process.env.NODE_ENV = "test";
			process.env.DATABASE_URL = "postgresql://localhost/db";

			// Masked
			const masked = veil.getEnv("AWS_SECRET_KEY");
			expect(masked.ok).toBe(true);
			if (masked.ok) {
				expect(masked.value).not.toBe("test-secret");
				expect(masked.value).toMatch(/\*+/);
			}

			// Denied
			const denied = veil.getEnv("DATABASE_URL");
			expect(denied.ok).toBe(false);

			// Allowed (no matching rule)
			const allowed = veil.getEnv("NODE_ENV");
			expect(allowed.ok).toBe(true);
			if (allowed.ok) {
				expect(allowed.value).toBe("test");
			}
		});

		it("checkCommand returns expected result types", () => {
			const allowed = veil.checkCommand("ls -la");
			expect(allowed.ok).toBe(true);
			if (allowed.ok) {
				expect(allowed.command).toBe("ls -la");
			}

			const blocked = veil.checkCommand("rm -rf /");
			expect(blocked.ok).toBe(false);
			if (!blocked.ok) {
				expect(blocked.blocked).toBe(true);
				expect(blocked.safeAlternatives).toContain("rm -i");
			}
		});
	});

	describe("Preset Usage Pattern", () => {
		it("creates veil from preset directly", () => {
			const veil = createVeil(PRESET_RECOMMENDED);
			expect(veil).toBeDefined();
			expect(veil.checkFile("node_modules").ok).toBe(false);
		});

		it("merges presets with custom config", () => {
			const custom: VeilConfig = {
				fileRules: [{ match: "custom-dir", action: "deny" }],
			};

			const merged = mergeConfigs(PRESET_MINIMAL, custom);
			const veil = createVeil(merged);

			// Has custom rule
			expect(veil.checkFile("custom-dir").ok).toBe(false);
			// Has preset rule
			expect(veil.checkFile(".env").ok).toBe(false);
		});

		it("combines multiple presets", () => {
			const combined = mergeConfigs(PRESET_MINIMAL, PRESET_CI);
			const veil = createVeil(combined);
			expect(veil).toBeDefined();
		});
	});

	describe("Injector Pattern", () => {
		it("uses file injector for synthetic content", () => {
			const veil = createVeil({
				injectors: {
					files: (path) => {
						if (path === "config.json") {
							return '{"synthetic": true}';
						}
						return null;
					},
				},
			});

			const result = veil.checkFile("config.json");
			expect(result.ok).toBe(true);
			if (result.ok && "value" in result) {
				expect(result.value).toBe('{"synthetic": true}');
			}
		});

		it("uses env injector for synthetic values", () => {
			const veil = createVeil({
				injectors: {
					env: (key) => {
						if (key === "INJECTED_VAR") {
							return "synthetic-value";
						}
						return null;
					},
				},
			});

			const result = veil.getEnv("INJECTED_VAR");
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toBe("synthetic-value");
			}
		});

		it("uses directory injector for synthetic listings", () => {
			const veil = createVeil({
				injectors: {
					directories: (path) => {
						if (path === "src") {
							return ["index.ts", "app.ts", "utils/"];
						}
						return null;
					},
				},
			});

			const result = veil.checkDirectory("src");
			expect(result.ok).toBe(true);
			if (result.ok && "value" in result) {
				expect(result.value).toEqual(["index.ts", "app.ts", "utils/"]);
			}
		});
	});

	describe("Scoped Policy Pattern", () => {
		it("creates scoped instances with additional rules", () => {
			const veil = createVeil({
				fileRules: [{ match: "base-blocked", action: "deny" }],
			});

			const scoped = veil.scope({
				fileRules: [{ match: "scope-blocked", action: "deny" }],
			});

			// Base rule still works
			expect(scoped.checkFile("base-blocked").ok).toBe(false);
			// Scoped rule also works
			expect(scoped.checkFile("scope-blocked").ok).toBe(false);
		});
	});

	describe("Audit Trail Pattern", () => {
		it("tracks intercepted operations", () => {
			const veil = createVeil({
				fileRules: [{ match: "blocked", action: "deny" }],
				envRules: [{ match: "SECRET", action: "deny" }],
			});

			veil.checkFile("blocked/file.ts");
			process.env.SECRET = "value";
			veil.getEnv("SECRET");

			const intercepted = veil.getInterceptedCalls();
			expect(intercepted.length).toBe(2);
			expect(intercepted[0]?.type).toBe("file");
			expect(intercepted[1]?.type).toBe("env");
		});

		it("clears intercepted calls", () => {
			const veil = createVeil({
				fileRules: [{ match: "blocked", action: "deny" }],
			});

			veil.checkFile("blocked");
			expect(veil.getInterceptedCalls().length).toBe(1);

			veil.clearInterceptedCalls();
			expect(veil.getInterceptedCalls().length).toBe(0);
		});
	});

	describe("Type Safety", () => {
		it("rule actions are type-safe", () => {
			const actions: RuleAction[] = ["allow", "deny", "mask", "rewrite"];
			expect(actions).toHaveLength(4);
		});

		it("config objects are type-safe", () => {
			const fileRule: FileRule = {
				match: "test",
				action: "deny",
				reason: "Test reason",
			};

			const envRule: EnvRule = {
				match: /^TEST_/,
				action: "mask",
				replacement: "[MASKED]",
			};

			const cliRule: CliRule = {
				match: /^dangerous/,
				action: "deny",
				safeAlternatives: ["safe-command"],
			};

			const config: VeilConfig = {
				fileRules: [fileRule],
				envRules: [envRule],
				cliRules: [cliRule],
			};

			expect(config.fileRules).toHaveLength(1);
			expect(config.envRules).toHaveLength(1);
			expect(config.cliRules).toHaveLength(1);
		});

		it("result types are properly discriminated", () => {
			const veil = createVeil({
				fileRules: [{ match: "blocked", action: "deny" }],
			});

			const result = veil.checkFile("blocked");

			// Type narrowing works
			if (result.ok) {
				// This is VeilSuccess
				const _success: VeilSuccess = result;
			} else {
				// This is VeilBlocked
				const blocked: VeilBlocked = result;
				expect(blocked.blocked).toBe(true);
				expect(blocked.reason).toBeDefined();
			}
		});
	});

	describe("Utility Functions", () => {
		it("matchesPattern works with strings", () => {
			expect(matchesPattern("node_modules/pkg", "node_modules")).toBe(true);
			expect(matchesPattern("src/index.ts", "node_modules")).toBe(false);
		});

		it("matchesPattern works with RegExp", () => {
			expect(matchesPattern("AWS_SECRET_KEY", /^AWS_/)).toBe(true);
			expect(matchesPattern("OTHER_VAR", /^AWS_/)).toBe(false);
		});

		it("applyMask masks values correctly", () => {
			// Values <= 4 chars get full mask
			expect(applyMask("key")).toBe("****");
			// Values > 4 chars show first and last with asterisks in between
			expect(applyMask("short")).toBe("s***t");
			expect(applyMask("longersecret")).toMatch(/^l\*+t$/);
			// Custom replacement overrides default masking
			expect(applyMask("anything", "[REDACTED]")).toBe("[REDACTED]");
		});

		it("findMatchingRule finds first match", () => {
			const rules: FileRule[] = [
				{ match: "first", action: "deny" },
				{ match: "second", action: "allow" },
			];

			const result = findMatchingRule("first-file", rules);
			expect(result?.rule.match).toBe("first");
			expect(result?.index).toBe(0);
		});
	});
});
