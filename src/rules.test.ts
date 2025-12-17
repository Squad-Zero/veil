/**
 * Rules System Tests
 */

import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	RULE_PACKS,
	fromCategory,
	fromPacks,
	listPacks,
	listRules,
	recommended,
	strict,
} from "./rules/categories";
import {
	crossPlatformRules,
	darwinRules,
	linuxRules,
	registerPlatformRules,
	windowsRules,
} from "./rules/platform";
import {
	buildConfigFromRules,
	clearRegistry,
	detectPlatform,
	extendRules,
	getAllRules,
	getRecommendedRules,
	getRule,
	getRulesByCategory,
	getRulesByPlatform,
} from "./rules/registry";

// We need to clear the registry between tests
// Since the registry is a module-level Map, we'll test carefully

describe("Rules System", () => {
	// Register platform rules once at the start of all tests
	beforeAll(() => {
		clearRegistry();
		registerPlatformRules();
	});

	describe("Platform Detection", () => {
		it("should detect linux platform", () => {
			// In our test environment, this is linux
			expect(detectPlatform()).toBe("linux");
		});
	});

	describe("Rule Registration", () => {
		it("should register platform rules", () => {
			const allRules = getAllRules();
			expect(allRules.length).toBeGreaterThan(0);
		});

		it("should get rule by ID", () => {
			const rule = getRule("linux/no-delete-root");
			expect(rule).toBeDefined();
			expect(rule?.description).toBe("Prevent rm -rf /");
		});

		it("should get rules by category", () => {
			const destructiveRules = getRulesByCategory("destructive");
			expect(destructiveRules.length).toBeGreaterThan(0);
			expect(destructiveRules.every((r) => r.category === "destructive")).toBe(true);
		});

		it("should get rules by platform", () => {
			const linuxOnlyRules = getRulesByPlatform("linux");
			expect(linuxOnlyRules.length).toBeGreaterThan(0);
			// Should include linux-specific and cross-platform rules
			const hasLinuxRule = linuxOnlyRules.some((r) => r.id.startsWith("linux/"));
			const hasCrossRule = linuxOnlyRules.some((r) => r.platforms.includes("all"));
			expect(hasLinuxRule).toBe(true);
			expect(hasCrossRule).toBe(true);
		});

		it("should build config from rules", () => {
			const rulesConfig = {
				"linux/no-delete-root": "error" as const,
				"env/mask-aws": "error" as const,
				"fs/hide-env-files": "warn" as const,
			};
			const config = buildConfigFromRules(rulesConfig, "linux");

			expect(config.cliRules?.length).toBeGreaterThan(0);
			expect(config.envRules?.length).toBeGreaterThan(0);
			expect(config.fileRules?.length).toBeGreaterThan(0);
		});

		it("should skip disabled rules", () => {
			const rulesConfig = {
				"linux/no-delete-root": "off" as const,
				"env/mask-aws": "error" as const,
			};
			const config = buildConfigFromRules(rulesConfig, "linux");

			// Should not have the linux/no-delete-root CLI rules
			const hasDeleteRoot = config.cliRules?.some((r) => r.reason?.includes("delete root"));
			expect(hasDeleteRoot).toBeFalsy();
		});

		it("should skip platform-incompatible rules", () => {
			const rulesConfig = {
				"win/no-delete-system32": "error" as const,
			};
			const config = buildConfigFromRules(rulesConfig, "linux");

			// Should have no CLI rules since win rules don't apply to linux
			expect(config.cliRules?.length).toBe(0);
		});
	});

	describe("Platform Rules", () => {
		it("should have windows rules", () => {
			expect(windowsRules.length).toBeGreaterThan(0);
			expect(windowsRules.every((r) => r.platforms.includes("windows"))).toBe(true);
		});

		it("should have darwin rules", () => {
			expect(darwinRules.length).toBeGreaterThan(0);
			expect(darwinRules.every((r) => r.platforms.includes("darwin"))).toBe(true);
		});

		it("should have linux rules", () => {
			expect(linuxRules.length).toBeGreaterThan(0);
			expect(linuxRules.every((r) => r.platforms.includes("linux"))).toBe(true);
		});

		it("should have cross-platform rules", () => {
			expect(crossPlatformRules.length).toBeGreaterThan(0);
			expect(crossPlatformRules.every((r) => r.platforms.includes("all"))).toBe(true);
		});

		describe("Windows-specific rules", () => {
			it("should block System32 deletion", () => {
				const rule = windowsRules.find((r) => r.id === "win/no-delete-system32");
				expect(rule).toBeDefined();
				expect(rule?.cliRules).toBeDefined();
				expect(rule?.cliRules?.some((r) => r.action === "deny")).toBe(true);
			});

			it("should block format commands", () => {
				const rule = windowsRules.find((r) => r.id === "win/no-format-drive");
				expect(rule).toBeDefined();
			});
		});

		describe("macOS-specific rules", () => {
			it("should block /System deletion", () => {
				const rule = darwinRules.find((r) => r.id === "darwin/no-delete-system");
				expect(rule).toBeDefined();
			});

			it("should hide keychain", () => {
				const rule = darwinRules.find((r) => r.id === "darwin/hide-keychain");
				expect(rule).toBeDefined();
				expect(rule?.fileRules?.length).toBeGreaterThan(0);
			});
		});

		describe("Linux-specific rules", () => {
			it("should block rm -rf /", () => {
				const rule = linuxRules.find((r) => r.id === "linux/no-delete-root");
				expect(rule).toBeDefined();
			});

			it("should hide /etc/shadow", () => {
				const rule = linuxRules.find((r) => r.id === "linux/hide-shadow");
				expect(rule).toBeDefined();
			});

			it("should block fork bombs", () => {
				const rule = linuxRules.find((r) => r.id === "linux/no-fork-bomb");
				expect(rule).toBeDefined();
			});
		});
	});

	describe("Rule Packs", () => {
		it("should have security:recommended pack", () => {
			expect(RULE_PACKS["security:recommended"]).toBeDefined();
			expect(RULE_PACKS["security:recommended"].rules.length).toBeGreaterThan(0);
		});

		it("should have platform packs", () => {
			expect(RULE_PACKS["platform:windows"]).toBeDefined();
			expect(RULE_PACKS["platform:darwin"]).toBeDefined();
			expect(RULE_PACKS["platform:linux"]).toBeDefined();
		});

		it("should have context packs", () => {
			expect(RULE_PACKS["context:dev"]).toBeDefined();
			expect(RULE_PACKS["context:ci"]).toBeDefined();
			expect(RULE_PACKS["context:production"]).toBeDefined();
		});

		it("should create config from packs", () => {
			const config = fromPacks("security:recommended", "platform:linux");
			expect(Object.keys(config).length).toBeGreaterThan(0);
			expect(config["env/mask-aws"]).toBe("error");
			expect(config["linux/no-delete-root"]).toBe("error");
		});

		it("should handle unknown packs gracefully", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
				// noop
			});
			const config = fromPacks("unknown-pack");
			expect(Object.keys(config).length).toBe(0);
			expect(warnSpy).toHaveBeenCalled();
			warnSpy.mockRestore();
		});
	});

	describe("Category Helpers", () => {
		it("should get rules from category", () => {
			const credentialRules = fromCategory("credentials");
			expect(Object.keys(credentialRules).length).toBeGreaterThan(0);
		});

		it("should respect severity parameter", () => {
			const rules = fromCategory("credentials", "warn");
			expect(Object.values(rules).every((v) => v === "warn")).toBe(true);
		});
	});

	describe("Convenience Functions", () => {
		it("should get recommended config", () => {
			const config = recommended();
			expect(Object.keys(config).length).toBeGreaterThan(0);
		});

		it("should get strict config", () => {
			const config = strict();
			expect(Object.keys(config).length).toBeGreaterThan(0);
		});

		it("should list all rules", () => {
			const rules = listRules();
			expect(rules.length).toBeGreaterThan(0);
			expect(rules.some((r) => r.startsWith("linux/"))).toBe(true);
		});

		it("should list all packs", () => {
			const packs = listPacks();
			expect(packs.length).toBeGreaterThan(0);
			expect(packs).toContain("security:recommended");
		});
	});

	describe("Rule Extension", () => {
		it("should extend rules config", () => {
			const base = {
				"env/mask-aws": "error" as const,
				"env/mask-azure": "error" as const,
			};
			const overrides = {
				"env/mask-aws": "off" as const,
				"fs/hide-env-files": "warn" as const,
			};
			const extended = extendRules(base, overrides);

			expect(extended["env/mask-aws"]).toBe("off");
			expect(extended["env/mask-azure"]).toBe("error");
			expect(extended["fs/hide-env-files"]).toBe("warn");
		});
	});

	describe("getRecommendedRules", () => {
		it("should return recommended rules for platform", () => {
			const rules = getRecommendedRules("linux");
			expect(Object.keys(rules).length).toBeGreaterThan(0);
		});
	});
});
