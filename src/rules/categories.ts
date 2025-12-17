/**
 * Rule Categories and Packs
 *
 * Pre-built collections of rules for common use cases
 */

import { getAllRules } from "./registry";
import type { RulePack, RulesConfig } from "./types";

// ============================================================================
// Rule Packs - Pre-built Collections
// ============================================================================

/**
 * All available rule packs
 */
export const RULE_PACKS: Record<string, RulePack> = {
	// Security-focused packs
	"security:recommended": {
		name: "Security Recommended",
		description: "Essential security rules for any project",
		rules: [
			"env/mask-aws",
			"env/mask-azure",
			"env/mask-gcp",
			"env/deny-passwords",
			"env/mask-tokens",
			"env/mask-secrets",
			"env/deny-database-urls",
			"fs/hide-env-files",
			"fs/hide-private-keys",
			"cli/no-curl-pipe-bash",
			"cli/no-credential-echo",
		],
	},
	"security:strict": {
		name: "Security Strict",
		description: "Maximum security - blocks more aggressively",
		rules: [
			// All recommended rules
			"env/mask-aws",
			"env/mask-azure",
			"env/mask-gcp",
			"env/deny-passwords",
			"env/mask-tokens",
			"env/mask-secrets",
			"env/deny-database-urls",
			"fs/hide-env-files",
			"fs/hide-private-keys",
			"fs/hide-docker-config",
			"fs/hide-npm-config",
			"fs/hide-git-credentials",
			"cli/no-curl-pipe-bash",
			"cli/no-wget-pipe-bash",
			"cli/no-credential-echo",
			"cli/no-curl-with-password",
		],
	},

	// Platform packs
	"platform:windows": {
		name: "Windows",
		description: "Windows-specific protections",
		rules: [
			"win/no-delete-system32",
			"win/no-delete-windows",
			"win/no-delete-program-files",
			"win/no-format-drive",
			"win/no-delete-above-cwd",
			"win/no-modify-registry",
			"win/hide-ntuser",
			"win/hide-sam",
			"win/hide-credential-manager",
		],
	},
	"platform:darwin": {
		name: "macOS",
		description: "macOS-specific protections",
		rules: [
			"darwin/no-delete-system",
			"darwin/no-delete-library",
			"darwin/no-delete-applications",
			"darwin/no-delete-above-cwd",
			"darwin/hide-keychain",
			"darwin/no-security-dump",
			"darwin/hide-ssh",
			"darwin/no-disable-sip",
		],
	},
	"platform:linux": {
		name: "Linux",
		description: "Linux-specific protections",
		rules: [
			"linux/no-delete-root",
			"linux/no-delete-boot",
			"linux/no-delete-etc",
			"linux/no-delete-var",
			"linux/no-delete-above-cwd",
			"linux/no-delete-home-recursive",
			"linux/no-dd-to-disk",
			"linux/no-mkfs",
			"linux/hide-shadow",
			"linux/hide-ssh",
			"linux/hide-gnupg",
			"linux/no-fork-bomb",
			"linux/no-chmod-777-recursive",
		],
	},

	// Context packs
	"context:dev": {
		name: "Development",
		description: "Rules for local development",
		rules: [
			"fs/hide-node-modules",
			"fs/hide-vcs",
			"fs/hide-build-output",
			"fs/hide-env-files",
			"fs/hide-private-keys",
			"env/mask-tokens",
			"env/mask-secrets",
		],
	},
	"context:ci": {
		name: "CI/CD",
		description: "Rules for CI/CD pipelines",
		rules: [
			"env/mask-aws",
			"env/mask-azure",
			"env/mask-gcp",
			"env/deny-passwords",
			"env/mask-tokens",
			"fs/hide-private-keys",
			"cli/no-curl-pipe-bash",
		],
	},
	"context:production": {
		name: "Production",
		description: "Maximum protection for production environments",
		rules: [
			"env/mask-aws",
			"env/mask-azure",
			"env/mask-gcp",
			"env/deny-passwords",
			"env/mask-tokens",
			"env/mask-secrets",
			"env/deny-database-urls",
			"fs/hide-env-files",
			"fs/hide-private-keys",
			"fs/hide-docker-config",
			"cli/no-curl-pipe-bash",
			"cli/no-credential-echo",
			"cli/no-curl-with-password",
		],
	},

	// Minimal pack
	minimal: {
		name: "Minimal",
		description: "Just the essentials",
		rules: ["fs/hide-env-files", "env/deny-passwords", "env/mask-tokens"],
	},
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get rules config from pack names
 */
export function fromPacks(...packNames: string[]): RulesConfig {
	const config: RulesConfig = {};

	for (const packName of packNames) {
		const pack = RULE_PACKS[packName];
		if (!pack) {
			console.warn(`Unknown rule pack: ${packName}`);
			continue;
		}

		for (const ruleId of pack.rules) {
			config[ruleId] = "error";
		}
	}

	return config;
}

/**
 * Get all rules by category as a config
 */
export function fromCategory(category: string, severity: "error" | "warn" = "error"): RulesConfig {
	const config: RulesConfig = {};

	for (const rule of getAllRules()) {
		if (rule.category === category) {
			config[rule.id] = severity;
		}
	}

	return config;
}

/**
 * Create a recommended config for the current platform
 */
export function recommended(): RulesConfig {
	const platform = process.platform;
	const packs = ["security:recommended", "context:dev"];

	switch (platform) {
		case "win32":
			packs.push("platform:windows");
			break;
		case "darwin":
			packs.push("platform:darwin");
			break;
		default:
			packs.push("platform:linux");
	}

	return fromPacks(...packs);
}

/**
 * Create a strict config for the current platform
 */
export function strict(): RulesConfig {
	const platform = process.platform;
	const packs = ["security:strict", "context:production"];

	switch (platform) {
		case "win32":
			packs.push("platform:windows");
			break;
		case "darwin":
			packs.push("platform:darwin");
			break;
		default:
			packs.push("platform:linux");
	}

	return fromPacks(...packs);
}

/**
 * List all available rule IDs
 */
export function listRules(): string[] {
	return getAllRules().map((r) => r.id);
}

/**
 * List all available pack names
 */
export function listPacks(): string[] {
	return Object.keys(RULE_PACKS);
}
