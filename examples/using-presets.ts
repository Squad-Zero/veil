/**
 * Using Veil Presets
 *
 * This example demonstrates how to use built-in presets
 * for quick configuration without defining rules from scratch.
 */

import {
	// Individual rule sets for customization
	COMMON_HIDDEN_DIRS,
	DANGEROUS_COMMANDS,
	PRESET_CI,
	PRESET_MINIMAL,
	// Complete presets
	PRESET_RECOMMENDED,
	PRESET_STRICT,
	SENSITIVE_ENV_VARS,
	createVeil,
	// Helper to combine configs
	mergeConfigs,
} from "veil";

// ============================================================================
// Option 1: Use a preset directly
// ============================================================================

console.log("=== Using PRESET_RECOMMENDED ===\n");

const basicVeil = createVeil(PRESET_RECOMMENDED);

// This already blocks node_modules, .git, .env files, AWS credentials, etc.
console.log("node_modules blocked:", !basicVeil.checkDirectory("node_modules").ok);
console.log(".env blocked:", !basicVeil.checkFile(".env").ok);
console.log("rm -rf blocked:", !basicVeil.checkCommand("rm -rf /").ok);

// ============================================================================
// Option 2: Extend a preset with custom rules
// ============================================================================

console.log("\n=== Extending PRESET_RECOMMENDED ===\n");

const customVeil = createVeil(
	mergeConfigs(PRESET_RECOMMENDED, {
		// Add project-specific rules
		fileRules: [
			{ match: "internal-docs", action: "deny", reason: "Internal documentation" },
			{ match: /\.draft\./i, action: "deny", reason: "Draft files" },
		],
		envRules: [{ match: "MY_CUSTOM_SECRET", action: "deny" }],
	}),
);

// Has all PRESET_RECOMMENDED rules PLUS custom ones
console.log("internal-docs blocked:", !customVeil.checkDirectory("internal-docs").ok);
console.log("file.draft.md blocked:", !customVeil.checkFile("file.draft.md").ok);

// ============================================================================
// Option 3: Build your own preset from individual rule sets
// ============================================================================

console.log("\n=== Building Custom Preset ===\n");

const myPreset = {
	// Use the standard hidden directories
	fileRules: [
		...COMMON_HIDDEN_DIRS,
		// But don't use SENSITIVE_FILES - we want .env files visible
	],
	// Use standard sensitive env vars
	envRules: SENSITIVE_ENV_VARS,
	// Use dangerous commands
	cliRules: DANGEROUS_COMMANDS,
};

const customPresetVeil = createVeil(myPreset);

// node_modules blocked (from COMMON_HIDDEN_DIRS)
console.log("node_modules blocked:", !customPresetVeil.checkDirectory("node_modules").ok);
// .env NOT blocked (we didn't include SENSITIVE_FILES)
console.log(".env blocked:", !customPresetVeil.checkFile(".env").ok);

// ============================================================================
// Preset Comparison
// ============================================================================

console.log("\n=== Preset Comparison ===\n");

const presets = {
	MINIMAL: createVeil(PRESET_MINIMAL),
	RECOMMENDED: createVeil(PRESET_RECOMMENDED),
	STRICT: createVeil(PRESET_STRICT),
	CI: createVeil(PRESET_CI),
};

// Test the same operations across all presets
const testCases = [
	{ type: "file", target: ".env" },
	{ type: "file", target: "node_modules" },
	{ type: "env", target: "AWS_SECRET_KEY" },
	{ type: "cli", target: "rm -rf /" },
];

console.log("Preset behavior comparison:\n");
console.log("Target".padEnd(20), "MINIMAL", "RECOMMENDED", "STRICT", "CI");
console.log("-".repeat(65));

for (const test of testCases) {
	const results: string[] = [];

	for (const [_name, veil] of Object.entries(presets)) {
		let blocked = false;

		if (test.type === "file") {
			blocked = !veil.checkFile(test.target).ok;
		} else if (test.type === "env") {
			// Set test env var
			process.env[test.target] = "test-value";
			const result = veil.getEnv(test.target);
			blocked = !result.ok || result.value !== "test-value";
		} else if (test.type === "cli") {
			blocked = !veil.checkCommand(test.target).ok;
		}

		results.push(blocked ? "❌" : "✅");
	}

	console.log(test.target.padEnd(20), results.join("       "));
}

console.log("\n❌ = blocked/masked, ✅ = allowed");
