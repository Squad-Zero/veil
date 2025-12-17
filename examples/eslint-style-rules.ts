/**
 * Example: ESLint-Style Rules Configuration
 *
 * Demonstrates how to use Veil's rule-based system similar to ESLint
 */

import {
	type RulesConfig,
	buildConfigFromRules,
	createVeil,
	extendRules,
	fromPacks,
	listPacks,
	listRules,
	recommended,
	// Rule system
	registerPlatformRules,
} from "../src";

// ============================================================================
// First, register the built-in rules
// ============================================================================
registerPlatformRules();

console.log("=== Veil ESLint-Style Rules Demo ===\n");

// ============================================================================
// List all available rules and packs
// ============================================================================
console.log("📋 Available Rule Packs:");
for (const pack of listPacks()) {
	console.log(`   - ${pack}`);
}
console.log();

console.log(`📋 Total Rules Available: ${listRules().length}`);
console.log();

// ============================================================================
// Method 1: Use a preset (recommended, strict)
// ============================================================================
console.log("🔧 Method 1: Using recommended() preset");
const recommendedRules = recommended();
console.log(`   Enabled ${Object.keys(recommendedRules).length} rules`);

const veilRecommended = createVeil(buildConfigFromRules(recommendedRules));
console.log(
	`   Checking 'rm -rf /': ${veilRecommended.checkCommand("rm -rf /").ok ? "allowed" : "blocked"}`,
);
console.log();

// ============================================================================
// Method 2: Use rule packs (like ESLint's "extends")
// ============================================================================
console.log("🔧 Method 2: Using fromPacks() - like ESLint extends");
const packRules = fromPacks("security:recommended", "platform:linux");
console.log(`   Combined ${Object.keys(packRules).length} rules from 2 packs`);

const veilPacks = createVeil(buildConfigFromRules(packRules, "linux"));
console.log(
	`   Checking AWS_SECRET_KEY: ${veilPacks.getEnv("AWS_SECRET_KEY").ok ? "visible" : "masked/blocked"}`,
);
console.log();

// ============================================================================
// Method 3: Explicit rule configuration (like ESLint's rules object)
// ============================================================================
console.log("🔧 Method 3: Explicit rule configuration");
const explicitRules: RulesConfig = {
	// Security rules
	"env/mask-aws": "error",
	"env/deny-passwords": "error",
	"fs/hide-env-files": "error",

	// Linux-specific
	"linux/no-delete-root": "error",
	"linux/no-delete-boot": "error",
	"linux/hide-shadow": "warn",

	// Disable some rules
	"fs/hide-node-modules": "off",
};
console.log(`   Configured ${Object.keys(explicitRules).length} rules explicitly`);

const veilExplicit = createVeil(buildConfigFromRules(explicitRules, "linux"));
console.log(
	`   Checking /etc/shadow: ${veilExplicit.checkFile("/etc/shadow").ok ? "visible" : "hidden"}`,
);
console.log();

// ============================================================================
// Method 4: Extend a preset with overrides
// ============================================================================
console.log("🔧 Method 4: Extending presets with overrides");
const customRules = extendRules(recommended(), {
	// Turn off some rules
	"fs/hide-build-output": "off",

	// Add stricter rules
	"env/deny-database-urls": "error",
	"cli/no-curl-pipe-bash": "error",
});
console.log("   Extended recommended with custom overrides");
console.log(`   Total rules: ${Object.keys(customRules).length}`);
console.log();

// ============================================================================
// Method 5: Context-specific packs
// ============================================================================
console.log("🔧 Method 5: Context-specific packs");

const devRules = fromPacks("context:dev", "platform:linux");
console.log(`   Development: ${Object.keys(devRules).length} rules`);

const ciRules = fromPacks("context:ci", "platform:linux");
console.log(`   CI/CD: ${Object.keys(ciRules).length} rules`);

const prodRules = fromPacks("context:production", "platform:linux");
console.log(`   Production: ${Object.keys(prodRules).length} rules`);
console.log();

// ============================================================================
// Show some specific rule IDs (like ESLint docs)
// ============================================================================
console.log("📖 Example Rule IDs (ESLint-style naming):");
const exampleRules = [
	"linux/no-delete-root",
	"linux/no-delete-above-cwd",
	"darwin/hide-keychain",
	"win/no-delete-system32",
	"env/mask-aws",
	"env/deny-passwords",
	"fs/hide-env-files",
	"cli/no-curl-pipe-bash",
];
for (const rule of exampleRules) {
	console.log(`   ${rule}`);
}
console.log();

console.log("✅ Rules system demo complete!");
