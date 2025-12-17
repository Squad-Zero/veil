/**
 * Basic Veil Usage Example
 *
 * This example demonstrates the core functionality of Veil:
 * - File visibility control
 * - Environment variable protection
 * - CLI command interception
 */

import { createVeil } from "veil";

// Create a Veil instance with basic rules
const veil = createVeil({
	// File visibility rules
	fileRules: [
		{ match: "node_modules", action: "deny", reason: "Too large for context" },
		{ match: ".git", action: "deny", reason: "Version control internals" },
		{ match: /\.env/, action: "deny", reason: "Environment files contain secrets" },
		{ match: /secrets?/i, action: "deny", reason: "Secrets directory" },
	],

	// Environment variable rules
	envRules: [
		{ match: /^AWS_/, action: "mask" },
		{ match: /PASSWORD|SECRET|TOKEN|KEY/i, action: "mask" },
		{ match: "DATABASE_URL", action: "deny" },
	],

	// CLI command rules
	cliRules: [
		{
			match: /^rm\s+-rf/,
			action: "deny",
			reason: "Dangerous recursive delete",
			safeAlternatives: ["rm -i", "trash"],
		},
		{ match: /^sudo\s/, action: "deny", reason: "Elevated privileges not allowed" },
	],
});

// ============================================================================
// File Access Examples
// ============================================================================

console.log("=== File Access Control ===\n");

// Check allowed file
const srcResult = veil.checkFile("src/index.ts");
console.log("src/index.ts:", srcResult.ok ? "✅ Allowed" : "❌ Blocked");

// Check blocked file
const envResult = veil.checkFile(".env.local");
if (!envResult.ok) {
	console.log(".env.local:", "❌ Blocked -", envResult.reason);
}

// Check blocked directory
const nodeModulesResult = veil.checkDirectory("node_modules");
if (!nodeModulesResult.ok) {
	console.log("node_modules/:", "❌ Blocked -", nodeModulesResult.reason);
}

// Filter paths
const allPaths = [
	"src/app.ts",
	"src/utils/helper.ts",
	"node_modules/lodash/index.js",
	".env",
	"secrets/api-keys.json",
	"README.md",
];
const visiblePaths = veil.filterPaths(allPaths);
console.log("\nFiltered paths:", visiblePaths);
// Output: ['src/app.ts', 'src/utils/helper.ts', 'README.md']

// ============================================================================
// Environment Variable Examples
// ============================================================================

console.log("\n=== Environment Variable Protection ===\n");

// Set up some example env vars for demonstration
process.env.AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";
process.env.DATABASE_URL = "postgresql://admin:secret@localhost/db";
process.env.NODE_ENV = "development";

// Masked variable
const awsResult = veil.getEnv("AWS_SECRET_KEY");
if (awsResult.ok) {
	console.log("AWS_SECRET_KEY:", awsResult.value); // "A********E" (masked)
}

// Denied variable
const dbResult = veil.getEnv("DATABASE_URL");
console.log("DATABASE_URL:", dbResult.ok ? dbResult.value : "❌ Denied");

// Allowed variable (no matching rule = allow by default)
const nodeEnvResult = veil.getEnv("NODE_ENV");
console.log("NODE_ENV:", nodeEnvResult.ok ? nodeEnvResult.value : "❌ Denied");

// Get all visible env vars
const visibleEnv = veil.getVisibleEnv();
console.log("\nVisible environment variables:", Object.keys(visibleEnv).length, "vars");

// ============================================================================
// CLI Command Examples
// ============================================================================

console.log("\n=== CLI Command Interception ===\n");

// Safe command
const lsResult = veil.checkCommand("ls -la");
console.log("ls -la:", lsResult.ok ? "✅ Allowed" : "❌ Blocked");

// Dangerous command
const rmResult = veil.checkCommand("rm -rf /");
if (!rmResult.ok) {
	console.log("rm -rf /:", "❌ Blocked");
	if (rmResult.safeAlternatives) {
		console.log("  Safe alternatives:", rmResult.safeAlternatives.join(", "));
	}
}

// Sudo command
const sudoResult = veil.checkCommand("sudo apt install something");
console.log("sudo apt install:", sudoResult.ok ? "✅ Allowed" : "❌ Blocked");

// ============================================================================
// Audit Trail
// ============================================================================

console.log("\n=== Audit Trail ===\n");

const intercepted = veil.getInterceptedCalls();
console.log("Intercepted operations:", intercepted.length);
for (const record of intercepted) {
	console.log(`  - [${record.type}] ${record.target} → ${record.action}`);
}
