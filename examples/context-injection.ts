/**
 * Context Injection Example
 *
 * This example demonstrates how to inject synthetic/curated content
 * in place of real sensitive data, allowing LLMs to work with
 * representative data without accessing real secrets.
 */

import { createVeil } from "veil";

// ============================================================================
// Scenario: AI Coding Assistant
// ============================================================================

// We want the AI to help with our code, but we don't want it to see:
// - Real API keys
// - Production database credentials
// - Actual customer data

const veil = createVeil({
	// Standard protections
	fileRules: [
		{ match: "node_modules", action: "deny" },
		{ match: /\.env/, action: "deny" },
	],
	envRules: [{ match: /SECRET|PASSWORD|KEY|TOKEN/i, action: "deny" }],

	// Context injectors - provide synthetic data
	injectors: {
		// When the AI asks to read a file, we can provide curated content
		files: (path: string): string | null => {
			// Provide a sanitized version of .env
			if (path === ".env" || path === ".env.local") {
				return `# Environment Configuration
DATABASE_URL=postgresql://localhost:5432/myapp_dev
REDIS_URL=redis://localhost:6379
API_KEY=dev_api_key_placeholder
SECRET_KEY=dev_secret_placeholder
NODE_ENV=development
LOG_LEVEL=debug`;
			}

			// Provide example customer data instead of real data
			if (path.includes("customers") && path.endsWith(".json")) {
				return JSON.stringify(
					{
						customers: [
							{ id: 1, name: "Alice Example", email: "alice@example.com" },
							{ id: 2, name: "Bob Sample", email: "bob@example.com" },
						],
					},
					null,
					2,
				);
			}

			// Provide a sanitized config file
			if (path === "config/production.json") {
				return JSON.stringify(
					{
						database: { host: "db.example.com", port: 5432 },
						cache: { host: "cache.example.com", port: 6379 },
						api: { url: "https://api.example.com" },
					},
					null,
					2,
				);
			}

			// Return null for files we don't want to inject
			return null;
		},

		// Inject safe values for environment variables
		env: (key: string): string | null => {
			const safeValues: Record<string, string> = {
				DATABASE_URL: "postgresql://localhost:5432/dev",
				REDIS_URL: "redis://localhost:6379",
				API_KEY: "dev_placeholder_key",
				AWS_ACCESS_KEY_ID: "AKIAEXAMPLEKEYID",
				AWS_SECRET_ACCESS_KEY: "example-secret-key-placeholder",
			};

			return safeValues[key] ?? null;
		},

		// Provide curated directory listings
		directories: (path: string): string[] | null => {
			// Only show relevant files in the secrets directory
			if (path === "config" || path === "config/") {
				return [
					"database.ts",
					"cache.ts",
					"api.ts",
					// Omit: credentials.ts, secrets.json, etc.
				];
			}

			// For the app directory, show structure without internals
			if (path === "app" || path === "app/") {
				return [
					"routes/",
					"components/",
					"utils/",
					"types/",
					// Omit: __internal__/, .secrets/, etc.
				];
			}

			return null;
		},
	},
});

// ============================================================================
// Usage Examples
// ============================================================================

console.log("=== Context Injection Demo ===\n");

// The AI can "read" .env but gets safe synthetic content
console.log("Reading .env file:");
const envFile = veil.checkFile(".env");
if (envFile.ok && "value" in envFile) {
	console.log(envFile.value);
}

console.log(`\n${"=".repeat(50)}\n`);

// The AI can "read" customer data but gets example data
console.log("Reading customers.json:");
const customersFile = veil.checkFile("data/customers.json");
if (customersFile.ok && "value" in customersFile) {
	console.log(customersFile.value);
}

console.log(`\n${"=".repeat(50)}\n`);

// Environment variables return safe placeholders
console.log("Environment variables:");
const dbUrl = veil.getEnv("DATABASE_URL");
if (dbUrl.ok) {
	console.log("DATABASE_URL:", dbUrl.value);
}

const awsKey = veil.getEnv("AWS_ACCESS_KEY_ID");
if (awsKey.ok) {
	console.log("AWS_ACCESS_KEY_ID:", awsKey.value);
}

console.log(`\n${"=".repeat(50)}\n`);

// Files not in the injector still go through normal rules
console.log("Non-injected file access:");
const srcFile = veil.checkFile("src/index.ts");
console.log("src/index.ts:", srcFile.ok ? "Allowed (normal access)" : "Blocked");

const realSecrets = veil.checkFile("secrets/real-keys.json");
console.log("secrets/real-keys.json:", realSecrets.ok ? "Allowed" : "Blocked (no injection)");
