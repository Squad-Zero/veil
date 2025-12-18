#!/usr/bin/env node
/**
 * Veil MCP Server
 *
 * A Model Context Protocol server that intercepts CLI commands and environment
 * variable access, applying Veil rules before execution.
 *
 * Tools provided:
 * - run_command: Execute a shell command (with Veil filtering)
 * - get_env: Get an environment variable (with Veil filtering)
 * - check_command: Check if a command is allowed without executing
 * - check_env: Check if an env var is accessible without retrieving
 */

import { exec } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
	CallToolRequestSchema,
	type CallToolResult,
	ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { VeilConfig } from "../types.js";
import { createVeil } from "../veil.js";

const execAsync = promisify(exec);

/**
 * Load veil config from the current working directory or specified path
 */
async function loadVeilConfig(): Promise<VeilConfig | undefined> {
	const configPaths = [
		"veil.config.ts",
		"veil.config.js",
		"veil.config.mjs",
		".veilrc.ts",
		".veilrc.js",
	];

	const cwd = process.cwd();
	// biome-ignore lint/complexity/useLiteralKeys: TypeScript requires bracket notation for index signatures
	const configPath = process.env["VEIL_CONFIG"];

	if (configPath) {
		const fullPath = resolve(cwd, configPath);
		if (existsSync(fullPath)) {
			try {
				const loaded = (await import(pathToFileURL(fullPath).href)) as {
					default?: VeilConfig;
				} & VeilConfig;
				return loaded.default ?? loaded;
			} catch {
				console.error(`[veil-mcp] Failed to load config from ${fullPath}`);
			}
		}
	}

	for (const configFile of configPaths) {
		const fullPath = join(cwd, configFile);
		if (existsSync(fullPath)) {
			try {
				const loaded = (await import(pathToFileURL(fullPath).href)) as {
					default?: VeilConfig;
				} & VeilConfig;
				return loaded.default ?? loaded;
			} catch {
				// Try next config file
			}
		}
	}

	return undefined;
}

/**
 * Format a Veil result for MCP response
 */
function formatBlockedResponse(reason?: string, alternatives?: string[]): CallToolResult {
	let message = "Command blocked by Veil security policy.";
	if (reason) {
		message += `\n\nReason: ${reason}`;
	}
	if (alternatives && alternatives.length > 0) {
		message += `\n\nSafe alternatives:\n${alternatives.map((a) => `  - ${a}`).join("\n")}`;
	}
	return {
		content: [{ type: "text", text: message }],
		isError: true,
	};
}

/**
 * Create and start the Veil MCP server
 */
async function main(): Promise<void> {
	const config = await loadVeilConfig();
	const veil = createVeil(config ?? {});

	// eslint-disable-next-line @typescript-eslint/no-deprecated -- Server is the correct low-level API for custom tool handlers
	const server = new Server(
		{ name: "veil-mcp", version: "0.1.0" },
		{ capabilities: { tools: { listChanged: false } } },
	);

	// List available tools
	server.setRequestHandler(ListToolsRequestSchema, () => {
		return {
			tools: [
				{
					name: "run_command",
					description:
						"Execute a shell command. Commands are validated against Veil security rules before execution. Dangerous commands may be blocked or rewritten.",
					inputSchema: {
						type: "object",
						properties: {
							command: {
								type: "string",
								description: "The shell command to execute",
							},
							cwd: {
								type: "string",
								description: "Working directory for command execution (optional)",
							},
							timeout: {
								type: "number",
								description: "Timeout in milliseconds (default: 30000)",
							},
						},
						required: ["command"],
					},
				},
				{
					name: "get_env",
					description:
						"Get the value of an environment variable. Access is validated against Veil security rules. Sensitive variables may be masked, blocked, or transformed.",
					inputSchema: {
						type: "object",
						properties: {
							name: {
								type: "string",
								description: "The name of the environment variable",
							},
						},
						required: ["name"],
					},
				},
				{
					name: "check_command",
					description:
						"Check if a command would be allowed by Veil security rules without executing it. Returns the validation result including any rewrites or blocks.",
					inputSchema: {
						type: "object",
						properties: {
							command: {
								type: "string",
								description: "The shell command to check",
							},
						},
						required: ["command"],
					},
				},
				{
					name: "check_env",
					description:
						"Check if an environment variable would be accessible by Veil security rules without retrieving it. Returns the validation result.",
					inputSchema: {
						type: "object",
						properties: {
							name: {
								type: "string",
								description: "The name of the environment variable to check",
							},
						},
						required: ["name"],
					},
				},
			],
		};
	});

	// Handle tool calls
	server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
		const { name, arguments: args } = request.params;

		switch (name) {
			case "run_command": {
				const {
					command,
					cwd,
					timeout = 30000,
				} = args as {
					command: string;
					cwd?: string;
					timeout?: number;
				};

				// Check command against Veil rules
				const result = veil.checkCommand(command);

				if (!result.ok) {
					return formatBlockedResponse(result.reason, result.safeAlternatives);
				}

				// Use potentially rewritten command
				const finalCommand = result.command ?? command;

				try {
					const { stdout, stderr } = await execAsync(finalCommand, {
						cwd: cwd ?? process.cwd(),
						timeout,
						maxBuffer: 10 * 1024 * 1024, // 10MB
					});

					let output = "";
					if (result.context) {
						output += `[Veil] ${result.context}\n\n`;
					}
					if (result.command !== command) {
						output += `[Veil] Command rewritten: ${command} → ${result.command}\n\n`;
					}
					output += stdout;
					if (stderr) {
						output += `\n\nStderr:\n${stderr}`;
					}

					return {
						content: [{ type: "text", text: output || "(no output)" }],
					};
				} catch (error) {
					const err = error as Error & { stdout?: string; stderr?: string; code?: number };
					return {
						content: [
							{
								type: "text",
								text: `Command failed (exit code ${err.code ?? "unknown"}):\n${err.stderr ?? err.message}\n\nStdout:\n${err.stdout ?? "(none)"}`,
							},
						],
						isError: true,
					};
				}
			}

			case "get_env": {
				const { name: envName } = args as { name: string };

				const result = veil.getEnv(envName);

				if (!result.ok) {
					return {
						content: [
							{
								type: "text",
								text: `Environment variable "${envName}" is not accessible.\n\nReason: ${result.reason || "Blocked by Veil security policy"}`,
							},
						],
						isError: true,
					};
				}

				let output = "";
				if (result.context) {
					output += `[Veil] ${result.context}\n\n`;
				}
				output += result.value ?? "(not set)";

				return {
					content: [{ type: "text", text: output }],
				};
			}

			case "check_command": {
				const { command } = args as { command: string };

				const result = veil.checkCommand(command);

				if (!result.ok) {
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify(
									{
										allowed: false,
										reason: result.reason,
										safeAlternatives: result.safeAlternatives,
									},
									null,
									2,
								),
							},
						],
					};
				}

				return {
					content: [
						{
							type: "text",
							text: JSON.stringify(
								{
									allowed: true,
									command: result.command,
									rewritten: result.command !== command,
									context: result.context,
								},
								null,
								2,
							),
						},
					],
				};
			}

			case "check_env": {
				const { name: envName } = args as { name: string };

				const result = veil.getEnv(envName);

				if (!result.ok) {
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify(
									{
										accessible: false,
										reason: result.reason,
									},
									null,
									2,
								),
							},
						],
					};
				}

				return {
					content: [
						{
							type: "text",
							text: JSON.stringify(
								{
									accessible: true,
									masked: result.value !== process.env[envName],
									context: result.context,
								},
								null,
								2,
							),
						},
					],
				};
			}

			default:
				return {
					content: [{ type: "text", text: `Unknown tool: ${name}` }],
					isError: true,
				};
		}
	});

	// Connect via stdio
	const transport = new StdioServerTransport();
	await server.connect(transport);

	// Log to stderr (stdout is reserved for MCP protocol)
	console.error("[veil-mcp] Server started");
	if (config) {
		console.error("[veil-mcp] Loaded config from workspace");
	} else {
		console.error("[veil-mcp] No config found, using permissive defaults");
	}
}

export { main as startMcpServer };

// Auto-run when executed directly (not imported via CLI)
// Check if this file is being run directly as a standalone script
const scriptPath = process.argv[1] ?? "";
const isDirectExecution =
	scriptPath.endsWith("mcp/index.cjs") ||
	scriptPath.endsWith("mcp/index.js") ||
	scriptPath.includes("veil-mcp");

if (isDirectExecution) {
	main().catch((error: unknown) => {
		console.error("[veil-mcp] Fatal error:", error);
		process.exit(1);
	});
}
