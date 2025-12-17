/**
 * Rule System Types
 */

import type { CliRule, EnvRule, FileRule } from "../types";

/**
 * Supported platforms
 */
export type Platform = "windows" | "darwin" | "linux" | "all";

/**
 * Rule categories
 */
export type RuleCategory =
	| "security"
	| "privacy"
	| "filesystem"
	| "credentials"
	| "destructive"
	| "network"
	| "system";

/**
 * Rule severity levels
 */
export type RuleSeverity = "error" | "warn" | "off";

/**
 * A named rule definition
 */
export interface VeilRule {
	/** Unique rule ID (e.g., "fs/no-delete-root") */
	id: string;
	/** Human-readable description */
	description: string;
	/** Rule category */
	category: RuleCategory;
	/** Applicable platforms */
	platforms: Platform[];
	/** Default severity */
	defaultSeverity: RuleSeverity;
	/** The actual rule(s) this maps to */
	fileRules?: FileRule[];
	envRules?: EnvRule[];
	cliRules?: CliRule[];
}

/**
 * Rule configuration - severity or off
 */
export type RuleConfig = RuleSeverity | [RuleSeverity, Record<string, unknown>];

/**
 * Rules configuration object
 */
export type RulesConfig = Record<string, RuleConfig>;

/**
 * A rule pack is a collection of rules
 */
export interface RulePack {
	/** Pack name */
	name: string;
	/** Description */
	description: string;
	/** Rules included in this pack */
	rules: string[];
}
