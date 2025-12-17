/**
 * Rule Matching Utilities
 *
 * Helper functions for matching rules against targets.
 * These utilities are exported for advanced users who want to build custom engines.
 */

import type { BaseRule, RuleAction } from "./types";

/**
 * Check if a target string matches a rule pattern.
 *
 * For string patterns, this checks for exact match or substring inclusion.
 * For RegExp patterns, this tests the target against the regex.
 *
 * @param target - The string to check (file path, env var name, command, etc.)
 * @param pattern - String for exact/substring match, or RegExp for pattern matching
 * @returns true if the target matches the pattern
 */
export function matchesPattern(target: string, pattern: string | RegExp): boolean {
	if (typeof pattern === "string") {
		// Exact match or path contains
		return target === pattern || target.includes(pattern);
	}
	return pattern.test(target);
}

/**
 * Find the first matching rule for a target from an array of rules.
 *
 * Rules are evaluated in order - the first match wins.
 * This enables priority-based rule configurations.
 *
 * @param target - The string to match against rules
 * @param rules - Array of rules to evaluate
 * @returns The matching rule and its index, or null if no match
 */
export function findMatchingRule<T extends BaseRule>(
	target: string,
	rules: T[]
): { rule: T; index: number } | null {
	for (let i = 0; i < rules.length; i++) {
		const rule = rules[i];
		if (rule && matchesPattern(target, rule.match)) {
			return { rule, index: i };
		}
	}
	return null;
}

/**
 * Evaluate rules in order and return the action to take.
 *
 * Returns null if no rules match, which typically defaults to allow.
 * Includes a policy reference for audit logging.
 *
 * @param target - The string to match against rules
 * @param rules - Array of rules to evaluate
 * @returns The action, matching rule, and policy reference, or null if no match
 */
export function evaluateRules<T extends BaseRule>(
	target: string,
	rules: T[]
): { action: RuleAction; rule: T; policyRef: string } | null {
	const match = findMatchingRule(target, rules);
	if (!match) {
		return null;
	}
	const { rule, index } = match;
	const ruleType = getRuleTypeName(rule);
	return {
		action: rule.action,
		rule,
		policyRef: `${ruleType}[${index}]`,
	};
}

/**
 * Get a descriptive name for a rule type
 */
function getRuleTypeName(rule: BaseRule): string {
	// We use a simple heuristic based on properties
	if ("safeAlternatives" in rule) {
		return "cliRules";
	}
	// Default to fileRules as it's the most common
	return "rules";
}

/**
 * Apply a mask to a sensitive value.
 *
 * If a replacement is provided, uses that directly.
 * Otherwise, generates a mask showing first and last character with asterisks in between.
 *
 * @param value - The value to mask
 * @param replacement - Optional custom replacement string
 * @returns The masked value
 */
export function applyMask(value: string, replacement?: string): string {
	if (replacement !== undefined) {
		return replacement;
	}
	// Default mask: show first and last char, mask middle
	if (value.length <= 4) {
		return "****";
	}
	return `${value[0]}${"*".repeat(Math.min(value.length - 2, 8))}${value[value.length - 1]}`;
}

/**
 * Generate a policy reference string for audit logging.
 *
 * @param ruleType - The type of rule (e.g., fileRules, envRules, cliRules)
 * @param index - The index of the rule in its array
 * @returns A formatted policy reference like fileRules[0]
 */
export function generatePolicyRef(ruleType: string, index: number): string {
	return `${ruleType}[${index}]`;
}
