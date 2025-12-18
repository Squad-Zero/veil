/**
 * Shell wrapper utilities for Veil CLI
 *
 * Handles detection, wrapper generation, and profile management
 * for both POSIX shells (bash, zsh) and PowerShell.
 */

export const SHELL_MARKER_START = "# >>> veil shell wrapper >>>";
export const SHELL_MARKER_END = "# <<< veil shell wrapper <<<";
export const PS_SHELL_MARKER_START = "# >>> veil shell wrapper >>>";
export const PS_SHELL_MARKER_END = "# <<< veil shell wrapper <<<";

export type ShellType = "zsh" | "bash" | "powershell" | "unknown";

/**
 * Detect shell type from a config file path
 */
export function detectShellFromPath(path: string): ShellType {
    if (path.endsWith(".ps1")) {
        return "powershell";
    }
    if (path.includes(".bashrc") || path.includes(".bash_profile")) {
        return "bash";
    }
    if (path.includes(".zshrc")) {
        return "zsh";
    }
    return "unknown";
}

/**
 * Detect current shell from environment variables
 */
export function detectCurrentShell(
    env: Record<string, string | undefined> = process.env,
    platform: string = process.platform,
): ShellType {
    // Check for PowerShell first (works on Windows)
    if (env["PSModulePath"] || env["POWERSHELL_DISTRIBUTION_CHANNEL"]) {
        return "powershell";
    }

    const shell = env["SHELL"] ?? "";
    if (shell.includes("zsh")) return "zsh";
    if (shell.includes("bash")) return "bash";

    // On Windows without SHELL env var, assume PowerShell
    if (platform === "win32") {
        return "powershell";
    }

    return "unknown";
}

/**
 * Generate a bash/zsh shell wrapper
 */
export function getBashWrapper(commands: string[], forceMode: boolean): string {
    const wrapperFunctions = commands
        .map(
            (cmd) => `${cmd}() {
  if command -v veil-wrap >/dev/null 2>&1; then
    veil-wrap ${cmd} "$@"
  else
    command ${cmd} "$@"
  fi
}`,
        )
        .join("\n\n");

    const modeComment = forceMode
        ? "# Mode: FORCE - applies to ALL terminals (humans + AI)"
        : "# Mode: AI-only - only activates when VEIL_ENABLED=1 (set in VS Code)";

    return `${SHELL_MARKER_START}
# Veil intercepts these commands to enforce security policies
# See: https://github.com/Squad-Zero/veil
${modeComment}
${wrapperFunctions}
${SHELL_MARKER_END}`;
}

/**
 * Generate a PowerShell wrapper
 */
export function getPowerShellWrapper(commands: string[], forceMode: boolean): string {
    const wrapperFunctions = commands
        .map(
            (cmd) => `function ${cmd} {
  if (Get-Command veil-wrap -ErrorAction SilentlyContinue) {
    veil-wrap ${cmd} @args
  } else {
    & (Get-Command ${cmd} -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1) @args
  }
}`,
        )
        .join("\n\n");

    const modeComment = forceMode
        ? "# Mode: FORCE - applies to ALL terminals (humans + AI)"
        : "# Mode: AI-only - only activates when VEIL_ENABLED=1 (set in VS Code)";

    return `${PS_SHELL_MARKER_START}
# Veil intercepts these commands to enforce security policies
# See: https://github.com/Squad-Zero/veil
${modeComment}
${wrapperFunctions}
${PS_SHELL_MARKER_END}`;
}

/**
 * Generate shell wrapper based on shell type
 */
export function getShellWrapper(commands: string[], forceMode: boolean, shellType: ShellType): string {
    if (shellType === "powershell") {
        return getPowerShellWrapper(commands, forceMode);
    }
    return getBashWrapper(commands, forceMode);
}

/**
 * Get all possible shell config paths for the current platform
 */
export function getShellConfigPaths(
    env: Record<string, string | undefined> = process.env,
    platform: string = process.platform,
): string[] {
    const home = env["HOME"] ?? env["USERPROFILE"] ?? "";
    const paths = [
        `${home}/.zshrc`,
        `${home}/.bashrc`,
        `${home}/.bash_profile`,
    ];

    // Add PowerShell profile paths for Windows
    if (platform === "win32") {
        const userProfile = env["USERPROFILE"] ?? "";
        // PowerShell 7+ (cross-platform)
        paths.push(`${userProfile}/Documents/PowerShell/Microsoft.PowerShell_profile.ps1`);
        // Windows PowerShell 5.1
        paths.push(`${userProfile}/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1`);
    }

    return paths;
}

/**
 * Remove wrapper block from content
 */
export function removeWrapperFromContent(content: string): { modified: string; found: boolean } {
    // Check for marker
    if (!content.includes(SHELL_MARKER_START) && !content.includes(PS_SHELL_MARKER_START)) {
        return { modified: content, found: false };
    }

    // Use whichever marker is found
    const markerStart = content.includes(SHELL_MARKER_START) ? SHELL_MARKER_START : PS_SHELL_MARKER_START;
    const markerEnd = content.includes(SHELL_MARKER_END) ? SHELL_MARKER_END : PS_SHELL_MARKER_END;
    const startIdx = content.indexOf(markerStart);
    const endIdx = content.indexOf(markerEnd);

    if (startIdx === -1 || endIdx === -1) {
        return { modified: content, found: false };
    }

    const before = content.slice(0, startIdx).trimEnd();
    const after = content.slice(endIdx + markerEnd.length).trimStart();
    const modified = before + (after ? `\n\n${after}` : "\n");

    return { modified, found: true };
}

/**
 * Check if content already has a wrapper installed
 */
export function hasWrapperInstalled(content: string): boolean {
    return content.includes(SHELL_MARKER_START) || content.includes(PS_SHELL_MARKER_START);
}

/**
 * Add wrapper to content
 */
export function addWrapperToContent(content: string, wrapper: string): string {
    return `${content.trimEnd()}\n\n${wrapper}\n`;
}
