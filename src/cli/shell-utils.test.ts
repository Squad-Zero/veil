import { describe, expect, it } from "vitest";
import {
    SHELL_MARKER_START,
    SHELL_MARKER_END,
    PS_SHELL_MARKER_START,
    PS_SHELL_MARKER_END,
    detectShellFromPath,
    detectCurrentShell,
    getBashWrapper,
    getPowerShellWrapper,
    getShellWrapper,
    getShellConfigPaths,
    removeWrapperFromContent,
    hasWrapperInstalled,
    addWrapperToContent,
} from "./shell-utils";

describe("shell-utils", () => {
    describe("detectShellFromPath", () => {
        it("detects PowerShell from .ps1 extension", () => {
            expect(detectShellFromPath("C:\\Users\\test\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1")).toBe("powershell");
            expect(detectShellFromPath("/home/user/test.ps1")).toBe("powershell");
        });

        it("detects bash from .bashrc", () => {
            expect(detectShellFromPath("/home/user/.bashrc")).toBe("bash");
            expect(detectShellFromPath("C:\\Users\\test\\.bashrc")).toBe("bash");
        });

        it("detects bash from .bash_profile", () => {
            expect(detectShellFromPath("/home/user/.bash_profile")).toBe("bash");
        });

        it("detects zsh from .zshrc", () => {
            expect(detectShellFromPath("/home/user/.zshrc")).toBe("zsh");
        });

        it("returns unknown for unrecognized paths", () => {
            expect(detectShellFromPath("/home/user/.config/fish/config.fish")).toBe("unknown");
            expect(detectShellFromPath("/some/random/path")).toBe("unknown");
        });
    });

    describe("detectCurrentShell", () => {
        it("detects PowerShell from PSModulePath env var", () => {
            expect(detectCurrentShell({ PSModulePath: "C:\\Program Files\\PowerShell\\Modules" }, "win32")).toBe("powershell");
        });

        it("detects PowerShell from POWERSHELL_DISTRIBUTION_CHANNEL env var", () => {
            expect(detectCurrentShell({ POWERSHELL_DISTRIBUTION_CHANNEL: "PSCore" }, "darwin")).toBe("powershell");
        });

        it("detects zsh from SHELL env var", () => {
            expect(detectCurrentShell({ SHELL: "/bin/zsh" }, "darwin")).toBe("zsh");
            expect(detectCurrentShell({ SHELL: "/usr/local/bin/zsh" }, "linux")).toBe("zsh");
        });

        it("detects bash from SHELL env var", () => {
            expect(detectCurrentShell({ SHELL: "/bin/bash" }, "linux")).toBe("bash");
            expect(detectCurrentShell({ SHELL: "/usr/bin/bash" }, "darwin")).toBe("bash");
        });

        it("defaults to PowerShell on Windows without SHELL env var", () => {
            expect(detectCurrentShell({}, "win32")).toBe("powershell");
        });

        it("returns unknown on non-Windows without SHELL env var", () => {
            expect(detectCurrentShell({}, "linux")).toBe("unknown");
            expect(detectCurrentShell({}, "darwin")).toBe("unknown");
        });

        it("prioritizes PowerShell env vars over SHELL", () => {
            expect(detectCurrentShell({ SHELL: "/bin/bash", PSModulePath: "/usr/local/share/powershell" }, "linux")).toBe("powershell");
        });
    });

    describe("getBashWrapper", () => {
        it("generates bash function syntax", () => {
            const wrapper = getBashWrapper(["wrangler"], false);
            expect(wrapper).toContain("wrangler()");
            expect(wrapper).toContain("command -v veil-wrap");
            expect(wrapper).toContain('veil-wrap wrangler "$@"');
            expect(wrapper).toContain("command wrangler");
        });

        it("includes AI-only mode comment when forceMode is false", () => {
            const wrapper = getBashWrapper(["wrangler"], false);
            expect(wrapper).toContain("AI-only");
            expect(wrapper).toContain("VEIL_ENABLED=1");
        });

        it("includes FORCE mode comment when forceMode is true", () => {
            const wrapper = getBashWrapper(["wrangler"], true);
            expect(wrapper).toContain("FORCE");
            expect(wrapper).toContain("ALL terminals");
        });

        it("wraps multiple commands", () => {
            const wrapper = getBashWrapper(["wrangler", "npm", "yarn"], false);
            expect(wrapper).toContain("wrangler()");
            expect(wrapper).toContain("npm()");
            expect(wrapper).toContain("yarn()");
        });

        it("includes marker comments", () => {
            const wrapper = getBashWrapper(["wrangler"], false);
            expect(wrapper).toContain(SHELL_MARKER_START);
            expect(wrapper).toContain(SHELL_MARKER_END);
        });
    });

    describe("getPowerShellWrapper", () => {
        it("generates PowerShell function syntax", () => {
            const wrapper = getPowerShellWrapper(["wrangler"], false);
            expect(wrapper).toContain("function wrangler");
            expect(wrapper).toContain("Get-Command veil-wrap");
            expect(wrapper).toContain("veil-wrap wrangler @args");
            expect(wrapper).toContain("-CommandType Application");
        });

        it("includes AI-only mode comment when forceMode is false", () => {
            const wrapper = getPowerShellWrapper(["wrangler"], false);
            expect(wrapper).toContain("AI-only");
        });

        it("includes FORCE mode comment when forceMode is true", () => {
            const wrapper = getPowerShellWrapper(["wrangler"], true);
            expect(wrapper).toContain("FORCE");
        });

        it("wraps multiple commands", () => {
            const wrapper = getPowerShellWrapper(["wrangler", "npm", "yarn"], false);
            expect(wrapper).toContain("function wrangler");
            expect(wrapper).toContain("function npm");
            expect(wrapper).toContain("function yarn");
        });

        it("includes marker comments", () => {
            const wrapper = getPowerShellWrapper(["wrangler"], false);
            expect(wrapper).toContain(PS_SHELL_MARKER_START);
            expect(wrapper).toContain(PS_SHELL_MARKER_END);
        });
    });

    describe("getShellWrapper", () => {
        it("returns PowerShell wrapper for powershell type", () => {
            const wrapper = getShellWrapper(["cmd"], false, "powershell");
            expect(wrapper).toContain("function cmd");
            expect(wrapper).toContain("Get-Command");
        });

        it("returns bash wrapper for bash type", () => {
            const wrapper = getShellWrapper(["cmd"], false, "bash");
            expect(wrapper).toContain("cmd()");
            expect(wrapper).toContain("command -v");
        });

        it("returns bash wrapper for zsh type", () => {
            const wrapper = getShellWrapper(["cmd"], false, "zsh");
            expect(wrapper).toContain("cmd()");
        });

        it("returns bash wrapper for unknown type", () => {
            const wrapper = getShellWrapper(["cmd"], false, "unknown");
            expect(wrapper).toContain("cmd()");
        });
    });

    describe("getShellConfigPaths", () => {
        it("includes bash and zsh paths", () => {
            const paths = getShellConfigPaths({ HOME: "/home/user" }, "linux");
            expect(paths).toContain("/home/user/.zshrc");
            expect(paths).toContain("/home/user/.bashrc");
            expect(paths).toContain("/home/user/.bash_profile");
        });

        it("includes PowerShell paths on Windows", () => {
            const paths = getShellConfigPaths({ USERPROFILE: "C:\\Users\\test" }, "win32");
            expect(paths).toContain("C:\\Users\\test/Documents/PowerShell/Microsoft.PowerShell_profile.ps1");
            expect(paths).toContain("C:\\Users\\test/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1");
        });

        it("does not include PowerShell paths on non-Windows", () => {
            const paths = getShellConfigPaths({ HOME: "/home/user" }, "linux");
            expect(paths.some(p => p.includes(".ps1"))).toBe(false);
        });

        it("uses USERPROFILE on Windows when HOME is not set", () => {
            const paths = getShellConfigPaths({ USERPROFILE: "C:\\Users\\test" }, "win32");
            expect(paths[0]).toContain("C:\\Users\\test");
        });
    });

    describe("hasWrapperInstalled", () => {
        it("returns true when bash wrapper is installed", () => {
            const content = `# Some config\n${SHELL_MARKER_START}\nwrapper content\n${SHELL_MARKER_END}`;
            expect(hasWrapperInstalled(content)).toBe(true);
        });

        it("returns true when PowerShell wrapper is installed", () => {
            const content = `# Some config\n${PS_SHELL_MARKER_START}\nwrapper content\n${PS_SHELL_MARKER_END}`;
            expect(hasWrapperInstalled(content)).toBe(true);
        });

        it("returns false when no wrapper is installed", () => {
            const content = "# Just some regular config\nexport PATH=/usr/bin";
            expect(hasWrapperInstalled(content)).toBe(false);
        });
    });

    describe("removeWrapperFromContent", () => {
        it("removes bash wrapper from content", () => {
            const content = `# Before\n\n${SHELL_MARKER_START}\nwrapper content\n${SHELL_MARKER_END}\n\n# After`;
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(true);
            expect(result.modified).not.toContain(SHELL_MARKER_START);
            expect(result.modified).not.toContain("wrapper content");
            expect(result.modified).toContain("# Before");
            expect(result.modified).toContain("# After");
        });

        it("removes PowerShell wrapper from content", () => {
            const content = `# Before\n\n${PS_SHELL_MARKER_START}\nfunction test {}\n${PS_SHELL_MARKER_END}\n\n# After`;
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(true);
            expect(result.modified).not.toContain("function test");
        });

        it("returns original content when no wrapper found", () => {
            const content = "# Just some config";
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(false);
            expect(result.modified).toBe(content);
        });

        it("handles content with only start marker gracefully", () => {
            const content = `# Before\n${SHELL_MARKER_START}\nincomplete`;
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(false);
        });

        it("handles wrapper at end of file", () => {
            const content = `# Before\n\n${SHELL_MARKER_START}\nwrapper\n${SHELL_MARKER_END}`;
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(true);
            expect(result.modified.trim()).toBe("# Before");
        });

        it("handles wrapper at start of file", () => {
            const content = `${SHELL_MARKER_START}\nwrapper\n${SHELL_MARKER_END}\n\n# After`;
            const result = removeWrapperFromContent(content);
            expect(result.found).toBe(true);
            expect(result.modified.trim()).toBe("# After");
        });
    });

    describe("addWrapperToContent", () => {
        it("appends wrapper to content", () => {
            const content = "# Existing config";
            const wrapper = "# New wrapper";
            const result = addWrapperToContent(content, wrapper);
            expect(result).toContain("# Existing config");
            expect(result).toContain("# New wrapper");
            expect(result.indexOf("# Existing config")).toBeLessThan(result.indexOf("# New wrapper"));
        });

        it("adds blank line between content and wrapper", () => {
            const content = "# Existing config";
            const wrapper = "# New wrapper";
            const result = addWrapperToContent(content, wrapper);
            expect(result).toContain("\n\n# New wrapper");
        });

        it("trims trailing whitespace from content", () => {
            const content = "# Existing config   \n\n\n";
            const wrapper = "# New wrapper";
            const result = addWrapperToContent(content, wrapper);
            expect(result).toBe("# Existing config\n\n# New wrapper\n");
        });

        it("handles empty content", () => {
            const content = "";
            const wrapper = "# Wrapper";
            const result = addWrapperToContent(content, wrapper);
            expect(result).toBe("\n\n# Wrapper\n");
        });
    });

    describe("markers are consistent", () => {
        it("bash and PowerShell use the same marker format", () => {
            // They're the same markers, just different constant names for clarity
            expect(SHELL_MARKER_START).toBe(PS_SHELL_MARKER_START);
            expect(SHELL_MARKER_END).toBe(PS_SHELL_MARKER_END);
        });
    });
});
