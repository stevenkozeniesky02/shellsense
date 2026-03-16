"""Shell hook script generators for ShellSense."""

from __future__ import annotations

import json


class HookGenerator:
    """Generates shell hook scripts for various shells and tools."""

    def generate_shell_hook(self, shell: str) -> str:
        """Generate a preexec hook script for the given shell."""
        if shell == "zsh":
            return self._generate_zsh_hook()
        elif shell == "bash":
            return self._generate_bash_hook()
        else:
            raise ValueError(f"Unsupported shell: {shell}")

    def _generate_zsh_hook(self) -> str:
        return r"""# ShellSense Zsh Hook
# Add to your .zshrc: eval "$(shellsense hook zsh)"

shellsense_preexec() {
    local cmd="$1"

    # Skip shellsense's own commands
    [[ "$cmd" == shellsense* ]] && return

    # Run analysis (suppress errors)
    local result
    result=$(shellsense check "$cmd" --json 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]] && [[ -n "$result" ]]; then
        local risk_level
        risk_level=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('risk_level',''))" 2>/dev/null)

        if [[ "$risk_level" == "danger" ]]; then
            echo ""
            shellsense check "$cmd" 2>/dev/null
            echo ""
            echo -n "Proceed anyway? [y/N] "
            read -r response
            if [[ "$response" != [yY] ]]; then
                # Cancel the command by returning non-zero
                return 1
            fi
        elif [[ "$risk_level" == "caution" ]]; then
            shellsense check "$cmd" 2>/dev/null
        fi
    fi
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec shellsense_preexec
echo "ShellSense: Zsh hook installed. Commands will be analyzed before execution."
"""

    def _generate_bash_hook(self) -> str:
        return r"""# ShellSense Bash Hook
# Add to your .bashrc: eval "$(shellsense hook bash)"

shellsense_preexec() {
    local cmd="$1"

    # Skip shellsense's own commands
    [[ "$cmd" == shellsense* ]] && return

    # Run analysis
    local result
    result=$(shellsense check "$cmd" --json 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]] && [[ -n "$result" ]]; then
        local risk_level
        risk_level=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('risk_level',''))" 2>/dev/null)

        if [[ "$risk_level" == "danger" ]]; then
            echo ""
            shellsense check "$cmd" 2>/dev/null
            echo ""
            read -r -p "Proceed anyway? [y/N] " response
            if [[ "$response" != [yY] ]]; then
                return 1
            fi
        elif [[ "$risk_level" == "caution" ]]; then
            shellsense check "$cmd" 2>/dev/null
        fi
    fi
}

# Install the preexec hook using bash-preexec if available
if [[ -n "$PROMPT_COMMAND" ]]; then
    __shellsense_orig_prompt="$PROMPT_COMMAND"
fi

# Use DEBUG trap for preexec-like behavior
shellsense_debug_trap() {
    local cmd="$BASH_COMMAND"
    # Only check top-level commands (not subshells)
    if [[ "$BASH_SUBSHELL" -eq 0 ]]; then
        shellsense_preexec "$cmd"
    fi
}

trap 'shellsense_debug_trap' DEBUG
echo "ShellSense: Bash hook installed. Commands will be analyzed before execution."
"""

    def generate_claude_code_hook(self) -> str:
        """Generate a Claude Code hooks.json snippet for PreToolUse on Bash commands."""
        hook_config = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'shellsense check "$TOOL_INPUT_COMMAND" --json',
                                "description": "ShellSense: Analyze command safety before execution",
                                "blocking": True,
                            }
                        ],
                    }
                ]
            }
        }
        return json.dumps(hook_config, indent=2)
