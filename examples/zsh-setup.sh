#!/bin/bash
# ShellSense Zsh Setup
# Run this script or add the eval line to your .zshrc

echo "Setting up ShellSense for Zsh..."

# Initialize config if needed
shellsense init 2>/dev/null

# Add hook to .zshrc if not already present
HOOK_LINE='eval "$(shellsense hook zsh)"'

if ! grep -q "shellsense hook zsh" ~/.zshrc 2>/dev/null; then
    echo "" >> ~/.zshrc
    echo "# ShellSense - terminal safety tool" >> ~/.zshrc
    echo "$HOOK_LINE" >> ~/.zshrc
    echo "Added ShellSense hook to ~/.zshrc"
    echo "Run 'source ~/.zshrc' or open a new terminal to activate."
else
    echo "ShellSense hook already in ~/.zshrc"
fi
