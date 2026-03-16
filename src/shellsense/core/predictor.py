"""Filesystem state predictor for ShellSense."""

from __future__ import annotations

import glob as globmod
import os
from typing import Optional

from shellsense.core.models import (
    AnalysisResult,
    CommandInfo,
    FileChange,
    FileChangeType,
    Suggestion,
)
from shellsense.core.risk import RiskScorer


class FilesystemPredictor:
    """Predicts filesystem changes from shell commands."""

    def __init__(self, working_dir: Optional[str] = None):
        self._cwd = working_dir or os.getcwd()
        self._risk_scorer = RiskScorer()

    def analyze(self, cmd: CommandInfo) -> AnalysisResult:
        """Analyze a command and predict its filesystem impact."""
        risk_score, risk_level, pattern_matches = self._risk_scorer.score(cmd)

        warnings = tuple(m.warning for m in pattern_matches)
        suggestions = tuple(m.suggestion for m in pattern_matches if m.suggestion)
        matched_pattern_names = tuple(m.pattern_name for m in pattern_matches)

        handler = self._get_handler(cmd.executable)
        if handler:
            changes, reversible, rev_note, dry_run, dry_cmd, extra_warnings, extra_suggestions = (
                handler(cmd)
            )
        else:
            changes = ()
            reversible = True
            rev_note = "Unknown command - reversibility cannot be determined"
            dry_run = False
            dry_cmd = None
            extra_warnings = ()
            extra_suggestions = ()

        return AnalysisResult(
            command=cmd,
            risk_level=risk_level,
            risk_score=risk_score,
            predicted_changes=changes,
            reversible=reversible,
            reversibility_note=rev_note,
            warnings=warnings + extra_warnings,
            suggestions=suggestions + extra_suggestions,
            dry_run_available=dry_run,
            dry_run_command=dry_cmd,
            matched_patterns=matched_pattern_names,
        )

    def _get_handler(self, executable: str):
        """Get the prediction handler for a given executable."""
        handlers = {
            "rm": self._predict_rm,
            "mv": self._predict_mv,
            "cp": self._predict_cp,
            "mkdir": self._predict_mkdir,
            "touch": self._predict_touch,
            "chmod": self._predict_chmod,
            "chown": self._predict_chown,
            "git": self._predict_git,
            "docker": self._predict_docker,
            "pip": self._predict_pip,
            "rsync": self._predict_rsync,
            "kubectl": self._predict_kubectl,
            "brew": self._predict_brew,
            "apt": self._predict_apt,
            "apt-get": self._predict_apt,
            "systemctl": self._predict_systemctl,
        }
        return handlers.get(executable)

    def _resolve_path(self, path: str) -> str:
        """Resolve a path relative to working directory."""
        if os.path.isabs(path):
            return path
        return os.path.normpath(os.path.join(self._cwd, path))

    def _expand_glob(self, pattern: str) -> list[str]:
        """Expand glob patterns to matching paths."""
        resolved = self._resolve_path(pattern)
        matches = globmod.glob(resolved)
        return matches if matches else [resolved]

    def _get_size(self, path: str) -> Optional[int]:
        """Get file/directory size, or None if not accessible.

        Limits directory traversal to avoid scanning huge trees like /.
        """
        try:
            if os.path.isfile(path):
                return os.path.getsize(path)
            elif os.path.isdir(path):
                # Don't walk system root or very large directories
                if path in ("/", "/usr", "/var", "/etc", "/System"):
                    return None
                total = 0
                file_count = 0
                max_files = 10_000
                for dirpath, _dirnames, filenames in os.walk(path):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        try:
                            total += os.path.getsize(fp)
                        except OSError:
                            pass
                        file_count += 1
                        if file_count >= max_files:
                            return total
                return total
        except OSError:
            return None

    def _predict_rm(self, cmd: CommandInfo):
        is_recursive = any(f in cmd.flags for f in ("-r", "-R", "--recursive", "-rf", "-fr"))
        changes: list[FileChange] = []

        for arg in cmd.args:
            paths = self._expand_glob(arg)
            for path in paths:
                size = self._get_size(path)
                if os.path.isdir(path) and is_recursive:
                    changes.append(
                        FileChange(
                            path=path,
                            change_type=FileChangeType.DELETE,
                            details="Directory and all contents will be removed",
                            size_bytes=size,
                        )
                    )
                elif os.path.isdir(path) and not is_recursive:
                    changes.append(
                        FileChange(
                            path=path,
                            change_type=FileChangeType.DELETE,
                            details="rm will FAIL: target is a directory (use -r to remove)",
                            size_bytes=size,
                        )
                    )
                elif os.path.isfile(path) or os.path.islink(path):
                    changes.append(
                        FileChange(
                            path=path,
                            change_type=FileChangeType.DELETE,
                            details="File will be removed",
                            size_bytes=size,
                        )
                    )
                else:
                    changes.append(
                        FileChange(
                            path=path,
                            change_type=FileChangeType.DELETE,
                            details="Target will be removed (does not currently exist)",
                        )
                    )

        return (
            tuple(changes),
            False,
            "Deleted files cannot be recovered without backups",
            False,
            None,
            (),
            (),
        )

    def _predict_mv(self, cmd: CommandInfo):
        changes: list[FileChange] = []

        if len(cmd.args) >= 2:
            sources = cmd.args[:-1]
            dest = cmd.args[-1]
            dest_path = self._resolve_path(dest)

            for src in sources:
                src_path = self._resolve_path(src)
                size = self._get_size(src_path)

                if os.path.isdir(dest_path) or len(sources) > 1:
                    target = os.path.join(dest_path, os.path.basename(src_path))
                else:
                    target = dest_path

                changes.append(
                    FileChange(
                        path=src_path,
                        change_type=FileChangeType.MOVE,
                        details=f"Will be moved to {target}",
                        size_bytes=size,
                    )
                )

                if os.path.exists(target):
                    changes.append(
                        FileChange(
                            path=target,
                            change_type=FileChangeType.MODIFY,
                            details="Existing file will be overwritten",
                        )
                    )

        return (
            tuple(changes),
            True,
            "Can be reversed by moving files back to original location",
            False,
            None,
            (),
            (),
        )

    def _predict_cp(self, cmd: CommandInfo):
        changes: list[FileChange] = []
        is_recursive = any(f in cmd.flags for f in ("-r", "-R", "--recursive"))

        if len(cmd.args) >= 2:
            sources = cmd.args[:-1]
            dest = cmd.args[-1]
            dest_path = self._resolve_path(dest)

            for src in sources:
                src_path = self._resolve_path(src)
                size = self._get_size(src_path)

                if os.path.isdir(dest_path) or len(sources) > 1:
                    target = os.path.join(dest_path, os.path.basename(src_path))
                else:
                    target = dest_path

                detail = "Directory copied recursively" if is_recursive else "File copied"
                changes.append(
                    FileChange(
                        path=target,
                        change_type=FileChangeType.CREATE,
                        details=detail,
                        size_bytes=size,
                    )
                )

        return (
            tuple(changes),
            True,
            "Copied files can be deleted to reverse",
            False,
            None,
            (),
            (),
        )

    def _predict_mkdir(self, cmd: CommandInfo):
        changes: list[FileChange] = []

        for arg in cmd.args:
            path = self._resolve_path(arg)
            changes.append(
                FileChange(
                    path=path,
                    change_type=FileChangeType.CREATE,
                    details="Directory will be created",
                )
            )

        return (
            tuple(changes),
            True,
            "Directories can be removed with rmdir",
            False,
            None,
            (),
            (),
        )

    def _predict_touch(self, cmd: CommandInfo):
        changes: list[FileChange] = []

        for arg in cmd.args:
            path = self._resolve_path(arg)
            if os.path.exists(path):
                changes.append(
                    FileChange(
                        path=path,
                        change_type=FileChangeType.MODIFY,
                        details="Timestamp will be updated",
                    )
                )
            else:
                changes.append(
                    FileChange(
                        path=path,
                        change_type=FileChangeType.CREATE,
                        details="Empty file will be created",
                    )
                )

        return (
            tuple(changes),
            True,
            "Created files can be deleted; timestamp changes are minor",
            False,
            None,
            (),
            (),
        )

    def _predict_chmod(self, cmd: CommandInfo):
        changes: list[FileChange] = []

        # Find the mode argument (first non-flag arg)
        mode = cmd.args[0] if cmd.args else "unknown"
        targets = cmd.args[1:] if len(cmd.args) > 1 else ()

        for target in targets:
            path = self._resolve_path(target)
            changes.append(
                FileChange(
                    path=path,
                    change_type=FileChangeType.PERMISSION,
                    details=f"Permissions will be changed to {mode}",
                )
            )

        warnings = ()
        suggestions = ()
        if mode == "777":
            warnings = ("chmod 777 makes files world-readable and writable - security risk!",)
            suggestions = (
                Suggestion(
                    message="Use more restrictive permissions like 755 or 644",
                    suggested_command=None,
                ),
            )

        return (
            tuple(changes),
            True,
            "Permissions can be changed back to previous values",
            False,
            None,
            warnings,
            suggestions,
        )

    def _predict_chown(self, cmd: CommandInfo):
        changes: list[FileChange] = []

        owner = cmd.args[0] if cmd.args else "unknown"
        targets = cmd.args[1:] if len(cmd.args) > 1 else ()

        for target in targets:
            path = self._resolve_path(target)
            changes.append(
                FileChange(
                    path=path,
                    change_type=FileChangeType.OWNERSHIP,
                    details=f"Ownership will be changed to {owner}",
                )
            )

        return (
            tuple(changes),
            True,
            "Ownership can be changed back (may require sudo)",
            False,
            None,
            (),
            (),
        )

    def _predict_git(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""
        changes: list[FileChange] = []
        reversible = True
        rev_note = ""
        warnings: tuple[str, ...] = ()

        if subcommand == "reset" and "--hard" in cmd.flags:
            reversible = False
            rev_note = "Hard reset discards uncommitted changes permanently"
            changes = (
                FileChange(
                    path=self._cwd,
                    change_type=FileChangeType.MODIFY,
                    details="Working directory will be reset, uncommitted changes lost",
                ),
            )
        elif subcommand == "clean" and ("-f" in cmd.flags or "--force" in cmd.flags):
            reversible = False
            rev_note = "Cleaned untracked files cannot be recovered"
            changes = (
                FileChange(
                    path=self._cwd,
                    change_type=FileChangeType.DELETE,
                    details="Untracked files will be permanently deleted",
                ),
            )
        elif subcommand in ("push",):
            if "--force" in cmd.flags:
                reversible = False
                rev_note = "Force push can permanently overwrite remote history"
                warnings = ("Force pushing can destroy work others have based on the old history",)
            else:
                rev_note = "Pushed commits can be reverted with git revert"
        elif subcommand == "checkout":
            rev_note = "Can switch back to previous branch"
        elif subcommand in ("add", "commit", "stash", "branch", "merge"):
            rev_note = f"git {subcommand} operations are generally reversible"
        else:
            rev_note = f"git {subcommand} - check git documentation for reversibility"

        return tuple(changes), reversible, rev_note, False, None, warnings, ()

    def _predict_docker(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""
        changes: list[FileChange] = []
        reversible = True
        rev_note = ""

        if subcommand == "system" and len(cmd.args) > 1 and cmd.args[1] == "prune":
            reversible = False
            rev_note = "Pruned Docker resources must be rebuilt/re-pulled"
        elif subcommand in ("rm", "rmi"):
            reversible = False
            rev_note = "Removed containers/images must be rebuilt/re-pulled"
        elif subcommand in ("run", "create", "build"):
            rev_note = "Container/image can be removed to reverse"
        elif subcommand in ("stop", "start", "restart"):
            rev_note = f"Container can be {('started' if subcommand == 'stop' else 'stopped')} again"
        else:
            rev_note = f"docker {subcommand} - check Docker docs for reversibility"

        return tuple(changes), reversible, rev_note, False, None, (), ()

    def _predict_pip(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""
        if subcommand == "install":
            rev_note = "Installed packages can be removed with pip uninstall"
            reversible = True
        elif subcommand == "uninstall":
            rev_note = "Uninstalled packages can be reinstalled"
            reversible = True
        else:
            rev_note = f"pip {subcommand}"
            reversible = True

        return (), reversible, rev_note, False, None, (), ()

    def _predict_rsync(self, cmd: CommandInfo):
        is_dry_run = any(f in cmd.flags for f in ("-n", "--dry-run"))
        dry_cmd = None

        if not is_dry_run:
            # Suggest dry run version
            dry_cmd = cmd.raw.replace("rsync ", "rsync --dry-run ", 1)

        return (
            (),
            True,
            "Files can generally be synced back",
            True,
            dry_cmd,
            (),
            (),
        )

    def _predict_kubectl(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""

        if subcommand == "delete":
            return (
                (),
                False,
                "Deleted Kubernetes resources may need to be recreated from manifests",
                True,
                cmd.raw.replace("delete", "delete --dry-run=client", 1),
                (),
                (),
            )
        elif subcommand == "apply":
            return (
                (),
                True,
                "Applied resources can be reverted by applying previous manifests",
                True,
                cmd.raw.replace("apply", "apply --dry-run=client", 1),
                (),
                (),
            )
        else:
            return (), True, f"kubectl {subcommand}", False, None, (), ()

    def _predict_brew(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""

        if subcommand == "install":
            return (), True, "Installed packages can be removed with brew uninstall", False, None, (), ()
        elif subcommand == "uninstall":
            return (), True, "Packages can be reinstalled with brew install", False, None, (), ()
        elif subcommand == "update":
            return (), True, "Homebrew updated - previous state in git history", False, None, (), ()
        else:
            return (), True, f"brew {subcommand}", False, None, (), ()

    def _predict_apt(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""

        if subcommand == "install":
            return (
                (),
                True,
                "Installed packages can be removed with apt remove",
                True,
                cmd.raw + " --dry-run" if "--dry-run" not in cmd.raw else None,
                (),
                (),
            )
        elif subcommand in ("remove", "purge"):
            return (
                (),
                True,
                "Removed packages can be reinstalled",
                True,
                cmd.raw + " --dry-run" if "--dry-run" not in cmd.raw else None,
                (),
                (),
            )
        elif subcommand == "autoremove":
            return (), True, "Removed packages can be reinstalled", True, cmd.raw + " --dry-run", (), ()
        else:
            return (), True, f"apt {subcommand}", False, None, (), ()

    def _predict_systemctl(self, cmd: CommandInfo):
        subcommand = cmd.args[0] if cmd.args else ""
        service = cmd.args[1] if len(cmd.args) > 1 else "unknown"

        if subcommand in ("stop", "start", "restart"):
            reverse = {"stop": "start", "start": "stop", "restart": "restart"}
            return (
                (),
                True,
                f"Service can be reversed with systemctl {reverse[subcommand]} {service}",
                False,
                None,
                (),
                (),
            )
        elif subcommand in ("enable", "disable"):
            reverse = {"enable": "disable", "disable": "enable"}
            return (
                (),
                True,
                f"Can be reversed with systemctl {reverse[subcommand]} {service}",
                False,
                None,
                (),
                (),
            )
        else:
            return (), True, f"systemctl {subcommand}", False, None, (), ()
