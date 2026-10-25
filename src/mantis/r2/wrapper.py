"""
Mantis radare2 Wrapper.
Executes radare2, rabin2, and rahash2 CLI tools with fail-closed error handling,
bounded timeouts, and robust environment resolution (handling LD_LIBRARY_PATH).
"""

import os
import shutil
import subprocess
from typing import ClassVar

from ..exceptions import MANTIS_RC_FAILURE, MANTIS_RC_TIMEOUT, MantisR2Error
from .parser import (
    EntropyProfile,
    R2BinaryInfo,
    R2Opcode,
    R2Section,
    parse_binary_info,
    parse_disasm,
    parse_entropy,
    parse_sections,
)


class R2Wrapper:
    """
    Forensic radare2 wrapper ensuring fail-closed boundaries and strict execution timeouts.
    """

    DEFAULT_TIMEOUT_SEC = 30
    KNOWN_LIB_PATHS: ClassVar[list[str]] = [
        "/usr/local/lib",
        "/usr/lib",
    ]

    def __init__(
        self,
        r2_bin: str | None = None,
        rabin2_bin: str | None = None,
        rahash2_bin: str | None = None,
        extra_lib_paths: list[str] | None = None,
        timeout: int = DEFAULT_TIMEOUT_SEC,
    ):
        self.r2_bin = r2_bin or self._find_tool("radare2") or self._find_tool("r2")
        self.rabin2_bin = rabin2_bin or self._find_tool("rabin2")
        self.rahash2_bin = rahash2_bin or self._find_tool("rahash2")
        self.timeout = timeout
        self.lib_paths = list(self.KNOWN_LIB_PATHS)
        if extra_lib_paths:
            self.lib_paths.extend(extra_lib_paths)

        isolated_dir = self._prepare_isolated_r2_lib_dir()
        if isolated_dir and isolated_dir not in self.lib_paths:
            self.lib_paths.insert(0, isolated_dir)

    @classmethod
    def _prepare_isolated_r2_lib_dir(cls) -> str | None:
        """
        Symlinks candidate libr_*.so files into an isolated directory (~/.cache/mantis/r2_libs).
        This guarantees foreign libraries (such as Termux Bionic runtime files)
        never poison the glibc loader for standard system binaries.
        """
        isolated_dir = os.path.expanduser("~/.cache/mantis/r2_libs")
        candidate_dirs = [
            "/data/data/com.termux/files/usr/lib",
            "/usr/local/lib/radare2",
            "/usr/lib/radare2",
        ]

        found_any = False
        for cdir in candidate_dirs:
            if not os.path.isdir(cdir):
                continue
            try:
                os.makedirs(isolated_dir, exist_ok=True)
                for fname in os.listdir(cdir):
                    if fname.startswith("libr_") and (".so" in fname):
                        dst = os.path.join(isolated_dir, fname)
                        src = os.path.join(cdir, fname)
                        if not os.path.exists(dst):
                            try:
                                os.symlink(src, dst)
                            except OSError:
                                pass
                        found_any = True
            except OSError:
                pass

        if found_any and os.path.isdir(isolated_dir):
            return isolated_dir
        return None

    @staticmethod
    def _find_tool(tool_name: str) -> str | None:
        # 1. Standard PATH
        which_path = shutil.which(tool_name)
        if which_path and os.path.exists(which_path):
            return which_path

        # 2. Known standard install paths
        candidates = [
            f"/data/data/com.termux/files/usr/bin/{tool_name}",
            f"/usr/local/bin/{tool_name}",
            f"/usr/bin/{tool_name}",
        ]
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def get_env(self) -> dict[str, str]:
        """
        Constructs an environment dictionary ensuring required shared libraries
        are resolvable via LD_LIBRARY_PATH.
        """
        env = dict(os.environ)
        existing_ld = env.get("LD_LIBRARY_PATH", "")
        paths = [p for p in self.lib_paths if os.path.exists(p)]
        if existing_ld:
            paths.insert(0, existing_ld)

        if paths:
            env["LD_LIBRARY_PATH"] = ":".join(paths)
        return env

    def run_command(
        self,
        cmd: list[str],
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Executes an r2 tool command fail-closed.
        Raises MantisR2Error if the binary is missing, times out, or fails.
        """
        if not cmd or not cmd[0]:
            raise MantisR2Error("Command binary is not specified or unavailable.", code=MANTIS_RC_FAILURE)

        t = timeout or self.timeout
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                check=False,
                text=True,
                env=self.get_env(),
                timeout=t,
            )
            if check and res.returncode != 0:
                raise MantisR2Error(
                    f"Tool command {' '.join(cmd)} failed (rc={res.returncode}): {res.stderr.strip()}",
                    code=res.returncode,
                )
            return res
        except subprocess.TimeoutExpired as e:
            raise MantisR2Error(
                f"Tool command {' '.join(cmd)} timed out after {t}s.",
                code=MANTIS_RC_TIMEOUT,
            ) from e
        except FileNotFoundError as e:
            raise MantisR2Error(
                f"Tool executable not found: {cmd[0]}",
                code=MANTIS_RC_FAILURE,
            ) from e

    def get_binary_info(self, file_path: str) -> R2BinaryInfo:
        """Extracts binary metadata using rabin2 -j -I."""
        if not self.rabin2_bin:
            raise MantisR2Error("rabin2 binary not found on system.", code=MANTIS_RC_FAILURE)

        cmd = [self.rabin2_bin, "-j", "-I", file_path]
        res = self.run_command(cmd)
        return parse_binary_info(res.stdout)

    def get_sections(self, file_path: str) -> list[R2Section]:
        """Extracts binary sections using rabin2 -j -S."""
        if not self.rabin2_bin:
            raise MantisR2Error("rabin2 binary not found on system.", code=MANTIS_RC_FAILURE)

        cmd = [self.rabin2_bin, "-j", "-S", file_path]
        res = self.run_command(cmd)
        return parse_sections(res.stdout)

    def disassemble(self, file_path: str, offset: int = 0, count: int = 10) -> list[R2Opcode]:
        """Disassembles instructions at an offset using radare2 pdj."""
        if not self.r2_bin:
            raise MantisR2Error("radare2 binary not found on system.", code=MANTIS_RC_FAILURE)

        cmd = [self.r2_bin, "-qc", f"s {offset}; pdj {count}", file_path]
        res = self.run_command(cmd)
        return parse_disasm(res.stdout)

    def calculate_entropy(self, file_path: str, block_size: int = 1024) -> EntropyProfile:
        """Calculates file entropy using rahash2."""
        if not self.rahash2_bin:
            raise MantisR2Error("rahash2 binary not found on system.", code=MANTIS_RC_FAILURE)

        cmd = [self.rahash2_bin, "-j", "-a", "entropy", "-b", str(block_size), file_path]
        res = self.run_command(cmd)
        return parse_entropy(res.stdout)
