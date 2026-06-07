"""Subprocess runner with typed exceptions, streaming, and exponential-backoff retries."""
from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Callable
from typing import Optional

from .exceptions import CaptureError, CrackError, DependencyError

logger = logging.getLogger(__name__)

_BACKOFF_BASE = 1.0
_BACKOFF_MAX = 30.0


class SubprocessRunner:
    """Thread-safe subprocess wrapper with retry and structured error handling."""

    def run(
        self,
        cmd: list[str],
        timeout: float = 60.0,
        retries: int = 0,
        on_output_line: Optional[Callable[[str], None]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run *cmd*, retrying up to *retries* times with exponential backoff.
        Every call is logged at DEBUG with full argv + pid.
        """
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt <= retries:
            if attempt > 0:
                delay = min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_MAX)
                logger.debug("Retry %d/%d after %.1fs: %s", attempt, retries, delay, cmd[0])
                time.sleep(delay)

            try:
                logger.debug("RUN argv=%s", cmd)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                logger.debug("EXIT code=%d pid=finished", result.returncode)

                if on_output_line:
                    for line in result.stdout.splitlines():
                        logger.debug("stdout: %s", line)
                        on_output_line(line)
                    for line in result.stderr.splitlines():
                        logger.debug("stderr: %s", line)

                return result

            except subprocess.TimeoutExpired as exc:
                last_exc = CaptureError(
                    f"{cmd[0]!r} timed out after {timeout:.0f}s"
                )
                last_exc.__cause__ = exc

            except FileNotFoundError as exc:
                raise DependencyError(
                    f"Required binary not found: {cmd[0]!r}. "
                    "Run: wifi-auditor --preflight",
                    binary=cmd[0],
                ) from exc

            except subprocess.CalledProcessError as exc:
                last_exc = _parse_subprocess_error(exc)

            attempt += 1

        assert last_exc is not None
        raise last_exc

    def stream(
        self,
        cmd: list[str],
        timeout: float = 300.0,
        on_output_line: Optional[Callable[[str], None]] = None,
    ) -> int:
        """
        Stream *cmd* stdout line-by-line through *on_output_line*.
        Returns the exit code. Kills the process if *timeout* elapses.
        """
        logger.debug("STREAM argv=%s", cmd)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise DependencyError(
                f"Required binary not found: {cmd[0]!r}",
                binary=cmd[0],
            ) from exc

        logger.debug("STREAM pid=%d", proc.pid)
        start = time.monotonic()

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip("\n")
                logger.debug("stdout: %s", line)
                if on_output_line:
                    on_output_line(line)
                if time.monotonic() - start > timeout:
                    proc.kill()
                    raise CaptureError(
                        f"{cmd[0]!r} stream timed out after {timeout:.0f}s"
                    )
        finally:
            proc.wait()

        return proc.returncode


def _parse_subprocess_error(exc: subprocess.CalledProcessError) -> Exception:
    stderr = (exc.stderr or "").lower()
    if "no such file" in stderr or "not found" in stderr:
        return DependencyError(str(exc))
    if "handshake" in stderr or "pmkid" in stderr:
        return CaptureError(str(exc))
    return CrackError(str(exc))
