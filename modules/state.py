"""Session state management with persistence and graceful signal handling."""
from __future__ import annotations

import json
import logging
import signal
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path.home() / ".wifi-auditor" / "sessions"


class Stage(str, Enum):
    INIT = "init"
    INTERFACE = "interface"
    SCANNING = "scanning"
    CAPTURING = "capturing"
    WORDLIST = "wordlist"
    CRACKING = "cracking"
    DONE = "done"
    FAILED = "failed"


@dataclass
class SessionState:
    interface: Optional[str] = None
    monitor_interface: Optional[str] = None
    target_bssid: Optional[str] = None
    target_ssid: Optional[str] = None
    channel: Optional[int] = None
    capture_file: Optional[str] = None
    handshake_file: Optional[str] = None
    wordlist_file: Optional[str] = None
    result: Optional[str] = None
    stage: Stage = Stage.INIT
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    session_id: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )


class StateManager:
    """Manages session lifecycle, disk persistence, and cleanup on SIGINT/SIGTERM."""

    def __init__(self) -> None:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self.state = SessionState()
        self._register_signals()

    def _register_signals(self) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (OSError, ValueError):
            pass

    def _handle_signal(self, signum: int, frame: object) -> None:
        logger.info("Signal %d received — cleaning up interface before exit", signum)
        self._cleanup_interface()
        sys.exit(0)

    def _cleanup_interface(self) -> None:
        if self.state.monitor_interface:
            try:
                logger.info("Stopping monitor mode on %s", self.state.monitor_interface)
                subprocess.run(
                    ["airmon-ng", "stop", self.state.monitor_interface],
                    capture_output=True,
                    timeout=10,
                )
            except Exception as exc:
                logger.debug("Interface cleanup error: %s", exc)
            self.state.monitor_interface = None

    def transition(self, stage: Stage, **kwargs: object) -> None:
        """Move to *stage*, set any extra fields in *kwargs*, then persist."""
        self.state.stage = stage
        for key, value in kwargs.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)
        self._save()
        logger.debug("Stage → %s", stage.value)

    def _save(self) -> None:
        path = SESSIONS_DIR / f"{self.state.session_id}.json"
        data = asdict(self.state)
        data["stage"] = self.state.stage.value
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def list_incomplete(cls) -> list[Path]:
        """Return paths to sessions that did not reach DONE or FAILED."""
        if not SESSIONS_DIR.exists():
            return []
        incomplete: list[Path] = []
        for f in sorted(SESSIONS_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if data.get("stage") not in (Stage.DONE.value, Stage.FAILED.value):
                    incomplete.append(f)
            except Exception:
                pass
        return incomplete

    @classmethod
    def load(cls, path: Path) -> "StateManager":
        """Load a previously-saved session from disk."""
        mgr = cls.__new__(cls)
        mgr._register_signals = cls._register_signals.__get__(mgr)  # type: ignore[attr-defined]
        mgr._register_signals()
        data = json.loads(path.read_text())
        stage_val = data.pop("stage", Stage.INIT.value)
        valid_fields = SessionState.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        filtered["stage"] = Stage(stage_val)
        mgr.state = SessionState(**filtered)
        return mgr
