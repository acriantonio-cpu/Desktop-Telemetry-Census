"""Console output with verbosity levels + a journal hook (everything important is also persisted).

Verbosity: 0 = normal, 1 (-v) = per-item detail, 2 (-vv / --debug) = decision traces.
Messages are printed as plain text (no rich markup parsing) so paths/brackets never break rendering.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.table import Table
from rich.text import Text


class UI:
    def __init__(self) -> None:
        self.console = Console(highlight=False, soft_wrap=True)
        self.err = Console(stderr=True, highlight=False, soft_wrap=True)
        self.verbosity = 0
        self.sink: Callable[[str, str], None] | None = None  # (level, message) -> journal

    # ---- configuration -------------------------------------------------
    def set_verbosity(self, level: int) -> None:
        self.verbosity = max(0, int(level))

    def attach_journal(self, sink: Callable[[str, str], None] | None) -> None:
        self.sink = sink

    def _journal(self, level: str, msg: str) -> None:
        if self.sink:
            try:
                self.sink(level, msg)
            except Exception:  # noqa: BLE001, S110  # journaling must never break the tool  # nosec B110
                pass

    # ---- messages ------------------------------------------------------
    def step(self, msg: str) -> None:
        self.console.print(Text(f"\n=== {msg}", style="bold cyan"))
        self._journal("STEP", msg)

    def info(self, msg: str) -> None:
        self.console.print(Text(f"[i] {msg}"))
        self._journal("INFO", msg)

    def ok(self, msg: str) -> None:
        self.console.print(Text(f"[OK] {msg}", style="green"))
        self._journal("OK", msg)

    def warn(self, msg: str) -> None:
        self.console.print(Text(f"[!] {msg}", style="yellow"))
        self._journal("WARN", msg)

    def error(self, msg: str) -> None:
        self.err.print(Text(f"[ERROR] {msg}", style="bold red"))
        self._journal("ERROR", msg)

    def verbose(self, msg: str) -> None:
        if self.verbosity >= 1:
            self.console.print(Text(f"    {msg}", style="dim"))
        self._journal("VERBOSE", msg)

    def debug(self, msg: str) -> None:
        if self.verbosity >= 2:
            self.console.print(Text(f"    [debug] {msg}", style="magenta"))
        self._journal("DEBUG", msg)

    def plain(self, msg: str = "") -> None:
        self.console.print(Text(msg))

    # ---- structures ----------------------------------------------------
    def table(self, title: str, columns: list[str], rows: list[list], styles: dict[int, str] | None = None) -> None:
        t = Table(title=title, show_lines=False, header_style="bold")
        for c in columns:
            t.add_column(str(c), overflow="fold")
        for r in rows:
            t.add_row(*[Text("" if v is None else str(v)) for v in r])
        self.console.print(t)

    def kv(self, title: str, items: list[tuple[str, object]]) -> None:
        self.table(title, ["key", "value"], [[k, v] for k, v in items])


ui = UI()
