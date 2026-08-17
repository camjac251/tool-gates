"""Validate the GitHub-rendered structure of the project README."""

from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path


def normalize(parts: list[str]) -> str:
    return " ".join("".join(parts).split())


class ReadmeRenderParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.important_alerts: list[str] = []
        self.mermaid_blocks = 0
        self.rows: list[list[str]] = []
        self.summaries: list[str] = []

        self._alert_div_depth = 0
        self._alert_parts: list[str] = []
        self._current_row: list[str] | None = None
        self._current_cell: list[str] | None = None
        self._summary_parts: list[str] | None = None

    def handle_starttag(
        self, tag: str, attrs_list: list[tuple[str, str | None]]
    ) -> None:
        attrs = dict(attrs_list)
        classes = set((attrs.get("class") or "").split())

        if self._alert_div_depth:
            if tag == "div":
                self._alert_div_depth += 1
        elif tag == "div" and "markdown-alert-important" in classes:
            self._alert_div_depth = 1
            self._alert_parts = []

        if tag == "section" and attrs.get("data-type") == "mermaid":
            self.mermaid_blocks += 1
        elif tag == "tr":
            self._current_row = []
        elif tag in {"td", "th"} and self._current_row is not None:
            self._current_cell = []
        elif tag == "summary":
            self._summary_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self._alert_div_depth:
            self._alert_div_depth -= 1
            if not self._alert_div_depth:
                self.important_alerts.append(normalize(self._alert_parts))
                self._alert_parts = []

        if tag in {"td", "th"} and self._current_cell is not None:
            if self._current_row is not None:
                self._current_row.append(normalize(self._current_cell))
            self._current_cell = None
        elif tag == "tr" and self._current_row is not None:
            self.rows.append(self._current_row)
            self._current_row = None
        elif tag == "summary" and self._summary_parts is not None:
            self.summaries.append(normalize(self._summary_parts))
            self._summary_parts = None

    def handle_data(self, data: str) -> None:
        if self._alert_div_depth:
            self._alert_parts.append(data)
        if self._current_cell is not None:
            self._current_cell.append(data)
        if self._summary_parts is not None:
            self._summary_parts.append(data)


def validate(html: str) -> list[str]:
    parser = ReadmeRenderParser()
    parser.feed(html)
    parser.close()

    errors: list[str] = []
    expected_alert_fragments = (
        "Auto Mode does not bypass Tool Gates.",
        "Tool Gates still evaluates each supported hook call before Claude's classifier",
    )
    if not any(
        all(fragment in alert for fragment in expected_alert_fragments)
        for alert in parser.important_alerts
    ):
        errors.append("the Auto Mode notice is not a GitHub IMPORTANT alert")

    expected_summaries = {
        "Codex CLI setup",
        "Antigravity CLI setup",
        "Gemini CLI compatibility setup",
    }
    missing_summaries = expected_summaries.difference(parser.summaries)
    if missing_summaries:
        errors.append(
            "missing collapsible setup sections: "
            + ", ".join(sorted(missing_summaries))
        )

    if parser.mermaid_blocks < 1:
        errors.append("the architecture diagram is not rendered as Mermaid")

    shell_rows = [row for row in parser.rows if row and row[0] == "Shell-aware gates"]
    if len(shell_rows) != 1:
        errors.append(
            "the shell-aware feature row is missing or split across table cells"
        )
    else:
        shell_description = shell_rows[0][1] if len(shell_rows[0]) == 2 else ""
        missing_operators = [
            operator
            for operator in ("&&", "||", "; command chains")
            if operator not in shell_description
        ]
        if missing_operators:
            errors.append(
                "the shell-aware feature row lost operators: "
                + ", ".join(missing_operators)
            )

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} RENDERED_HTML", file=sys.stderr)
        return 2

    html_path = Path(sys.argv[1])
    try:
        html = html_path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"unable to read {html_path}: {error}", file=sys.stderr)
        return 2

    errors = validate(html)
    if errors:
        print("README GitHub rendering check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("README GitHub rendering check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
