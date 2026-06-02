"""
Container Probe – Graphical Interface
Drop this file at the repo root (alongside src/) and run:
    python gui.py
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Make sure the package is importable when running from the repo root
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent / "src"))

from container_probe import inspect_file                          # noqa: E402
from container_probe.cli import (                                 # noqa: E402
    render_findings,
    summarize_encryption_details,
    summarize_algorithms,
    build_analysis_guidance,
    summarize_verdict,
    normalize_encryption_details,
    Style,
    PASSWORD_RECOVERY_SUPPORT,
)

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT   = "#3b82f6"   # blue-500
SUCCESS  = "#22c55e"   # green-500
WARNING  = "#f59e0b"   # amber-500
DANGER   = "#ef4444"   # red-500
BG_CARD  = "#1e293b"   # slate-800
BG_ROW   = "#0f172a"   # slate-900
FG_MAIN  = "#f1f5f9"   # slate-100
FG_DIM   = "#94a3b8"   # slate-400

FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_SECTION= ("Segoe UI", 13, "bold")
FONT_LABEL  = ("Segoe UI", 11, "bold")
FONT_VALUE  = ("Segoe UI", 11)
FONT_MONO   = ("Consolas", 10)
FONT_BADGE  = ("Segoe UI", 9, "bold")

CONFIDENCE_COLORS = {"high": SUCCESS, "medium": WARNING, "low": DANGER}


# ---------------------------------------------------------------------------
# Helper widgets
# ---------------------------------------------------------------------------

class SectionHeader(ctk.CTkLabel):
    def __init__(self, parent, text, **kw):
        super().__init__(parent, text=f"  {text}", font=FONT_SECTION,
                         anchor="w", fg_color=BG_CARD,
                         text_color=FG_MAIN, corner_radius=6,
                         height=32, **kw)


class KVRow(ctk.CTkFrame):
    """A single key → value row with an optional copy button."""
    def __init__(self, parent, key, value, mono=False, copyable=True, **kw):
        super().__init__(parent, fg_color=BG_ROW, corner_radius=4, **kw)
        font = FONT_MONO if mono else FONT_VALUE
        ctk.CTkLabel(self, text=key, font=FONT_LABEL, text_color=FG_DIM,
                     width=190, anchor="w").pack(side="left", padx=(10, 4), pady=5)
        ctk.CTkLabel(self, text=str(value), font=font, text_color=FG_MAIN,
                     anchor="w", wraplength=560).pack(side="left", padx=4, pady=5, fill="x", expand=True)
        if copyable and value:
            ctk.CTkButton(self, text="Copy", width=52, height=24,
                          font=("Segoe UI", 10),
                          command=lambda v=str(value): self._copy(v)
                          ).pack(side="right", padx=8, pady=5)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)


class Badge(ctk.CTkLabel):
    def __init__(self, parent, confidence, **kw):
        color = CONFIDENCE_COLORS.get(confidence.lower(), FG_DIM)
        super().__init__(parent, text=f" {confidence.upper()} ",
                         font=FONT_BADGE, text_color="white",
                         fg_color=color, corner_radius=4, **kw)


class DetectionCard(ctk.CTkFrame):
    """One detection / heuristic / sidecar card."""
    def __init__(self, parent, finding: dict, **kw):
        super().__init__(parent, fg_color=BG_CARD, corner_radius=8, **kw)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(header, text=finding["label"], font=FONT_LABEL,
                     text_color=FG_MAIN, anchor="w").pack(side="left")
        Badge(header, finding["confidence"]).pack(side="left", padx=8)

        ctk.CTkLabel(self, text=finding["rationale"], font=FONT_VALUE,
                     text_color=FG_DIM, anchor="w", wraplength=720,
                     justify="left").pack(fill="x", padx=12, pady=(0, 6))

        for k, v in finding.get("details", {}).items():
            KVRow(self, k.replace("_", " ").title(), v, mono=True
                  ).pack(fill="x", padx=12, pady=2)

        ctk.CTkFrame(self, height=1, fg_color="#334155").pack(fill="x",
                     padx=12, pady=(8, 0))


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Container Probe")
        self.geometry("900x700")
        self.minsize(720, 500)
        self._selected_path: Path | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ── Top bar ────────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=64)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="🔍  Container Probe",
                     font=FONT_TITLE, text_color=FG_MAIN).pack(side="left", padx=20)

        ctk.CTkLabel(top, text="Encrypted-container inspector",
                     font=("Segoe UI", 11), text_color=FG_DIM).pack(side="left")

        # ── File picker bar ────────────────────────────────────────────
        picker = ctk.CTkFrame(self, fg_color=BG_ROW, corner_radius=0, height=52)
        picker.pack(fill="x", side="top")
        picker.pack_propagate(False)

        self._path_var = ctk.StringVar(value="No file selected …")
        ctk.CTkEntry(picker, textvariable=self._path_var, state="readonly",
                     font=FONT_VALUE, width=560,
                     text_color=FG_DIM).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(picker, text="Browse …", width=110,
                      command=self._browse).pack(side="left", padx=4)

        self._scan_btn = ctk.CTkButton(picker, text="Scan", width=100,
                                       fg_color=ACCENT,
                                       command=self._start_scan)
        self._scan_btn.pack(side="left", padx=4)

        self._status = ctk.CTkLabel(picker, text="", font=("Segoe UI", 10),
                                    text_color=FG_DIM)
        self._status.pack(side="left", padx=12)

        # ── Scrollable results area ────────────────────────────────────
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="#0d1117",
                                              corner_radius=0)
        self._scroll.pack(fill="both", expand=True)

        self._show_placeholder()

    def _show_placeholder(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._scroll,
                     text="Select a file and click Scan to begin.",
                     font=("Segoe UI", 14), text_color=FG_DIM
                     ).pack(pady=60)

    # ------------------------------------------------------------------
    # File picking
    # ------------------------------------------------------------------

    def _browse(self):
        path = filedialog.askopenfilename(title="Select file to inspect")
        if path:
            self._selected_path = Path(path)
            self._path_var.set(str(self._selected_path))
            self._status.configure(text="")

    # ------------------------------------------------------------------
    # Scanning (runs in background thread so the UI stays responsive)
    # ------------------------------------------------------------------

    def _start_scan(self):
        if not self._selected_path:
            self._status.configure(text="⚠  No file selected", text_color=WARNING)
            return
        if not self._selected_path.exists():
            self._status.configure(text="⚠  File not found", text_color=DANGER)
            return

        self._scan_btn.configure(state="disabled", text="Scanning …")
        self._status.configure(text="", text_color=FG_DIM)

        for w in self._scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._scroll, text="Scanning …",
                     font=("Segoe UI", 13), text_color=FG_DIM
                     ).pack(pady=40)

        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        try:
            report = inspect_file(self._selected_path).to_dict()
            self.after(0, lambda: self._render_report(report))
        except Exception as exc:
            self.after(0, lambda: self._render_error(exc))

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_error(self, exc: Exception):
        self._reset_scan_btn()
        for w in self._scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._scroll, text=f"❌  Error: {exc}",
                     font=("Segoe UI", 12), text_color=DANGER).pack(pady=40)

    def _render_report(self, report: dict):
        self._reset_scan_btn()
        for w in self._scroll.winfo_children():
            w.destroy()

        pad = {"fill": "x", "padx": 16, "pady": 6}

        # ── File stats ────────────────────────────────────────────────
        SectionHeader(self._scroll, "File Statistics").pack(**pad)
        stats = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
        stats.pack(**pad)
        KVRow(stats, "Path",           report["path"]).pack(fill="x", padx=10, pady=2)
        KVRow(stats, "Size",           f"{report['size_bytes']:,} bytes").pack(fill="x", padx=10, pady=2)
        KVRow(stats, "Analyzed",       f"{report['analyzed_bytes']:,} bytes").pack(fill="x", padx=10, pady=2)
        KVRow(stats, "Entropy",        f"{report['sample_entropy']:.4f} bits/byte").pack(fill="x", padx=10, pady=2)
        KVRow(stats, "Chi-square",     f"{report['chi_square']:.2f}").pack(fill="x", padx=10, pady=2)
        KVRow(stats, "Printable ratio",f"{report['printable_ratio']:.4f}").pack(fill="x", padx=10, pady=2)

        # ── Verdict ───────────────────────────────────────────────────
        verdict = summarize_verdict(report["detections"])
        if verdict:
            SectionHeader(self._scroll, "Verdict").pack(**pad)
            v_frame = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
            v_frame.pack(**pad)
            ctk.CTkLabel(v_frame, text=verdict, font=("Segoe UI", 12),
                         text_color=FG_MAIN, anchor="w", wraplength=820,
                         justify="left").pack(padx=16, pady=10, fill="x")

        # ── Encryption details ────────────────────────────────────────
        enc_details = summarize_encryption_details(report["detections"])
        if enc_details:
            SectionHeader(self._scroll, "Encryption Details").pack(**pad)
            enc_frame = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
            enc_frame.pack(**pad)
            for key, value in enc_details:
                KVRow(enc_frame, key, value, mono=True).pack(fill="x", padx=10, pady=2)

        # ── Algorithm summary ─────────────────────────────────────────
        algo_summary = summarize_algorithms(report["detections"])
        if algo_summary:
            SectionHeader(self._scroll, "Algorithm Summary").pack(**pad)
            algo_frame = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
            algo_frame.pack(**pad)
            for item in algo_summary:
                ctk.CTkLabel(algo_frame, text=f"•  {item}", font=FONT_VALUE,
                             text_color=FG_MAIN, anchor="w"
                             ).pack(padx=16, pady=3, fill="x")

        # ── Format matches ────────────────────────────────────────────
        SectionHeader(self._scroll, "Format Matches").pack(**pad)
        if report["detections"]:
            for det in report["detections"]:
                DetectionCard(self._scroll, det).pack(**pad)
        else:
            ctk.CTkLabel(self._scroll, text="No known format matched.",
                         font=FONT_VALUE, text_color=FG_DIM).pack(padx=16, pady=4)

        # ── Heuristics ────────────────────────────────────────────────
        if report.get("heuristics"):
            SectionHeader(self._scroll, "Heuristics").pack(**pad)
            for det in report["heuristics"]:
                DetectionCard(self._scroll, det).pack(**pad)

        # ── Sidecar hints ─────────────────────────────────────────────
        if report.get("sidecar_hints"):
            SectionHeader(self._scroll, "Sidecar Hints").pack(**pad)
            for det in report["sidecar_hints"]:
                DetectionCard(self._scroll, det).pack(**pad)

        # ── Analysis guidance ─────────────────────────────────────────
        guidance = build_analysis_guidance(report)
        if guidance:
            SectionHeader(self._scroll, "Analysis Guidance").pack(**pad)
            g_frame = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
            g_frame.pack(**pad)
            for item in guidance:
                ctk.CTkLabel(g_frame, text=f"•  {item}", font=FONT_VALUE,
                             text_color=FG_MAIN, anchor="w", wraplength=820,
                             justify="left").pack(padx=16, pady=3, fill="x")

        # ── Notes ─────────────────────────────────────────────────────
        if report.get("notes"):
            SectionHeader(self._scroll, "Notes").pack(**pad)
            n_frame = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=8)
            n_frame.pack(**pad)
            for note in report["notes"]:
                ctk.CTkLabel(n_frame, text=f"•  {note}", font=FONT_VALUE,
                             text_color=FG_DIM, anchor="w", wraplength=820,
                             justify="left").pack(padx=16, pady=3, fill="x")

        # Bottom padding
        ctk.CTkFrame(self._scroll, height=20, fg_color="transparent").pack()

    def _reset_scan_btn(self):
        self._scan_btn.configure(state="normal", text="Scan")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
