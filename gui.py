"""
Phishing Email Analyzer — Modern GUI
Requires: pip install customtkinter
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from analyzer import PhishingAnalyzer


# ── Appearance ────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ───────────────────────────────────
BG_BASE    = "#0d1117"
BG_CARD    = "#161b22"
BG_INPUT   = "#21262d"
BORDER     = "#30363d"
TEXT_PRI   = "#e6edf3"
TEXT_SEC   = "#8b949e"
ACCENT     = "#2f81f7"
ACCENT_HVR = "#388bfd"
CLR_SAFE   = "#3fb950"
CLR_WARN   = "#d29922"
CLR_DANGER = "#f85149"
CLR_HEADER = "#58a6ff"


# ─────────────────────────────────────────────
#  REUSABLE COMPONENTS
# ─────────────────────────────────────────────

def card(parent, **kwargs):
    defaults = dict(fg_color=BG_CARD, corner_radius=12,
                    border_width=1, border_color=BORDER)
    defaults.update(kwargs)
    return ctk.CTkFrame(parent, **defaults)


def section_label(parent, text):
    return ctk.CTkLabel(parent, text=text,
                        font=ctk.CTkFont("Courier New", 11, "bold"),
                        text_color=TEXT_SEC, anchor="w")


# ─────────────────────────────────────────────
#  SCORE RING  (animated canvas arc)
# ─────────────────────────────────────────────

class ScoreRing(tk.Canvas):
    SIZE  = 160
    THICK = 14

    def __init__(self, parent, **kwargs):
        super().__init__(parent, width=self.SIZE, height=self.SIZE,
                         bg=BG_CARD, highlightthickness=0, **kwargs)
        self._score   = 0
        self._current = 0
        self._color   = CLR_SAFE
        self._draw(0)

    def _draw(self, filled_pct):
        self.delete("all")
        pad      = self.THICK + 4
        x0, y0   = pad, pad
        x1, y1   = self.SIZE - pad, self.SIZE - pad
        self.create_arc(x0, y0, x1, y1, start=0, extent=359.9,
                        style="arc", outline=BG_INPUT, width=self.THICK)
        if filled_pct > 0:
            self.create_arc(x0, y0, x1, y1, start=90,
                            extent=-(filled_pct / 100 * 359.9),
                            style="arc", outline=self._color, width=self.THICK)
        cx = cy = self.SIZE // 2
        self.create_text(cx, cy - 10, text=f"{self._score}%",
                         fill=TEXT_PRI, font=("Courier New", 26, "bold"))
        self.create_text(cx, cy + 18, text="RISK SCORE",
                         fill=TEXT_SEC, font=("Courier New", 9))

    def set_score(self, score, color):
        self._score   = score
        self._color   = color
        self._current = 0
        self._animate(score)

    def reset(self):
        self._score = self._current = 0
        self._color = CLR_SAFE
        self._draw(0)

    def _animate(self, target):
        if self._current < target:
            self._current = min(self._current + 2, target)
            self._draw(self._current)
            self.after(12, lambda: self._animate(target))
        else:
            self._draw(target)


# ─────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────

class PhishingAnalyzerGUI(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Phishing Analyzer")
        self.geometry("960x800")
        self.minsize(860, 680)
        self.configure(fg_color=BG_BASE)

        self.analyzer   = PhishingAnalyzer()
        self.vt_key_var = ctk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        self.file_var   = ctk.StringVar()
        self.show_key   = False
        self._analyzing = False

        self.vt_key_var.trace_add("write", lambda *_: self._refresh_vt_pill())
        self._build_ui()

    # ── Build UI ─────────────────────────────

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="  PHISHING ANALYZER",
                     font=ctk.CTkFont("Courier New", 20, "bold"),
                     text_color=CLR_HEADER).pack(side="left", padx=24)

        self.vt_pill = ctk.CTkLabel(header, text="",
                                    font=ctk.CTkFont("Courier New", 10),
                                    corner_radius=8, padx=10, pady=4)
        self.vt_pill.pack(side="right", padx=20)
        self._refresh_vt_pill()

        ctk.CTkFrame(self, height=2, fg_color=ACCENT, corner_radius=0).pack(fill="x")

        # Scrollable body
        body = ctk.CTkScrollableFrame(self, fg_color=BG_BASE,
                                      scrollbar_button_color=BORDER)
        body.pack(fill="both", expand=True, padx=20, pady=16)

        self._build_input_card(body)
        self._build_results_area(body)

        # Footer
        footer = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=44)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        ctk.CTkButton(footer, text="Clear", width=90, height=28,
                      fg_color=BG_INPUT, hover_color=BORDER,
                      text_color=TEXT_SEC, font=ctk.CTkFont("Courier New", 11),
                      corner_radius=6, command=self._clear).pack(side="left", padx=16, pady=8)

        self.status_lbl = ctk.CTkLabel(footer, text="Ready",
                                       font=ctk.CTkFont("Courier New", 10),
                                       text_color=TEXT_SEC)
        self.status_lbl.pack(side="right", padx=16)

    def _build_input_card(self, parent):
        c = card(parent)
        c.pack(fill="x", pady=(0, 14))
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=16)

        # VT key
        section_label(inner, "VIRUSTOTAL API KEY").pack(anchor="w", pady=(0, 6))
        vt_row = ctk.CTkFrame(inner, fg_color="transparent")
        vt_row.pack(fill="x", pady=(0, 14))

        self.vt_entry = ctk.CTkEntry(
            vt_row, textvariable=self.vt_key_var,
            placeholder_text="Paste your VirusTotal API key here...",
            show="*", height=38, fg_color=BG_INPUT, border_color=BORDER,
            text_color=TEXT_PRI, placeholder_text_color=TEXT_SEC,
            font=ctk.CTkFont("Courier New", 12), corner_radius=8)
        self.vt_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.toggle_btn = ctk.CTkButton(
            vt_row, text="Show", width=64, height=38,
            fg_color=BG_INPUT, hover_color=BORDER, text_color=TEXT_SEC,
            font=ctk.CTkFont("Courier New", 11), border_width=1,
            border_color=BORDER, corner_radius=8, command=self._toggle_key)
        self.toggle_btn.pack(side="left", padx=(0, 6))

        ctk.CTkButton(vt_row, text="X", width=38, height=38,
                      fg_color=BG_INPUT, hover_color="#3d1f1f",
                      text_color=CLR_DANGER, font=ctk.CTkFont("Courier New", 13),
                      border_width=1, border_color=BORDER, corner_radius=8,
                      command=lambda: self.vt_key_var.set("")).pack(side="left")

        # Separator
        ctk.CTkFrame(inner, height=1, fg_color=BORDER,
                     corner_radius=0).pack(fill="x", pady=(0, 12))

        # File picker
        section_label(inner, "EMAIL FILE  (.eml or .txt)").pack(anchor="w", pady=(0, 6))
        file_row = ctk.CTkFrame(inner, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, 14))

        self.file_entry = ctk.CTkEntry(
            file_row, textvariable=self.file_var,
            placeholder_text="No file selected...",
            height=38, fg_color=BG_INPUT, border_color=BORDER,
            text_color=TEXT_PRI, placeholder_text_color=TEXT_SEC,
            font=ctk.CTkFont("Courier New", 11), corner_radius=8,
            state="readonly")
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(file_row, text="Browse", width=90, height=38,
                      fg_color=BG_INPUT, hover_color=BORDER,
                      text_color=TEXT_PRI, font=ctk.CTkFont("Courier New", 11),
                      border_width=1, border_color=BORDER, corner_radius=8,
                      command=self._browse).pack(side="left")

        # Analyze button
        self.analyze_btn = ctk.CTkButton(
            inner, text="ANALYZE EMAIL", height=46,
            fg_color=ACCENT, hover_color=ACCENT_HVR,
            text_color="#ffffff", font=ctk.CTkFont("Courier New", 14, "bold"),
            corner_radius=10, command=self._start_analysis)
        self.analyze_btn.pack(fill="x")

    def _build_results_area(self, parent):
        # Score row
        score_row = ctk.CTkFrame(parent, fg_color="transparent")
        score_row.pack(fill="x", pady=(0, 14))

        ring_card = card(score_row, width=200)
        ring_card.pack(side="left", padx=(0, 14), fill="y")
        ring_card.pack_propagate(False)
        self.ring = ScoreRing(ring_card)
        self.ring.pack(padx=20, pady=20)

        verdict_card = card(score_row)
        verdict_card.pack(side="left", fill="both", expand=True)

        self.verdict_lbl = ctk.CTkLabel(
            verdict_card, text="Awaiting analysis...",
            font=ctk.CTkFont("Courier New", 15, "bold"),
            text_color=TEXT_SEC, anchor="w", wraplength=540, justify="left")
        self.verdict_lbl.pack(anchor="w", padx=20, pady=(20, 8))

        self.risk_badge = ctk.CTkLabel(verdict_card, text="",
                                       font=ctk.CTkFont("Courier New", 11, "bold"),
                                       corner_radius=6, padx=12, pady=4)
        self.risk_badge.pack(anchor="w", padx=20, pady=(0, 8))

        self.progress = ctk.CTkProgressBar(verdict_card, height=6, corner_radius=3,
                                           fg_color=BG_INPUT, progress_color=ACCENT)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=20, pady=(4, 12))

        self.spinner_lbl = ctk.CTkLabel(verdict_card, text="",
                                        font=ctk.CTkFont("Courier New", 11),
                                        text_color=TEXT_SEC)
        self.spinner_lbl.pack(anchor="w", padx=20, pady=(0, 16))

        # Results textbox
        results_card = card(parent)
        results_card.pack(fill="both", expand=True, pady=(0, 4))

        section_label(results_card, "DETAILED FINDINGS").pack(
            anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(results_card, height=1, fg_color=BORDER,
                     corner_radius=0).pack(fill="x")

        self.results_box = ctk.CTkTextbox(
            results_card, font=ctk.CTkFont("Courier New", 11),
            fg_color="transparent", text_color=TEXT_PRI,
            corner_radius=0, height=340, wrap="word", activate_scrollbars=True)
        self.results_box.pack(fill="both", expand=True, padx=4, pady=4)

        tw = self.results_box._textbox
        tw.tag_config("danger", foreground=CLR_DANGER)
        tw.tag_config("warn",   foreground=CLR_WARN)
        tw.tag_config("safe",   foreground=CLR_SAFE)
        tw.tag_config("header", foreground=CLR_HEADER,
                      font=("Courier New", 11, "bold"))
        tw.tag_config("dim",    foreground=TEXT_SEC)

        self._write_placeholder()

    # ── Interactions ─────────────────────────

    def _toggle_key(self):
        self.show_key = not self.show_key
        self.vt_entry.configure(show="" if self.show_key else "*")
        self.toggle_btn.configure(text="Hide" if self.show_key else "Show")

    def _refresh_vt_pill(self):
        key = self.vt_key_var.get().strip()
        if key:
            self.vt_pill.configure(text=f"VT ACTIVE  ({len(key)} chars)",
                                   fg_color="#0d2a1a", text_color=CLR_SAFE)
        else:
            self.vt_pill.configure(text="VT INACTIVE",
                                   fg_color="#2a1010", text_color=CLR_DANGER)

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Email / Text files", "*.eml *.txt"), ("All files", "*.*")])
        if path:
            self.file_var.set(path)
            self.status_lbl.configure(text=f"Loaded: {os.path.basename(path)}")

    def _start_analysis(self):
        if self._analyzing:
            return
        filepath = self.file_var.get().strip()
        if not filepath:
            messagebox.showwarning("No File", "Please select an email file first.")
            return
        if not os.path.exists(filepath):
            messagebox.showerror("Not Found", f"File not found:\n{filepath}")
            return

        self._analyzing = True
        self.analyze_btn.configure(state="disabled", text="Analyzing...")
        self.status_lbl.configure(text="Running analysis...")
        self._spinner_tick(0)
        threading.Thread(target=self._run_analysis,
                         args=(filepath,), daemon=True).start()

    def _run_analysis(self, filepath):
        self.analyzer.vt_api_key = self.vt_key_var.get().strip()
        try:
            result = self.analyzer.analyze_file(filepath)
            self.after(0, lambda: self._show_results(result))
        except Exception as exc:
            self.after(0, lambda: self._show_error(str(exc)))

    def _spinner_tick(self, frame):
        frames = ["|", "/", "-", "\\"]
        if self._analyzing:
            self.spinner_lbl.configure(
                text=f"{frames[frame % 4]}  Scanning domains and analyzing content...")
            self.after(120, lambda: self._spinner_tick(frame + 1))
        else:
            self.spinner_lbl.configure(text="")

    # ── Results display ──────────────────────

    def _show_results(self, result):
        self._analyzing = False
        self.analyze_btn.configure(state="normal", text="ANALYZE EMAIL")

        score      = result["score"]
        risk_level = result["risk_level"]

        if risk_level == "MALICIOUS":
            color      = CLR_DANGER
            verdict_tx = "PHISHING DETECTED  —  Do NOT interact with this email."
            badge_bg   = "#2a0d0d"
            pb_color   = CLR_DANGER
        elif risk_level == "SUSPICIOUS":
            color      = CLR_WARN
            verdict_tx = "Suspicious signals detected  —  verify before acting."
            badge_bg   = "#2a1e00"
            pb_color   = CLR_WARN
        else:
            color      = CLR_SAFE
            verdict_tx = "No significant phishing indicators detected."
            badge_bg   = "#0d2a1a"
            pb_color   = CLR_SAFE

        self.ring.set_score(score, color)
        self.verdict_lbl.configure(text=verdict_tx, text_color=color)
        self.risk_badge.configure(text=f"  {risk_level}  ",
                                  fg_color=badge_bg, text_color=color)
        self.progress.configure(progress_color=pb_color)
        self.progress.set(score / 100)
        self.status_lbl.configure(
            text=f"Done  |  {os.path.basename(self.file_var.get())}  |  {risk_level}  |  {score}%")

        self._write_findings(result)

        if risk_level == "MALICIOUS":
            messagebox.showwarning(
                "HIGH RISK DETECTED",
                f"Score: {score}/99  |  MALICIOUS\n\n"
                "Do NOT click links, reply, or provide any information.\n"
                "Report and delete immediately.")

    def _show_error(self, msg):
        self._analyzing = False
        self.analyze_btn.configure(state="normal", text="ANALYZE EMAIL")
        self.status_lbl.configure(text="Error")
        messagebox.showerror("Analysis Error", f"Something went wrong:\n\n{msg}")

    def _write_findings(self, result):
        box = self.results_box
        tw  = box._textbox

        box.configure(state="normal")
        box.delete("1.0", "end")

        def w(text, tag=None):
            box.insert("end", text)
            if tag:
                last = int(tw.index("end-1c").split(".")[0])
                tw.tag_add(tag, f"{last}.0", f"{last}.end")

        def line(char="-", n=72):
            w(char * n + "\n", "dim")

        w("  SUMMARY\n", "header")
        line()
        w(f"  Sender       : {result['sender'] or 'N/A'}\n")
        w(f"  Total URLs   : {result['url_count']}\n")
        w(f"  Flagged URLs : {result['suspicious_url_count']}\n")
        rl = result["risk_level"]
        rtag = {"MALICIOUS": "danger", "SUSPICIOUS": "warn", "BENIGN": "safe"}[rl]
        w(f"  Risk Score   : {result['score']}%\n")
        w(f"  Classification: {rl}\n", rtag)
        w("\n")

        if result["details"]:
            w("  DETAILED FINDINGS\n", "header")
            line()
            for detail in result["details"]:
                if "🚨" in detail:
                    w(f"  {detail}\n", "danger")
                elif "⚠️" in detail:
                    w(f"  {detail}\n", "warn")
                else:
                    w(f"  {detail}\n", "dim")
            w("\n")

        w("  RECOMMENDED ACTIONS\n", "header")
        line()
        for rec in result["recommendations"]:
            if rec.startswith("🚨"):
                w(f"  {rec}\n", "danger")
            elif rec.startswith("⚠️"):
                w(f"  {rec}\n", "warn")
            elif rec.startswith("✓"):
                w(f"  {rec}\n", "safe")
            else:
                w(f"  {rec}\n")

        w("\n")
        line("=")
        box.configure(state="disabled")

    def _write_placeholder(self):
        box = self.results_box
        tw  = box._textbox
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", "\n  Select an email file and click ANALYZE EMAIL to begin.\n\n")
        box.insert("end", "  This tool scans for:\n\n")
        items = [
            "  >  Suspicious and malicious URLs via VirusTotal",
            "  >  Sender spoofing  (SPF / DKIM / Reply-To mismatches)",
            "  >  Brand impersonation in domain names",
            "  >  Urgent and phishing language patterns",
            "  >  Typosquatting and homoglyph characters",
        ]
        for item in items:
            box.insert("end", item + "\n")
            last = int(tw.index("end-1c").split(".")[0])
            tw.tag_add("dim", f"{last}.0", f"{last}.end")
        box.configure(state="disabled")

    def _clear(self):
        self.file_var.set("")
        self.ring.reset()
        self.verdict_lbl.configure(text="Awaiting analysis...", text_color=TEXT_SEC)
        self.risk_badge.configure(text="", fg_color="transparent")
        self.progress.set(0)
        self.progress.configure(progress_color=ACCENT)
        self.status_lbl.configure(text="Ready")
        self._write_placeholder()


# ─────────────────────────────────────────────

def main():
    app = PhishingAnalyzerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
