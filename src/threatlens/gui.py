"""Tkinter interface for the local ThreatLens Desktop workflow."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from tkinter import Tk, filedialog, messagebox, ttk
from tkinter import StringVar, Text

from threatlens.exporters import write_report
from threatlens.models import AnalysisReport
from threatlens.service import AnalysisService


class ThreatLensApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("ThreatLens Desktop")
        self.root.geometry("1180x760")
        self.root.minsize(900, 620)
        self.service = AnalysisService()
        self.report: AnalysisReport | None = None
        self.mode = StringVar(value="file")
        self.target = StringVar()
        self.status = StringVar(value="Ready. Analysis is static and local-first.")
        self._configure_style()
        self._build()
        self._load_history()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        self.root.configure(bg="#0a101b")
        style.configure("TFrame", background="#0a101b")
        style.configure("Panel.TFrame", background="#111c2e")
        style.configure("TLabel", background="#0a101b", foreground="#dce8f5")
        style.configure("Panel.TLabel", background="#111c2e", foreground="#dce8f5")
        style.configure("Title.TLabel", background="#0a101b", foreground="#a9dcff", font=("TkDefaultFont", 18, "bold"))
        style.configure("Risk.TLabel", background="#111c2e", foreground="#ffd166", font=("TkDefaultFont", 22, "bold"))
        style.configure("TButton", background="#1e5a89", foreground="#ffffff", padding=(10, 7))
        style.map("TButton", background=[("active", "#2873ad")])
        style.configure("Treeview", background="#111c2e", foreground="#dce8f5", fieldbackground="#111c2e", rowheight=30)
        style.configure("Treeview.Heading", background="#1b324f", foreground="#dce8f5", font=("TkDefaultFont", 10, "bold"))
        style.map("Treeview", background=[("selected", "#245b88")])
        style.configure("TNotebook", background="#0a101b", borderwidth=0)
        style.configure("TNotebook.Tab", background="#14253b", foreground="#b9cce0", padding=(15, 9))
        style.map("TNotebook.Tab", background=[("selected", "#1e5a89")], foreground=[("selected", "#ffffff")])

    def _build(self) -> None:
        top = ttk.Frame(self.root, padding=20)
        top.pack(fill="x")
        ttk.Label(top, text="ThreatLens Desktop", style="Title.TLabel").pack(anchor="w")
        ttk.Label(top, text="Local-first defensive static analysis · Files, URLs and safe reversing", foreground="#93a8bf").pack(anchor="w", pady=(3, 14))

        control = ttk.Frame(top, style="Panel.TFrame", padding=14)
        control.pack(fill="x")
        ttk.Radiobutton(control, text="File", variable=self.mode, value="file", command=self._mode_changed).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(control, text="URL", variable=self.mode, value="url", command=self._mode_changed).grid(row=0, column=1, sticky="w", padx=(10, 18))
        self.target_entry = ttk.Entry(control, textvariable=self.target, width=75)
        self.target_entry.grid(row=0, column=2, sticky="ew")
        self.browse_button = ttk.Button(control, text="Choose file", command=self._browse)
        self.browse_button.grid(row=0, column=3, padx=(10, 0))
        self.analyze_button = ttk.Button(control, text="Analyze safely", command=self._start_analysis)
        self.analyze_button.grid(row=0, column=4, padx=(10, 0))
        control.columnconfigure(2, weight=1)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self._build_overview()
        self._build_findings()
        self._build_metadata()
        self._build_history()

        footer = ttk.Frame(self.root, padding=(20, 0, 20, 16))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, foreground="#93a8bf").pack(side="left")
        ttk.Button(footer, text="Export report", command=self._export).pack(side="right")
        ttk.Label(footer, text="Created and founded by Lumen AI · GitHub: @villatorofidel6-alt · Discord: px1j", foreground="#71879e").pack(side="right", padx=16)

    def _build_overview(self) -> None:
        frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(frame, text="Overview")
        panel = ttk.Frame(frame, style="Panel.TFrame", padding=22)
        panel.pack(fill="x")
        self.risk_label = ttk.Label(panel, text="Risk score: —", style="Risk.TLabel")
        self.risk_label.pack(anchor="w")
        self.target_label = ttk.Label(panel, text="No target analyzed.", style="Panel.TLabel")
        self.target_label.pack(anchor="w", pady=(6, 12))
        self.summary_label = ttk.Label(panel, text="Run a file or URL analysis to review findings.", style="Panel.TLabel", wraplength=900, justify="left")
        self.summary_label.pack(anchor="w")
        limits = ttk.Frame(frame, style="Panel.TFrame", padding=18)
        limits.pack(fill="both", expand=True, pady=(18, 0))
        ttk.Label(limits, text="Safety boundaries", style="Panel.TLabel", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        self.limits_text = Text(limits, height=13, bg="#111c2e", fg="#b9cce0", insertbackground="#b9cce0", relief="flat", wrap="word")
        self.limits_text.pack(fill="both", expand=True, pady=(8, 0))
        self.limits_text.insert("1.0", "ThreatLens does not execute, import, open or decrypt inspected files. URL analysis does not use a browser or JavaScript engine and rejects local/private targets.")
        self.limits_text.configure(state="disabled")

    def _build_findings(self) -> None:
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Findings")
        columns = ("severity", "category", "title", "evidence", "recommendation")
        self.findings = ttk.Treeview(frame, columns=columns, show="headings")
        widths = {"severity": 88, "category": 120, "title": 220, "evidence": 320, "recommendation": 360}
        for column in columns:
            self.findings.heading(column, text=column.title())
            self.findings.column(column, width=widths[column], minwidth=70, stretch=column in {"evidence", "recommendation"})
        ybar = ttk.Scrollbar(frame, orient="vertical", command=self.findings.yview)
        self.findings.configure(yscrollcommand=ybar.set)
        self.findings.pack(side="left", fill="both", expand=True)
        ybar.pack(side="right", fill="y")

    def _build_metadata(self) -> None:
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Metadata")
        self.metadata_text = Text(frame, bg="#111c2e", fg="#dce8f5", insertbackground="#dce8f5", relief="flat", wrap="word")
        self.metadata_text.pack(fill="both", expand=True)
        self.metadata_text.configure(state="disabled")

    def _build_history(self) -> None:
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Local history")
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", pady=(0, 10))
        self.history_query = StringVar()
        ttk.Entry(toolbar, textvariable=self.history_query, width=50).pack(side="left")
        ttk.Button(toolbar, text="Search", command=self._load_history).pack(side="left", padx=8)
        columns = ("timestamp", "type", "target", "sha256", "risk")
        self.history_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in {"timestamp": 190, "type": 80, "target": 300, "sha256": 260, "risk": 70}.items():
            self.history_tree.heading(column, text=column.title())
            self.history_tree.column(column, width=width, stretch=column == "target")
        self.history_tree.pack(fill="both", expand=True)

    def _mode_changed(self) -> None:
        is_file = self.mode.get() == "file"
        self.browse_button.configure(state="normal" if is_file else "disabled")
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, "" if is_file else "https://")

    def _browse(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a file for static analysis")
        if selected:
            self.target.set(selected)

    def _start_analysis(self) -> None:
        value = self.target.get().strip()
        if not value:
            messagebox.showwarning("ThreatLens", "Choose a file or enter a public http(s) URL.")
            return
        self.analyze_button.configure(state="disabled")
        self.status.set("Analyzing safely…")
        threading.Thread(target=self._run_analysis, args=(value, self.mode.get()), daemon=True).start()

    def _run_analysis(self, value: str, mode: str) -> None:
        try:
            report = self.service.analyze_file(value) if mode == "file" else self.service.analyze_url(value)
            self.root.after(0, lambda: self._display_report(report))
        except Exception as exc:
            self.root.after(0, lambda: self._display_error(str(exc)))

    def _display_error(self, message: str) -> None:
        self.analyze_button.configure(state="normal")
        self.status.set("Analysis did not complete.")
        messagebox.showerror("ThreatLens", message)

    def _display_report(self, report: AnalysisReport) -> None:
        self.report = report
        self.analyze_button.configure(state="normal")
        self.status.set(f"Analysis complete · Risk {report.risk_score}/100 · Stored locally")
        self.risk_label.configure(text=f"Risk score: {report.risk_score}/100 · {report.risk_level.upper()}")
        self.target_label.configure(text=f"{report.target_type.upper()} · {report.target}")
        self.summary_label.configure(text=" · ".join(f"{category}: {count}" for category, count in report.category_summary.items()) or "No findings from enabled checks.")
        self.limits_text.configure(state="normal")
        self.limits_text.delete("1.0", "end")
        self.limits_text.insert("1.0", "\n".join(f"• {limit}" for limit in report.analysis_limits))
        self.limits_text.configure(state="disabled")
        self.findings.delete(*self.findings.get_children())
        for finding in report.findings:
            self.findings.insert("", "end", values=(finding.severity.value.upper(), finding.category, finding.title, finding.evidence, finding.recommendation))
        self.metadata_text.configure(state="normal")
        self.metadata_text.delete("1.0", "end")
        self.metadata_text.insert("1.0", json.dumps(report.metadata, indent=2, ensure_ascii=False))
        self.metadata_text.configure(state="disabled")
        self._load_history()
        self.notebook.select(0)

    def _load_history(self) -> None:
        query = getattr(self, "history_query", StringVar()).get()
        if not hasattr(self, "history_tree"):
            return
        self.history_tree.delete(*self.history_tree.get_children())
        for entry in self.service.history.search(query):
            self.history_tree.insert("", "end", values=(entry["analyzed_at"], entry["target_type"], entry["target"], entry["sha256"] or "—", entry["risk_score"]))

    def _export(self) -> None:
        if not self.report:
            messagebox.showwarning("ThreatLens", "Analyze a target before exporting a report.")
            return
        destination = filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("HTML report", "*.html"), ("Text report", "*.txt")],
        )
        if not destination:
            return
        suffix = Path(destination).suffix.lower()
        format_name = {".json": "json", ".html": "html", ".htm": "html", ".txt": "text"}.get(suffix, "json")
        try:
            write_report(self.report, Path(destination), format_name)
            self.status.set(f"Report exported to {destination}")
        except OSError as exc:
            messagebox.showerror("ThreatLens", f"Could not export report: {exc}")


def launch() -> None:
    root = Tk()
    ThreatLensApp(root)
    root.mainloop()
