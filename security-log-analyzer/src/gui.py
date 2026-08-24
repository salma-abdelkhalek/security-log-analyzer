import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import os

from parser import parse_logs
from detector import detect_attacks
from report import export_json, export_csv

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_PATH = os.path.join(BASE_DIR, "sample_logs", "auth.log")


class LogAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.update_idletasks()
        self.title("SSH Brute-Force Log Analyzer")
        self.geometry("950x650")
        self.results = {}

        self.build_ui()

    def build_ui(self):
        # --- Top bar: file selection ---
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(fill="x", padx=15, pady=15)

        self.file_var = ctk.StringVar(value=DEFAULT_LOG_PATH)
        file_entry = ctk.CTkEntry(top_frame, textvariable=self.file_var, width=500)
        file_entry.pack(side="left", padx=(0, 10))

        browse_btn = ctk.CTkButton(top_frame, text="Browse", width=90, command=self.browse_file)
        browse_btn.pack(side="left", padx=(0, 10))

        run_btn = ctk.CTkButton(top_frame, text="Run Analysis", width=120,
                                 fg_color="#2E7D32", hover_color="#1B5E20",
                                 command=self.run_analysis)
        run_btn.pack(side="left")

        # --- Settings row: threshold / window ---
        settings_frame = ctk.CTkFrame(self)
        settings_frame.pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkLabel(settings_frame, text="Threshold:").pack(side="left", padx=(10, 5))
        self.threshold_var = ctk.StringVar(value="5")
        ctk.CTkEntry(settings_frame, textvariable=self.threshold_var, width=60).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(settings_frame, text="Window (sec):").pack(side="left", padx=(0, 5))
        self.window_var = ctk.StringVar(value="60")
        ctk.CTkEntry(settings_frame, textvariable=self.window_var, width=60).pack(side="left")

        # --- Metric cards ---
        self.metrics_frame = ctk.CTkFrame(self)
        self.metrics_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.total_label = self.make_metric_card(self.metrics_frame, "Total Entries", "0")
        self.flagged_label = self.make_metric_card(self.metrics_frame, "Flagged IPs", "0")
        self.status_label = self.make_metric_card(self.metrics_frame, "Status", "—")

              # --- Tabs: Alerts view + Event Logs view ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.tabview.add("Alerts")
        self.tabview.add("Event Logs")

        # --- Alerts tab content ---
        self.alerts_frame = ctk.CTkScrollableFrame(self.tabview.tab("Alerts"), height=350)
        self.alerts_frame.pack(fill="both", expand=True)

        # --- Event Logs tab content ---
        logs_tab = self.tabview.tab("Event Logs")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white",
                         fieldbackground="#2b2b2b", rowheight=26, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#1f6aa5", foreground="white",
                         font=("Segoe UI", 10, "bold"))

        columns = ("timestamp", "ip", "username", "success")
        self.logs_tree = ttk.Treeview(logs_tab, columns=columns, show="headings")
        headings = {"timestamp": "Timestamp", "ip": "Source IP",
                    "username": "Username", "success": "Result"}
        widths = {"timestamp": 180, "ip": 150, "username": 150, "success": 100}
        for col in columns:
            self.logs_tree.heading(col, text=headings[col])
            self.logs_tree.column(col, width=widths[col])

        scrollbar = ttk.Scrollbar(logs_tab, orient="vertical", command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=scrollbar.set)

        self.logs_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


        # --- Bottom: export buttons + status bar ---
        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkButton(bottom_frame, text="Save as JSON", width=130,
                      command=self.save_json).pack(side="left", padx=(10, 10), pady=10)
        ctk.CTkButton(bottom_frame, text="Save as CSV", width=130,
                      command=self.save_csv).pack(side="left", pady=10)

        self.status_bar = ctk.CTkLabel(bottom_frame, text="Ready.")
        self.status_bar.pack(side="right", padx=15)

    def make_metric_card(self, parent, title, value):
        card = ctk.CTkFrame(parent, corner_radius=10)
        card.pack(side="left", expand=True, fill="both", padx=8, pady=10)
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 12)).pack(pady=(10, 0))
        value_label = ctk.CTkLabel(card, text=value, font=("Segoe UI", 22, "bold"))
        value_label.pack(pady=(0, 10))
        return value_label
    def make_alert_card(self, ip, info, threshold):
        count = info["attempt_count"]

        # Determine severity + color
        if count >= threshold * 3:
            severity, color, icon = "CRITICAL", "#e53935", "🔴"
        elif count >= threshold * 1.5:
            severity, color, icon = "HIGH", "#fb8c00", "🟠"
        else:
            severity, color, icon = "MEDIUM", "#fdd835", "🟡"

        card = ctk.CTkFrame(self.alerts_frame, corner_radius=10, border_width=2, border_color=color)
        card.pack(fill="x", pady=6, padx=4)

        # Left colored strip
        strip = ctk.CTkFrame(card, width=6, fg_color=color, corner_radius=0)
        strip.pack(side="left", fill="y")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=15, pady=10)

        # Top row: severity badge + type + time
        top_row = ctk.CTkFrame(content, fg_color="transparent")
        top_row.pack(fill="x")

        badge = ctk.CTkLabel(top_row, text=f"{icon} {severity}", text_color=color,
                              font=("Segoe UI", 11, "bold"))
        badge.pack(side="left")

        type_label = ctk.CTkLabel(top_row, text="  BRUTE_FORCE", text_color="#9e9e9e",
                                   font=("Segoe UI", 11))
        type_label.pack(side="left")

        time_label = ctk.CTkLabel(top_row, text=info["last_attempt"], text_color="#757575",
                                   font=("Segoe UI", 10))
        time_label.pack(side="right")

        # Headline
        headline = ctk.CTkLabel(
            content,
            text=f"Brute-force attack: {count} failed login attempts detected",
            font=("Segoe UI", 13, "bold"),
            anchor="w", justify="left"
        )
        headline.pack(fill="x", pady=(4, 2))

        # Detail row
        detail = ctk.CTkLabel(
            content,
            text=f"📍 IP: {ip}    👤 Targets: {', '.join(info['usernames'])}    🕒 First seen: {info['first_attempt']}",
            font=("Segoe UI", 11), text_color="#b0b0b0",
            anchor="w", justify="left"
        )
        detail.pack(fill="x")

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log"), ("All files", "*.*")])
        if path:
            self.file_var.set(path)

    def run_analysis(self):
        filepath = self.file_var.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found:\n{filepath}")
            return

        try:
            threshold = int(self.threshold_var.get())
            window = int(self.window_var.get())
        except ValueError:
            messagebox.showerror("Error", "Threshold and window must be numbers.")
            return

        try:
            logs = parse_logs(filepath)
            self.results = detect_attacks(logs, threshold=threshold, window_seconds=window)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed:\n{e}")
            return
                # Populate Event Logs table
        for row in self.logs_tree.get_children():
            self.logs_tree.delete(row)

        for entry in logs:
            result = "✅ Success" if entry["success"] else "❌ Failed"
            self.logs_tree.insert("", "end", values=(
                entry["timestamp"], entry["ip"], entry["username"], result
            ))
        # Update metric cards
        self.total_label.configure(text=str(len(logs)))
        self.flagged_label.configure(text=str(len(self.results)))
        self.status_label.configure(
            text="🚨 Attacks" if self.results else "✅ Clean",
            text_color="#e57373" if self.results else "#81c784"
        )

              # Clear old alert cards
        for widget in self.alerts_frame.winfo_children():
            widget.destroy()

        if not self.results:
            ctk.CTkLabel(self.alerts_frame, text="✅ No suspicious activity detected.",
                         font=("Segoe UI", 13)).pack(pady=20)
        else:
            for ip, info in self.results.items():
                self.make_alert_card(ip, info, threshold)

        self.status_bar.configure(text=f"Analysis complete — {len(self.results)} attack(s) detected.")

    def save_json(self):
        if not self.results:
            messagebox.showwarning("No data", "Run an analysis first.")
            return
        export_json(self.results)
        messagebox.showinfo("Saved", "Report saved as report.json")

    def save_csv(self):
        if not self.results:
            messagebox.showwarning("No data", "Run an analysis first.")
            return
        export_csv(self.results)
        messagebox.showinfo("Saved", "Report saved as report.csv")


if __name__ == "__main__":
    app = LogAnalyzerApp()
    app.mainloop()