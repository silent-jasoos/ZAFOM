# -*- coding: utf-8 -*-
"""
===========================================
ZAFOM - Zee's Analyzer For Online Monitoring
Module: User Interface
Author: Zeeshan
Version: 2.1
===========================================
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Toplevel
from engine import PacketEngine


class ZAFOMInterface:
    """Main GUI interface for ZAFOM."""
    
    # Color scheme - Dark theme with yellow highlights
    BG = "#0b0b0b"
    PANEL = "#111111"
    TEXT = "#e6e6e6"
    ACCENT = "#2b2b2b"
    HIGHLIGHT = "#1f1f1f"
    BANNER_COLOR = "#FFD700"
    BUTTON_BG = "#1a1a1a"
    BUTTON_ACTIVE = "#2d2d2d"
    
    # Protocol colors
    PROTOCOL_COLORS = {
        "TCP": "#4CAF50",
        "UDP": "#2196F3",
        "DNS": "#9C27B0",
        "ICMP": "#FF9800",
        "ARP": "#F44336",
        "OTHER": "#607D8B"
    }
    
    def __init__(self, root):
        self.root = root
        self.search_results = []
        self.current_search_index = 0
        self.stats_window = None
        
        self.setup_window()
        self.create_widgets()
        
        # Initialize engine AFTER widgets are created
        self.engine = PacketEngine(error_callback=self.show_error)
        
        # Set up clean shutdown
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start GUI update loop
        self.update_gui()
    
    def setup_window(self):
        """Configure main window."""
        self.root.title("ZAFOM - Zee's Analyzer For Online Monitoring v2.1")
        self.root.geometry("1400x900")
        self.root.configure(bg=self.BG)
        self.root.minsize(1200, 700)
    
    def create_widgets(self):
        """Create all GUI widgets."""
        self._create_header()
        self._create_control_panel()
        self._create_search_panel()
        self._create_packet_table()
        self._create_details_panel()
        self._create_hex_panel()
        self._create_statusbar()
    
    def _create_header(self):
        """Create header with branding."""
        header = tk.Frame(self.root, bg="#000000", height=70)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(header, text="ZAFOM - Zee's Analyzer For Online Monitoring",
                        bg="#000000", fg=self.BANNER_COLOR, font=("Consolas", 20, "bold"))
        title.pack(side="left", padx=20, pady=15)
        
        version = tk.Label(header, text="v2.1 | by Zeeshan",
                          bg="#000000", fg=self.TEXT, font=("Consolas", 10))
        version.pack(side="right", padx=20, pady=15)
    
    def _create_control_panel(self):
        """Create control panel with buttons and filters."""
        control = tk.Frame(self.root, bg=self.PANEL, height=60)
        control.pack(fill="x", padx=5, pady=5)
        control.pack_propagate(False)
        
        left_frame = tk.Frame(control, bg=self.PANEL)
        left_frame.pack(side="left", padx=10, pady=10)
        
        self.start_btn = tk.Button(left_frame, text="▶ Start", command=self.start_capture,
                                   bg=self.BUTTON_BG, fg=self.BANNER_COLOR, 
                                   font=("Consolas", 10, "bold"), relief="flat", 
                                   padx=12, pady=5, cursor="hand2")
        self.start_btn.pack(side="left", padx=3)
        
        self.pause_btn = tk.Button(left_frame, text="⏸ Pause", command=self.pause_capture,
                                   bg=self.BUTTON_BG, fg="#FFA726", 
                                   font=("Consolas", 10, "bold"), relief="flat",
                                   padx=12, pady=5, cursor="hand2", state="disabled")
        self.pause_btn.pack(side="left", padx=3)
        
        self.stop_btn = tk.Button(left_frame, text="■ Stop", command=self.stop_capture,
                                 bg=self.BUTTON_BG, fg="#ff6b6b",
                                 font=("Consolas", 10, "bold"), relief="flat",
                                 padx=12, pady=5, cursor="hand2", state="disabled")
        self.stop_btn.pack(side="left", padx=3)
        
        tk.Button(left_frame, text="🗑 Clear", command=self.clear_packets,
                 bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 10),
                 relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left", padx=3)
        
        tk.Button(left_frame, text="📊 Stats", command=self.show_statistics,
                 bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 10),
                 relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left", padx=3)
        
        middle_frame = tk.Frame(control, bg=self.PANEL)
        middle_frame.pack(side="left", padx=20, pady=10)
        
        tk.Label(middle_frame, text="Protocol:", bg=self.PANEL, fg=self.TEXT,
                font=("Consolas", 9)).pack(side="left", padx=5)
        
        self.protocol_var = tk.StringVar(value="ALL")
        protocol_combo = ttk.Combobox(middle_frame, textvariable=self.protocol_var,
                                     values=["ALL", "TCP", "UDP", "DNS", "ICMP", "ARP"],
                                     state="readonly", width=8, font=("Consolas", 9))
        protocol_combo.pack(side="left", padx=5)
        protocol_combo.bind("<<ComboboxSelected>>", self.apply_filters)
        
        tk.Label(middle_frame, text="Port:", bg=self.PANEL, fg=self.TEXT,
                font=("Consolas", 9)).pack(side="left", padx=5)
        
        self.port_entry = tk.Entry(middle_frame, width=8, bg=self.BUTTON_BG,
                                   fg=self.TEXT, font=("Consolas", 9), relief="flat")
        self.port_entry.pack(side="left", padx=5)
        self.port_entry.bind("<Return>", self.apply_filters)
        
        tk.Button(middle_frame, text="Apply", command=self.apply_filters,
                 bg=self.BUTTON_BG, fg=self.BANNER_COLOR, font=("Consolas", 9),
                 relief="flat", padx=10, pady=2, cursor="hand2").pack(side="left", padx=5)
        
        right_frame = tk.Frame(control, bg=self.PANEL)
        right_frame.pack(side="right", padx=10, pady=10)
        
        for fmt in ["pcap", "json", "txt"]:
            tk.Button(right_frame, text=fmt.upper(), 
                     command=lambda f=fmt: self.export_packets(f),
                     bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 9),
                     relief="flat", padx=10, pady=5, cursor="hand2").pack(side="left", padx=2)
    
    def _create_search_panel(self):
        """Create search panel."""
        search_frame = tk.Frame(self.root, bg=self.PANEL, height=40)
        search_frame.pack(fill="x", padx=5, pady=2)
        search_frame.pack_propagate(False)
        
        tk.Label(search_frame, text="🔍 Search:", bg=self.PANEL, fg=self.TEXT,
                font=("Consolas", 9)).pack(side="left", padx=10)
        
        self.search_entry = tk.Entry(search_frame, width=30, bg=self.BUTTON_BG,
                                     fg=self.TEXT, font=("Consolas", 9), relief="flat")
        self.search_entry.pack(side="left", padx=5)
        self.search_entry.bind("<Return>", lambda e: self.search_packets())
        
        tk.Button(search_frame, text="Search", command=self.search_packets,
                 bg=self.BUTTON_BG, fg=self.BANNER_COLOR, font=("Consolas", 9),
                 relief="flat", padx=10, pady=2, cursor="hand2").pack(side="left", padx=5)
        
        self.search_result_label = tk.Label(search_frame, text="", bg=self.PANEL,
                                            fg=self.TEXT, font=("Consolas", 9))
        self.search_result_label.pack(side="left", padx=10)
        
        self.prev_btn = tk.Button(search_frame, text="◀ Prev", command=self.prev_result,
                                 bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 8),
                                 relief="flat", padx=8, pady=2, cursor="hand2", state="disabled")
        self.prev_btn.pack(side="left", padx=2)
        
        self.next_btn = tk.Button(search_frame, text="Next ▶", command=self.next_result,
                                 bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 8),
                                 relief="flat", padx=8, pady=2, cursor="hand2", state="disabled")
        self.next_btn.pack(side="left", padx=2)
    
    def _create_packet_table(self):
        """Create packet table view."""
        table_frame = tk.Frame(self.root, bg=self.PANEL)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        tk.Label(table_frame, text="📦 Captured Packets", bg=self.PANEL,
                fg=self.BANNER_COLOR, font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=5)
        
        tree_container = tk.Frame(table_frame, bg=self.PANEL)
        tree_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=self.PANEL, foreground=self.TEXT,
                       fieldbackground=self.PANEL, rowheight=26, borderwidth=0)
        style.map("Treeview", background=[("selected", self.HIGHLIGHT)],
                 foreground=[("selected", self.BANNER_COLOR)])
        style.configure("Treeview.Heading", background=self.ACCENT,
                       foreground=self.BANNER_COLOR, font=("Consolas", 9, "bold"))
        
        self.packet_table = ttk.Treeview(tree_container, columns=columns,
                                        show="headings", selectmode="browse")
        
        widths = [50, 80, 150, 150, 80, 80, 400]
        for col, width in zip(columns, widths):
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=width, anchor="center" if width <= 80 else "w")
        
        scrollbar = ttk.Scrollbar(tree_container, orient="vertical",
                                 command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)
        
        self.packet_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.packet_table.bind("<<TreeviewSelect>>", self.on_packet_select)
        
        for proto, color in self.PROTOCOL_COLORS.items():
            self.packet_table.tag_configure(proto, foreground=color)
    
    def _create_details_panel(self):
        """Create packet details panel."""
        details_frame = tk.Frame(self.root, bg=self.PANEL)
        details_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        tk.Label(details_frame, text="📋 Packet Details", bg=self.PANEL,
                fg=self.BANNER_COLOR, font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=5)
        
        text_container = tk.Frame(details_frame, bg=self.PANEL)
        text_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.details_box = tk.Text(text_container, bg=self.BG, fg=self.TEXT,
                                   font=("Consolas", 9), wrap="none", height=8)
        
        v_scroll = ttk.Scrollbar(text_container, orient="vertical", command=self.details_box.yview)
        h_scroll = ttk.Scrollbar(text_container, orient="horizontal", command=self.details_box.xview)
        self.details_box.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.details_box.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        text_container.grid_rowconfigure(0, weight=1)
        text_container.grid_columnconfigure(0, weight=1)
    
    def _create_hex_panel(self):
        """Create HEX dump panel."""
        hex_frame = tk.Frame(self.root, bg=self.PANEL)
        hex_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        tk.Label(hex_frame, text="🔢 Raw Packet Data (HEX)", bg=self.PANEL,
                fg=self.BANNER_COLOR, font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=5)
        
        text_container = tk.Frame(hex_frame, bg=self.PANEL)
        text_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.hex_box = tk.Text(text_container, bg=self.BG, fg="#4CAF50",
                              font=("Consolas", 9), wrap="none", height=8)
        
        v_scroll = ttk.Scrollbar(text_container, orient="vertical", command=self.hex_box.yview)
        h_scroll = ttk.Scrollbar(text_container, orient="horizontal", command=self.hex_box.xview)
        self.hex_box.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.hex_box.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        text_container.grid_rowconfigure(0, weight=1)
        text_container.grid_columnconfigure(0, weight=1)
    
    def _create_statusbar(self):
        """Create status bar."""
        statusbar = tk.Frame(self.root, bg=self.ACCENT, height=25)
        statusbar.pack(fill="x", side="bottom")
        statusbar.pack_propagate(False)
        
        self.status_label = tk.Label(statusbar, text="Ready", bg=self.ACCENT,
                                     fg=self.TEXT, font=("Consolas", 9), anchor="w")
        self.status_label.pack(side="left", padx=10)
        
        self.packet_count_label = tk.Label(statusbar, text="Packets: 0", bg=self.ACCENT,
                                           fg=self.BANNER_COLOR, font=("Consolas", 9, "bold"), anchor="e")
        self.packet_count_label.pack(side="right", padx=10)
    
    def start_capture(self):
        """Start packet capture."""
        if self.engine.start_capture():
            self.start_btn.config(state="disabled")
            self.pause_btn.config(state="normal")
            self.stop_btn.config(state="normal")
            self.status_label.config(text="⚡ Capturing packets...", fg="#4CAF50")
    
    def pause_capture(self):
        """Pause packet capture."""
        if self.engine.is_paused:
            if self.engine.resume_capture():
                self.pause_btn.config(text="⏸ Pause")
                self.status_label.config(text="⚡ Capturing packets...", fg="#4CAF50")
        else:
            if self.engine.pause_capture():
                self.pause_btn.config(text="▶ Resume")
                self.status_label.config(text="⏸ Capture paused", fg="#FFA726")
    
    def stop_capture(self):
        """Stop packet capture."""
        if self.engine.stop_capture():
            self.start_btn.config(state="normal")
            self.pause_btn.config(state="disabled", text="⏸ Pause")
            self.stop_btn.config(state="disabled")
            self.status_label.config(text="■ Capture stopped", fg="#ff6b6b")
    
    def clear_packets(self):
        """Clear all captured packets."""
        self.engine.clear_packets()
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)
        self.details_box.delete("1.0", tk.END)
        self.hex_box.delete("1.0", tk.END)
        self.packet_count_label.config(text="Packets: 0")
        self.search_results = []
        self.current_search_index = 0
        self.search_result_label.config(text="")
        self.prev_btn.config(state="disabled")
        self.next_btn.config(state="disabled")
        self.status_label.config(text="🗑 Packets cleared", fg=self.TEXT)
    
    def apply_filters(self, event=None):
        """Apply protocol and port filters."""
        protocol = self.protocol_var.get()
        port = self.port_entry.get().strip()
        if self.engine.set_filter(protocol, port):
            filter_text = f"Filter: {protocol}"
            if port:
                filter_text += f" | Port: {port}"
            self.status_label.config(text=filter_text, fg=self.BANNER_COLOR)
    
    def search_packets(self):
        """Search packets."""
        search_term = self.search_entry.get().strip()
        if not search_term:
            return
        self.search_results = self.engine.search_packets(search_term)
        if self.search_results:
            self.current_search_index = 0
            self.search_result_label.config(text=f"Found {len(self.search_results)} results")
            self.highlight_search_result()
            self.prev_btn.config(state="normal" if len(self.search_results) > 1 else "disabled")
            self.next_btn.config(state="normal" if len(self.search_results) > 1 else "disabled")
        else:
            self.search_result_label.config(text="No results found")
            self.prev_btn.config(state="disabled")
            self.next_btn.config(state="disabled")
    
    def prev_result(self):
        """Navigate to previous search result."""
        if self.search_results and self.current_search_index > 0:
            self.current_search_index -= 1
            self.highlight_search_result()
    
    def next_result(self):
        """Navigate to next search result."""
        if self.search_results and self.current_search_index < len(self.search_results) - 1:
            self.current_search_index += 1
            self.highlight_search_result()
    
    def highlight_search_result(self):
        """Highlight and scroll to current search result."""
        if not self.search_results:
            return
        packet_index = self.search_results[self.current_search_index]
        packet_num = packet_index + 1
        for item in self.packet_table.get_children():
            values = self.packet_table.item(item)["values"]
            if int(values[0]) == packet_num:
                self.packet_table.selection_set(item)
                self.packet_table.see(item)
                self.search_result_label.config(
                    text=f"Result {self.current_search_index + 1} of {len(self.search_results)}")
                break
    
    def show_statistics(self):
        """Show capture statistics window."""
        if self.stats_window and tk.Toplevel.winfo_exists(self.stats_window):
            self.stats_window.lift()
            return
        stats = self.engine.get_statistics()
        self.stats_window = Toplevel(self.root)
        self.stats_window.title("Capture Statistics")
        self.stats_window.geometry("500x400")
        self.stats_window.configure(bg=self.BG)
        tk.Label(self.stats_window, text="📊 Capture Statistics", bg=self.BG,
                fg=self.BANNER_COLOR, font=("Consolas", 16, "bold")).pack(pady=20)
        stats_frame = tk.Frame(self.stats_window, bg=self.PANEL)
        stats_frame.pack(fill="both", expand=True, padx=20, pady=10)
        general = tk.LabelFrame(stats_frame, text="General", bg=self.PANEL,
                               fg=self.BANNER_COLOR, font=("Consolas", 11, "bold"))
        general.pack(fill="x", padx=10, pady=10)
        for key, label in [("total_packets", "Total Packets"), ("total_bytes", "Total Bytes"),
                          ("duration", "Duration"), ("packets_per_second", "Packets/sec"),
                          ("bytes_per_second", "Bytes/sec")]:
            val = stats[key]
            text = f"{label}: {val:,}" if key == "total_bytes" else f"{label}: {val:.2f}" if isinstance(val, float) else f"{label}: {val}"
            tk.Label(general, text=text, bg=self.PANEL, fg=self.TEXT,
                    font=("Consolas", 10)).pack(anchor="w", padx=10, pady=3)
        protocol = tk.LabelFrame(stats_frame, text="Protocol Breakdown", bg=self.PANEL,
                                fg=self.BANNER_COLOR, font=("Consolas", 11, "bold"))
        protocol.pack(fill="x", padx=10, pady=10)
        for proto, count in sorted(stats['protocol_breakdown'].items(), key=lambda x: x[1], reverse=True):
            color = self.PROTOCOL_COLORS.get(proto, self.TEXT)
            tk.Label(protocol, text=f"{proto}: {count} packets", bg=self.PANEL,
                    fg=color, font=("Consolas", 10)).pack(anchor="w", padx=10, pady=3)
        tk.Button(self.stats_window, text="Close", command=self.stats_window.destroy,
                 bg=self.BUTTON_BG, fg=self.TEXT, font=("Consolas", 10),
                 relief="flat", padx=20, pady=5, cursor="hand2").pack(pady=10)
    
    def on_packet_select(self, event):
        """Handle packet selection in table."""
        selected = self.packet_table.focus()
        if not selected:
            return
        try:
            values = self.packet_table.item(selected)["values"]
            packet_num = int(values[0])
            index = packet_num - 1
            self.details_box.delete("1.0", tk.END)
            details = self.engine.get_packet_details(index)
            self.details_box.insert(tk.END, details)
            self.hex_box.delete("1.0", tk.END)
            hex_data = self.engine.get_packet_hex(index)
            self.hex_box.insert(tk.END, hex_data)
        except Exception as e:
            print(f"Selection error: {e}")
    
    def export_packets(self, format_type):
        """Export captured packets to file."""
        if self.engine.packet_count == 0:
            messagebox.showwarning("No Data", "No packets captured to export!")
            return
        extensions = {
            "pcap": [("PCAP files", "*.pcap"), ("All files", "*.*")],
            "json": [("JSON files", "*.json"), ("All files", "*.*")],
            "txt": [("Text files", "*.txt"), ("All files", "*.*")]
        }
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=extensions.get(format_type, [("All files", "*.*")]))
        if filename:
            if format_type == "pcap":
                success, msg = self.engine.export_pcap(filename)
            elif format_type == "json":
                success, msg = self.engine.export_json(filename)
            elif format_type == "txt":
                success, msg = self.engine.export_txt(filename)
            else:
                return
            if success:
                messagebox.showinfo("Export Successful", msg)
                self.status_label.config(text=f"✓ {msg}", fg="#4CAF50")
            else:
                messagebox.showerror("Export Failed", msg)
                self.status_label.config(text=f"✗ {msg}", fg="#ff6b6b")
    
    def show_error(self, message):
        """Display error message to user."""
        try:
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"✗ {message}", fg="#ff6b6b")
            messagebox.showerror("Error", message)
            if hasattr(self, 'start_btn'):
                self.start_btn.config(state="normal")
            if hasattr(self, 'pause_btn'):
                self.pause_btn.config(state="disabled")
            if hasattr(self, 'stop_btn'):
                self.stop_btn.config(state="disabled")
        except Exception as e:
            print(f"Error displaying error message: {e}")
    
    def on_closing(self):
        """Clean shutdown handler."""
        if self.engine.is_sniffing:
            self.engine.stop_capture()
        self.root.destroy()
    
    def update_gui(self):
        """Thread-safe GUI update loop."""
        try:
            packet_data = self.engine.get_next_packet()
            if packet_data:
                protocol = packet_data["protocol"]
                self.packet_table.insert("", "end", values=(
                    packet_data["number"], packet_data["time"], packet_data["source"],
                    packet_data["destination"], protocol, packet_data["length"],
                    packet_data["info"]), tags=(protocol,))
                children = self.packet_table.get_children()
                if children:
                    self.packet_table.see(children[-1])
                self.packet_count_label.config(text=f"Packets: {self.engine.packet_count}")
        except Exception as e:
            print(f"GUI update error: {e}")
        delay = 50 if self.engine.is_sniffing and not self.engine.is_paused else 200
        self.root.after(delay, self.update_gui)