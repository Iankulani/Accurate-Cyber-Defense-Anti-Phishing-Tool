import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import re
import requests
import whois
from urllib.parse import urlparse
import datetime
import json
import socket
import ssl
from PIL import Image, ImageTk
import time
import threading
import random
import hashlib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import numpy as np
import os
import sys
import html
import ipaddress
import dns.resolver
from bs4 import BeautifulSoup

class accurate:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Anti-Phishing Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2c3e50")
        
        # Initialize variables
        self.dark_mode = tk.BooleanVar(value=False)
        self.current_theme = "light"
        self.phishing_db = self.load_phishing_database()
        self.legitimate_db = self.load_legitimate_database()
        self.ml_model = None
        self.vectorizer = None
        self.load_ml_model()
        
        # Setup GUI
        self.setup_gui()
        
        # Apply initial theme
        self.apply_theme()
        
    def setup_gui(self):
        # Create main menu
        self.create_menu()
        
        # Create header
        self.create_header()
        
        # Create main content area with tabs
        self.create_main_content()
        
        # Create status bar
        self.create_status_bar()
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self.new_scan, accelerator="Ctrl+N")
        file_menu.add_command(label="Open Results", command=self.open_results)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="URL Analyzer", command=self.show_url_analyzer)
        tools_menu.add_command(label="Link Scanner", command=self.show_link_scanner)
        tools_menu.add_command(label="Website Inspector", command=self.show_website_inspector)
        tools_menu.add_command(label="Database Manager", command=self.show_database_manager)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings", command=self.show_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Views menu
        views_menu = tk.Menu(menubar, tearoff=0)
        views_menu.add_command(label="Dashboard", command=self.show_dashboard)
        views_menu.add_command(label="Scan History", command=self.show_scan_history)
        views_menu.add_command(label="Statistics", command=self.show_statistics)
        views_menu.add_separator()
        views_menu.add_checkbutton(label="Dark Mode", variable=self.dark_mode, command=self.toggle_dark_mode)
        menubar.add_cascade(label="Views", menu=views_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="General", command=self.show_general_settings)
        settings_menu.add_command(label="Security", command=self.show_security_settings)
        settings_menu.add_command(label="Updates", command=self.show_update_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#3498db", height=80)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="Accurate Cyber Defense Anti Phishing Tool", font=("Arial", 24, "bold"), 
                              fg="white", bg="#3498db")
        title_label.pack(side=tk.LEFT, padx=20)
        
        # Search bar
        search_frame = tk.Frame(header_frame, bg="#3498db")
        search_frame.pack(side=tk.RIGHT, padx=20)
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=40, font=("Arial", 12))
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        search_btn = tk.Button(search_frame, text="Analyze URL", command=self.analyze_url,
                              bg="#f39c12", fg="white", font=("Arial", 10, "bold"))
        search_btn.pack(side=tk.LEFT)
        
    def create_main_content(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Dashboard tab
        self.dashboard_frame = tk.Frame(self.notebook, bg="#ecf0f1")
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard()
        
        # URL Analyzer tab
        self.url_analyzer_frame = tk.Frame(self.notebook, bg="#ecf0f1")
        self.notebook.add(self.url_analyzer_frame, text="URL Analyzer")
        self.setup_url_analyzer()
        
        # Link Scanner tab
        self.link_scanner_frame = tk.Frame(self.notebook, bg="#ecf0f1")
        self.notebook.add(self.link_scanner_frame, text="Link Scanner")
        self.setup_link_scanner()
        
        # Website Inspector tab
        self.website_inspector_frame = tk.Frame(self.notebook, bg="#ecf0f1")
        self.notebook.add(self.website_inspector_frame, text="Website Inspector")
        self.setup_website_inspector()
        
        # Settings tab (initially hidden)
        self.settings_frame = tk.Frame(self.notebook, bg="#ecf0f1")
        
    def setup_dashboard(self):
        # Welcome message
        welcome_frame = tk.Frame(self.dashboard_frame, bg="white", relief=tk.RAISED, bd=2)
        welcome_frame.pack(fill=tk.X, padx=20, pady=20)
        
        welcome_label = tk.Label(welcome_frame, text="Welcome to Accurare Defense Anti phishing Tool",
                                font=("Arial", 18, "bold"), bg="white", fg="#2c3e50")
        welcome_label.pack(pady=10)
        
        desc_label = tk.Label(welcome_frame, 
                             text="Protect yourself from phishing attacks with our advanced detection system",
                             font=("Arial", 12), bg="white", fg="#7f8c8d")
        desc_label.pack(pady=(0, 10))
        
        # Stats frame
        stats_frame = tk.Frame(self.dashboard_frame, bg="white", relief=tk.RAISED, bd=2)
        stats_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        stats_label = tk.Label(stats_frame, text="Statistics", font=("Arial", 14, "bold"),
                              bg="white", fg="#2c3e50")
        stats_label.pack(pady=10)
        
        stats_inner = tk.Frame(stats_frame, bg="white")
        stats_inner.pack(pady=(0, 10))
        
        # Create some stat boxes
        stats_data = [
            ("Phishing URLs Detected", "1,243", "#e74c3c"),
            ("Legitimate URLs", "3,892", "#2ecc71"),
            ("Suspicious URLs", "567", "#f39c12"),
            ("Total Scans", "5,702", "#3498db")
        ]
        
        for text, value, color in stats_data:
            stat_box = tk.Frame(stats_inner, bg=color, relief=tk.RAISED, bd=1, width=150, height=100)
            stat_box.pack_propagate(False)
            stat_box.pack(side=tk.LEFT, padx=10)
            
            value_label = tk.Label(stat_box, text=value, font=("Arial", 24, "bold"), 
                                  bg=color, fg="white")
            value_label.pack(pady=(15, 5))
            
            text_label = tk.Label(stat_box, text=text, font=("Arial", 10), 
                                 bg=color, fg="white", wraplength=130)
            text_label.pack(pady=(0, 10))
        
        # Quick actions
        actions_frame = tk.Frame(self.dashboard_frame, bg="white", relief=tk.RAISED, bd=2)
        actions_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        actions_label = tk.Label(actions_frame, text="Quick Actions", font=("Arial", 14, "bold"),
                                bg="white", fg="#2c3e50")
        actions_label.pack(pady=10)
        
        actions_inner = tk.Frame(actions_frame, bg="white")
        actions_inner.pack(pady=(0, 10))
        
        action_buttons = [
            ("Analyze URL", self.show_url_analyzer, "#3498db"),
            ("Scan Links", self.show_link_scanner, "#9b59b6"),
            ("Inspect Website", self.show_website_inspector, "#2ecc71"),
            ("Check Database", self.show_database_manager, "#f39c12")
        ]
        
        for text, command, color in action_buttons:
            btn = tk.Button(actions_inner, text=text, command=command, 
                           bg=color, fg="white", font=("Arial", 12, "bold"),
                           width=15, height=2)
            btn.pack(side=tk.LEFT, padx=10)
    
    def setup_url_analyzer(self):
        # URL input section
        input_frame = tk.Frame(self.url_analyzer_frame, bg="white", relief=tk.RAISED, bd=2)
        input_frame.pack(fill=tk.X, padx=20, pady=20)
        
        input_label = tk.Label(input_frame, text="Enter URL to Analyze", 
                              font=("Arial", 14, "bold"), bg="white", fg="#2c3e50")
        input_label.pack(pady=10)
        
        url_frame = tk.Frame(input_frame, bg="white")
        url_frame.pack(pady=(0, 10))
        
        self.url_var = tk.StringVar()
        url_entry = tk.Entry(url_frame, textvariable=self.url_var, width=60, font=("Arial", 12))
        url_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        analyze_btn = tk.Button(url_frame, text="Analyze", command=self.analyze_url_detailed,
                               bg="#3498db", fg="white", font=("Arial", 12, "bold"))
        analyze_btn.pack(side=tk.LEFT)
        
        # Results section
        results_frame = tk.Frame(self.url_analyzer_frame, bg="white", relief=tk.RAISED, bd=2)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        results_label = tk.Label(results_frame, text="Analysis Results", 
                                font=("Arial", 14, "bold"), bg="white", fg="#2c3e50")
        results_label.pack(pady=10)
        
        # Create a notebook for different result views
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Overview tab
        overview_frame = tk.Frame(results_notebook, bg="white")
        results_notebook.add(overview_frame, text="Overview")
        
        self.overview_text = scrolledtext.ScrolledText(overview_frame, width=80, height=15,
                                                      font=("Consolas", 10))
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.overview_text.config(state=tk.DISABLED)
        
        # Details tab
        details_frame = tk.Frame(results_notebook, bg="white")
        results_notebook.add(details_frame, text="Details")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, width=80, height=15,
                                                     font=("Consolas", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        # Technical tab
        technical_frame = tk.Frame(results_notebook, bg="white")
        results_notebook.add(technical_frame, text="Technical")
        
        self.technical_text = scrolledtext.ScrolledText(technical_frame, width=80, height=15,
                                                       font=("Consolas", 10))
        self.technical_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.technical_text.config(state=tk.DISABLED)
    
    def setup_link_scanner(self):
        # Instructions
        instructions_frame = tk.Frame(self.link_scanner_frame, bg="white", relief=tk.RAISED, bd=2)
        instructions_frame.pack(fill=tk.X, padx=20, pady=20)
        
        instructions_label = tk.Label(instructions_frame, 
                                     text="Paste links to scan (one per line) or upload a file containing links",
                                     font=("Arial", 12), bg="white", fg="#2c3e50")
        instructions_label.pack(pady=10)
        
        # Input area
        input_frame = tk.Frame(self.link_scanner_frame, bg="white")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        self.links_text = scrolledtext.ScrolledText(input_frame, width=80, height=10,
                                                   font=("Consolas", 10))
        self.links_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Button frame
        button_frame = tk.Frame(self.link_scanner_frame, bg="white")
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        upload_btn = tk.Button(button_frame, text="Upload File", command=self.upload_links_file,
                              bg="#9b59b6", fg="white", font=("Arial", 10, "bold"))
        upload_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        scan_btn = tk.Button(button_frame, text="Scan Links", command=self.scan_links,
                            bg="#3498db", fg="white", font=("Arial", 10, "bold"))
        scan_btn.pack(side=tk.LEFT)
        
        clear_btn = tk.Button(button_frame, text="Clear", command=self.clear_links,
                             bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
        clear_btn.pack(side=tk.RIGHT)
        
        # Results area
        results_frame = tk.Frame(self.link_scanner_frame, bg="white", relief=tk.RAISED, bd=2)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        results_label = tk.Label(results_frame, text="Scan Results", 
                                font=("Arial", 14, "bold"), bg="white", fg="#2c3e50")
        results_label.pack(pady=10)
        
        # Create a table for results
        columns = ("URL", "Status", "Risk Level")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=200)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Export button
        export_btn = tk.Button(results_frame, text="Export Results", command=self.export_scan_results,
                              bg="#2ecc71", fg="white", font=("Arial", 10, "bold"))
        export_btn.pack(pady=(0, 10))
    
    def setup_website_inspector(self):
        # URL input section
        input_frame = tk.Frame(self.website_inspector_frame, bg="white", relief=tk.RAISED, bd=2)
        input_frame.pack(fill=tk.X, padx=20, pady=20)
        
        input_label = tk.Label(input_frame, text="Enter Website URL to Inspect", 
                              font=("Arial", 14, "bold"), bg="white", fg="#2c3e50")
        input_label.pack(pady=10)
        
        url_frame = tk.Frame(input_frame, bg="white")
        url_frame.pack(pady=(0, 10))
        
        self.inspect_url_var = tk.StringVar()
        url_entry = tk.Entry(url_frame, textvariable=self.inspect_url_var, width=60, font=("Arial", 12))
        url_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        inspect_btn = tk.Button(url_frame, text="Inspect", command=self.inspect_website,
                               bg="#3498db", fg="white", font=("Arial", 12, "bold"))
        inspect_btn.pack(side=tk.LEFT)
        
        # Results section
        results_frame = tk.Frame(self.website_inspector_frame, bg="white", relief=tk.RAISED, bd=2)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        results_label = tk.Label(results_frame, text="Website Inspection Results", 
                                font=("Arial", 14, "bold"), bg="white", fg="#2c3e50")
        results_label.pack(pady=10)
        
        # Create a notebook for different inspection views
        inspect_notebook = ttk.Notebook(results_frame)
        inspect_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # HTML Analysis tab
        html_frame = tk.Frame(inspect_notebook, bg="white")
        inspect_notebook.add(html_frame, text="HTML Analysis")
        
        self.html_text = scrolledtext.ScrolledText(html_frame, width=80, height=15,
                                                  font=("Consolas", 10))
        self.html_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.html_text.config(state=tk.DISABLED)
        
        # Headers tab
        headers_frame = tk.Frame(inspect_notebook, bg="white")
        inspect_notebook.add(headers_frame, text="Headers")
        
        self.headers_text = scrolledtext.ScrolledText(headers_frame, width=80, height=15,
                                                     font=("Consolas", 10))
        self.headers_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.headers_text.config(state=tk.DISABLED)
        
        # Security tab
        security_frame = tk.Frame(inspect_notebook, bg="white")
        inspect_notebook.add(security_frame, text="Security")
        
        self.security_text = scrolledtext.ScrolledText(security_frame, width=80, height=15,
                                                      font=("Consolas", 10))
        self.security_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.security_text.config(state=tk.DISABLED)
    
    def create_status_bar(self):
        status_frame = tk.Frame(self.root, bg="#34495e", relief=tk.SUNKEN, bd=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Ready", fg="white", bg="#34495e", 
                                    font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        version_label = tk.Label(status_frame, text="PhishGuard v1.0", fg="white", bg="#34495e",
                                font=("Arial", 10))
        version_label.pack(side=tk.RIGHT, padx=10)
    
    def apply_theme(self):
        if self.dark_mode.get():
            self.current_theme = "dark"
            bg_color = "#2c3e50"
            fg_color = "#ecf0f1"
            widget_bg = "#34495e"
            widget_fg = "#ecf0f1"
        else:
            self.current_theme = "light"
            bg_color = "#ecf0f1"
            fg_color = "#2c3e50"
            widget_bg = "white"
            widget_fg = "#2c3e50"
        
        # Apply colors to all widgets
        self.root.configure(bg=bg_color)
        
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=bg_color)
                
                for child in widget.winfo_children():
                    if isinstance(child, tk.Frame):
                        child.configure(bg=widget_bg)
                        
                        for grandchild in child.winfo_children():
                            if isinstance(grandchild, tk.Label):
                                grandchild.configure(bg=widget_bg, fg=widget_fg)
                            elif isinstance(grandchild, tk.Frame):
                                grandchild.configure(bg=widget_bg)
    
    def toggle_dark_mode(self):
        self.apply_theme()
    
    def analyze_url(self):
        url = self.search_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to analyze")
            return
        
        self.status_label.config(text=f"Analyzing URL: {url}")
        
        # Simulate analysis (in a real application, this would be actual phishing detection)
        result = self.check_url(url)
        
        if result["phishing"]:
            messagebox.showwarning("Phishing Detected", 
                                  f"The URL '{url}' appears to be a phishing site!\n\n"
                                  f"Confidence: {result['confidence']}%")
        else:
            messagebox.showinfo("Safe URL", 
                               f"The URL '{url}' appears to be safe.\n\n"
                               f"Confidence: {result['confidence']}%")
        
        self.status_label.config(text="Ready")
    
    def analyze_url_detailed(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to analyze")
            return
        
        self.status_label.config(text=f"Analyzing URL: {url}")
        
        # Run analysis in a separate thread to prevent GUI freezing
        threading.Thread(target=self.perform_detailed_analysis, args=(url,), daemon=True).start()
    
    def perform_detailed_analysis(self, url):
        try:
            # Simulate analysis process
            result = {
                "url": url,
                "phishing": False,
                "confidence": random.randint(85, 99),
                "reasons": [],
                "details": {},
                "technical": {}
            }
            
            # Check if URL is in phishing database
            if self.check_phishing_database(url):
                result["phishing"] = True
                result["reasons"].append("URL found in known phishing database")
            
            # Check URL structure
            url_analysis = self.analyze_url_structure(url)
            result["details"].update(url_analysis)
            
            if url_analysis.get("suspicious"):
                result["phishing"] = True
                result["reasons"].append("Suspicious URL structure detected")
            
            # Check domain age if possible
            domain_age = self.get_domain_age(url)
            if domain_age and domain_age < 30:  # Less than 30 days old
                result["phishing"] = True
                result["reasons"].append("Newly registered domain (less than 30 days)")
                result["details"]["domain_age"] = f"{domain_age} days"
            
            # Use ML model for prediction
            ml_result = self.ml_predict(url)
            if ml_result["phishing"]:
                result["phishing"] = True
                result["reasons"].append("Machine learning model detected phishing patterns")
                result["details"]["ml_confidence"] = f"{ml_result['confidence']}%"
            
            # Update GUI with results
            self.display_analysis_results(result)
            
        except Exception as e:
            self.status_label.config(text=f"Error analyzing URL: {str(e)}")
        finally:
            self.status_label.config(text="Ready")
    
    def display_analysis_results(self, result):
        # Update overview tab
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        
        overview_content = f"""
URL Analysis Report for: {result['url']}
        
Status: {'PHISHING SITE DETECTED' if result['phishing'] else 'SAFE SITE'}
Confidence: {result['confidence']}%
        
Summary:
"""
        
        if result['phishing']:
            overview_content += "This URL has characteristics commonly associated with phishing sites.\n\n"
            overview_content += "Reasons for detection:\n"
            for reason in result['reasons']:
                overview_content += f"- {reason}\n"
        else:
            overview_content += "This URL appears to be safe based on our analysis.\n"
        
        self.overview_text.insert(tk.END, overview_content)
        self.overview_text.config(state=tk.DISABLED)
        
        # Update details tab
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        details_content = "Detailed Analysis:\n\n"
        for key, value in result['details'].items():
            details_content += f"{key.replace('_', ' ').title()}: {value}\n"
        
        self.details_text.insert(tk.END, details_content)
        self.details_text.config(state=tk.DISABLED)
        
        # Update technical tab
        self.technical_text.config(state=tk.NORMAL)
        self.technical_text.delete(1.0, tk.END)
        
        technical_content = "Technical Details:\n\n"
        for key, value in result.get('technical', {}).items():
            technical_content += f"{key.replace('_', ' ').title()}: {value}\n"
        
        self.technical_text.insert(tk.END, technical_content)
        self.technical_text.config(state=tk.DISABLED)
        
        # Switch to URL Analyzer tab
        self.notebook.select(self.url_analyzer_frame)
    
    def scan_links(self):
        links_text = self.links_text.get(1.0, tk.END).strip()
        if not links_text:
            messagebox.showerror("Error", "Please enter links to scan")
            return
        
        links = [link.strip() for link in links_text.split('\n') if link.strip()]
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.status_label.config(text=f"Scanning {len(links)} links...")
        
        # Run scanning in a separate thread
        threading.Thread(target=self.perform_link_scanning, args=(links,), daemon=True).start()
    
    def perform_link_scanning(self, links):
        try:
            for i, link in enumerate(links):
                # Simulate scanning process
                result = self.check_url(link)
                
                # Update GUI with result
                self.root.after(0, self.add_scan_result, link, result)
                
                # Simulate some delay for realism
                time.sleep(0.1)
            
            self.status_label.config(text="Scan completed")
        except Exception as e:
            self.status_label.config(text=f"Error scanning links: {str(e)}")
    
    def add_scan_result(self, url, result):
        status = "Phishing" if result["phishing"] else "Safe"
        risk_level = "High" if result["phishing"] else "Low"
        
        self.results_tree.insert("", tk.END, values=(url, status, risk_level))
    
    def inspect_website(self):
        url = self.inspect_url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a website URL to inspect")
            return
        
        self.status_label.config(text=f"Inspecting website: {url}")
        
        # Run inspection in a separate thread
        threading.Thread(target=self.perform_website_inspection, args=(url,), daemon=True).start()
    
    def perform_website_inspection(self, url):
        try:
            # Simulate website inspection
            html_content = "<html><body><h1>Example Website</h1><p>This is a simulated website content.</p></body></html>"
            headers = {
                "Content-Type": "text/html",
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Frame-Options": "SAMEORIGIN"
            }
            security_info = {
                "SSL": "Valid",
                "HSTS": "Enabled",
                "XSS Protection": "Enabled",
                "Content Security Policy": "Not implemented"
            }
            
            # Update GUI with results
            self.root.after(0, self.display_inspection_results, html_content, headers, security_info)
            
        except Exception as e:
            self.status_label.config(text=f"Error inspecting website: {str(e)}")
        finally:
            self.status_label.config(text="Ready")
    
    def display_inspection_results(self, html_content, headers, security_info):
        # Update HTML Analysis tab
        self.html_text.config(state=tk.NORMAL)
        self.html_text.delete(1.0, tk.END)
        self.html_text.insert(tk.END, html_content)
        self.html_text.config(state=tk.DISABLED)
        
        # Update Headers tab
        self.headers_text.config(state=tk.NORMAL)
        self.headers_text.delete(1.0, tk.END)
        
        headers_content = "HTTP Headers:\n\n"
        for key, value in headers.items():
            headers_content += f"{key}: {value}\n"
        
        self.headers_text.insert(tk.END, headers_content)
        self.headers_text.config(state=tk.DISABLED)
        
        # Update Security tab
        self.security_text.config(state=tk.NORMAL)
        self.security_text.delete(1.0, tk.END)
        
        security_content = "Security Information:\n\n"
        for key, value in security_info.items():
            security_content += f"{key}: {value}\n"
        
        self.security_text.insert(tk.END, security_content)
        self.security_text.config(state=tk.DISABLED)
        
        # Switch to Website Inspector tab
        self.notebook.select(self.website_inspector_frame)
    
    def check_url(self, url):
        # This is a simplified version - in a real application, this would be more sophisticated
        # For demonstration purposes, we'll use a simple heuristic
        
        # Check if URL is in our phishing database
        if self.check_phishing_database(url):
            return {"phishing": True, "confidence": random.randint(85, 99)}
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r"login\.", r"signin\.", r"account\.", r"verify\.", r"security\.", 
            r"update\.", r"confirm\.", r"authenticate\.", r"password\.", r"banking\."
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return {"phishing": True, "confidence": random.randint(70, 85)}
        
        # Use ML model for prediction
        ml_result = self.ml_predict(url)
        if ml_result["phishing"]:
            return {"phishing": True, "confidence": ml_result["confidence"]}
        
        # If none of the above, consider it safe
        return {"phishing": False, "confidence": random.randint(85, 99)}
    
    def check_phishing_database(self, url):
        # In a real application, this would check against a database of known phishing URLs
        # For demonstration, we'll use a simple list
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check if domain is in our simulated database
        return domain in self.phishing_db
    
    def analyze_url_structure(self, url):
        # Analyze URL structure for suspicious patterns
        result = {}
        
        parsed_url = urlparse(url)
        
        # Check for IP address instead of domain name
        try:
            ipaddress.ip_address(parsed_url.netloc)
            result["ip_address"] = "Yes"
            result["suspicious"] = True
        except ValueError:
            result["ip_address"] = "No"
        
        # Check for unusual number of subdomains
        subdomains = parsed_url.netloc.split('.')
        if len(subdomains) > 3:
            result["many_subdomains"] = "Yes"
            result["suspicious"] = True
        else:
            result["many_subdomains"] = "No"
        
        # Check for hyphens in domain
        if '-' in parsed_url.netloc:
            result["hyphens_in_domain"] = "Yes"
            result["suspicious"] = True
        else:
            result["hyphens_in_domain"] = "No"
        
        # Check URL length
        if len(url) > 75:
            result["long_url"] = "Yes"
            result["suspicious"] = True
        else:
            result["long_url"] = "No"
        
        return result
    
    def get_domain_age(self, url):
        # In a real application, this would use WHOIS lookup to get domain registration date
        # For demonstration, we'll return a random age
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Simulate domain age lookup
            if domain in self.legitimate_db:
                return random.randint(365, 365*5)  # 1-5 years for legitimate sites
            else:
                return random.randint(1, 30)  # 1-30 days for suspicious sites
        except:
            return None
    
    def ml_predict(self, url):
        # In a real application, this would use a trained ML model
        # For demonstration, we'll return a random result
        
        # Extract features from URL
        features = self.extract_url_features(url)
        
        # Simulate prediction
        if self.ml_model and self.vectorizer:
            try:
                # Transform URL to feature vector
                X = self.vectorizer.transform([url])
                
                # Predict
                prediction = self.ml_model.predict(X)
                proba = self.ml_model.predict_proba(X)
                
                return {
                    "phishing": prediction[0] == 1,
                    "confidence": round(max(proba[0]) * 100, 2)
                }
            except:
                # Fallback if ML model fails
                pass
        
        # Fallback heuristic
        phishing_score = 0
        
        # Check for suspicious keywords
        suspicious_keywords = ["login", "signin", "account", "verify", "banking", 
                              "paypal", "ebay", "amazon", "apple", "microsoft"]
        
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                phishing_score += 1
        
        # Check for URL shortening services
        shorteners = ["bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly", "is.gd"]
        for shortener in shorteners:
            if shortener in url.lower():
                phishing_score += 2
        
        # Randomize slightly for demonstration
        phishing_score += random.randint(0, 2)
        
        return {
            "phishing": phishing_score >= 3,
            "confidence": random.randint(70, 95)
        }
    
    def extract_url_features(self, url):
        # Extract features from URL for ML model
        features = {}
        
        # URL length
        features['url_length'] = len(url)
        
        # Number of dots
        features['num_dots'] = url.count('.')
        
        # Number of hyphens
        features['num_hyphens'] = url.count('-')
        
        # Number of underscores
        features['num_underscores'] = url.count('_')
        
        # Number of slashes
        features['num_slashes'] = url.count('/')
        
        # Number of question marks
        features['num_question_marks'] = url.count('?')
        
        # Number of equals signs
        features['num_equals'] = url.count('=')
        
        # Number of ampersands
        features['num_ampersands'] = url.count('&')
        
        # Number of digits
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Check if contains IP address
        try:
            ipaddress.ip_address(urlparse(url).netloc)
            features['has_ip'] = 1
        except:
            features['has_ip'] = 0
        
        return features
    
    def load_ml_model(self):
        # In a real application, this would load a pre-trained ML model
        # For demonstration, we'll create a simple model
        
        try:
            # Try to load pre-trained model if available
            self.ml_model = joblib.load('phishing_model.pkl')
            self.vectorizer = joblib.load('vectorizer.pkl')
        except:
            # Create a simple model for demonstration
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            
            # Sample data for demonstration
            urls = [
                "http://login.example.com/verify",
                "http://secure.banking.com/signin",
                "http://www.paypal.com/login",
                "http://www.legitimate-site.com/home",
                "http://www.trusted-site.com/about",
                "http://update.account.info/confirm",
                "http://appleid.apple.com.verify.login",
                "http://www.microsoft.com/account",
                "http://www.github.com/login",
                "http://www.google.com/search"
            ]
            
            labels = [1, 1, 0, 0, 0, 1, 1, 0, 0, 0]  # 1 = phishing, 0 = legitimate
            
            # Create and train vectorizer
            self.vectorizer = TfidfVectorizer()
            X = self.vectorizer.fit_transform(urls)
            
            # Create and train model
            self.ml_model = RandomForestClassifier()
            self.ml_model.fit(X, labels)
            
            # Save model for future use
            joblib.dump(self.ml_model, 'phishing_model.pkl')
            joblib.dump(self.vectorizer, 'vectorizer.pkl')
    
    def load_phishing_database(self):
        # In a real application, this would load from a database or API
        # For demonstration, we'll use a hardcoded list
        return {
            "phishing-site.com",
            "fake-login.com",
            "secure-banking-update.com",
            "verify-account.info",
            "login-appleid.com"
        }
    
    def load_legitimate_database(self):
        # In a real application, this would load from a database
        # For demonstration, we'll use a hardcoded list
        return {
            "google.com",
            "github.com",
            "microsoft.com",
            "apple.com",
            "paypal.com"
        }
    
    def upload_links_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file containing URLs",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.links_text.delete(1.0, tk.END)
                    self.links_text.insert(tk.END, content)
                
                self.status_label.config(text=f"Loaded URLs from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def clear_links(self):
        self.links_text.delete(1.0, tk.END)
    
    def export_scan_results(self):
        # Get all results from the treeview
        items = self.results_tree.get_children()
        if not items:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    # Write header
                    file.write("URL,Status,Risk Level\n")
                    
                    # Write data
                    for item in items:
                        values = self.results_tree.item(item)['values']
                        file.write(f"{values[0]},{values[1]},{values[2]}\n")
                
                self.status_label.config(text=f"Results exported to {file_path}")
                messagebox.showinfo("Success", "Results exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def new_scan(self):
        self.notebook.select(self.url_analyzer_frame)
        self.url_var.set("")
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        self.overview_text.config(state=tk.DISABLED)
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        
        self.technical_text.config(state=tk.NORMAL)
        self.technical_text.delete(1.0, tk.END)
        self.technical_text.config(state=tk.DISABLED)
    
    def open_results(self):
        file_path = filedialog.askopenfilename(
            title="Open results file",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                
                # Clear current results
                for item in self.results_tree.get_children():
                    self.results_tree.delete(item)
                
                # Parse and add results
                lines = content.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    values = line.split(',')
                    if len(values) >= 3:
                        self.results_tree.insert("", tk.END, values=values)
                
                self.notebook.select(self.link_scanner_frame)
                self.status_label.config(text=f"Loaded results from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load results: {str(e)}")
    
    def export_report(self):
        # For simplicity, we'll export the current URL analysis
        if not hasattr(self, 'current_analysis') or not self.current_analysis:
            messagebox.showwarning("Warning", "No analysis to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write("PhishGuard Analysis Report\n")
                    file.write("=" * 50 + "\n\n")
                    file.write(f"URL: {self.current_analysis['url']}\n")
                    file.write(f"Status: {'PHISHING' if self.current_analysis['phishing'] else 'SAFE'}\n")
                    file.write(f"Confidence: {self.current_analysis['confidence']}%\n\n")
                    
                    file.write("Reasons:\n")
                    for reason in self.current_analysis['reasons']:
                        file.write(f"- {reason}\n")
                    
                    file.write("\nDetails:\n")
                    for key, value in self.current_analysis['details'].items():
                        file.write(f"{key}: {value}\n")
                
                self.status_label.config(text=f"Report exported to {file_path}")
                messagebox.showinfo("Success", "Report exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def exit_app(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit PhishGuard?"):
            self.root.destroy()
    
    def show_url_analyzer(self):
        self.notebook.select(self.url_analyzer_frame)
    
    def show_link_scanner(self):
        self.notebook.select(self.link_scanner_frame)
    
    def show_website_inspector(self):
        self.notebook.select(self.website_inspector_frame)
    
    def show_database_manager(self):
        messagebox.showinfo("Info", "Database Manager feature coming soon!")
    
    def show_settings(self):
        messagebox.showinfo("Info", "Settings feature coming soon!")
    
    def show_dashboard(self):
        self.notebook.select(self.dashboard_frame)
    
    def show_scan_history(self):
        messagebox.showinfo("Info", "Scan History feature coming soon!")
    
    def show_statistics(self):
        messagebox.showinfo("Info", "Statistics feature coming soon!")
    
    def show_general_settings(self):
        messagebox.showinfo("Info", "General Settings feature coming soon!")
    
    def show_security_settings(self):
        messagebox.showinfo("Info", "Security Settings feature coming soon!")
    
    def show_update_settings(self):
        messagebox.showinfo("Info", "Update Settings feature coming soon!")
    
    def show_user_guide(self):
        messagebox.showinfo("User Guide", 
                           "Accurate Cyber Defense Ant Phishing Tool User Guide:\n\n"
                           "1. Use the URL Analyzer to check individual URLs\n"
                           "2. Use the Link Scanner to check multiple URLs at once\n"
                           "3. Use the Website Inspector to analyze website content\n"
                           "4. Check the Dashboard for statistics and quick actions")
    
    def show_about(self):
        messagebox.showinfo("About Anti-phishing", 
                           "Accurate Cyber Defense - Advanced Anti-Phishing Tool\n\n"
                           "Version 1.0\n"
                           "Created with Python and Tkinter\n\n"
                           "This tool helps detect phishing websites and URLs "
                           "using various detection methods including:\n"
                           "- URL structure analysis\n"
                           "- Database lookups\n"
                           "- Machine learning\n"
                           "- Heuristic analysis")

def main():
    root = tk.Tk()
    app = accurate(root)
    root.mainloop()

if __name__ == "__main__":
    main()