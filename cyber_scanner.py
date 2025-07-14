import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
from datetime import datetime
import json
import csv
import webbrowser
import os
from collections import OrderedDict
import time

class AnimatedButton(tk.Canvas):
    def __init__(self, master=None, **kwargs):
        # Extract custom parameters before passing to parent
        self.text = kwargs.pop('text', 'Button')
        self.default_bg = kwargs.pop('bg', '#252525')
        self.hover_bg = kwargs.pop('hover_bg', '#00ffcc')
        self.text_color = kwargs.pop('text_color', 'white')
        self.corner_radius = kwargs.pop('corner_radius', 10)
        self.command = kwargs.pop('command', lambda: None)
        
        width = kwargs.pop('width', 100)
        height = kwargs.pop('height', 40)
        
        super().__init__(master, width=width, height=height, **kwargs)
        self.config(highlightthickness=0, bd=0)
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
        
        self.draw_button()
    
    def draw_button(self):
        self.delete("all")
        # Draw rounded rectangle
        self.create_round_rect(0, 0, self.winfo_reqwidth(), self.winfo_reqheight(), 
                             radius=self.corner_radius, 
                             fill=self.default_bg, outline='')
        # Add text
        self.create_text(self.winfo_reqwidth()//2, self.winfo_reqheight()//2, 
                        text=self.text, fill=self.text_color,
                        font=('Helvetica', 12, 'bold'))
    
    def create_round_rect(self, x1, y1, x2, y2, radius=10, **kwargs):
        points = [x1+radius, y1,
                 x2-radius, y1,
                 x2, y1,
                 x2, y1+radius,
                 x2, y2-radius,
                 x2, y2,
                 x2-radius, y2,
                 x1+radius, y2,
                 x1, y2,
                 x1, y2-radius,
                 x1, y1+radius,
                 x1, y1]
        return self.create_polygon(points, **kwargs, smooth=True)
    
    def on_enter(self, event):
        self.itemconfig(1, fill=self.hover_bg)
        self.config(cursor="hand2")
    
    def on_leave(self, event):
        self.itemconfig(1, fill=self.default_bg)
        self.config(cursor="")
    
    def on_click(self, event):
        self.itemconfig(1, fill='#00cc99')
        self.update()
        time.sleep(0.1)
        self.itemconfig(1, fill=self.hover_bg)
        self.command()

class CyberScanner:
    def __init__(self, root):
        self.root = root
        self.scan_history = []
        self.current_scan = None
        self.setup_ui()
        self.load_history()
        
    def setup_ui(self):
        self.root.title("CyberScanner Pro - Vulnerability Assessment Tool")
        self.root.geometry("1100x750")
        self.root.configure(bg="#121212")
        
        # Custom fonts
        self.title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        self.label_font = tkfont.Font(family="Helvetica", size=12)
        self.button_font = tkfont.Font(family="Helvetica", size=12, weight="bold")
        self.output_font = tkfont.Font(family="Consolas", size=11)
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#121212")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel (controls and history)
        left_panel = tk.Frame(main_frame, bg="#1e1e1e", width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_panel.pack_propagate(False)
        
        # Right panel (output)
        right_panel = tk.Frame(main_frame, bg="#121212")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = tk.Frame(left_panel, bg="#1e1e1e")
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title = tk.Label(title_frame, text="CyberScanner", font=self.title_font, 
                       bg="#1e1e1e", fg="#00ffcc")
        title.pack(pady=15)
        
        # Divider
        tk.Frame(left_panel, bg="#333", height=2).pack(fill=tk.X, pady=5)
        
        # Scan controls
        control_frame = tk.Frame(left_panel, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=15, pady=15)
        
        url_label = tk.Label(control_frame, text="Target URL:", font=self.label_font, 
                           bg="#1e1e1e", fg="#00ffcc")
        url_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.url_entry = tk.Entry(control_frame, font=self.label_font, 
                                bg="#252525", fg="white", insertbackground="white",
                                relief=tk.FLAT, highlightcolor="#00ffcc",
                                highlightthickness=1, highlightbackground="#333")
        self.url_entry.insert(0, "http://testphp.vulnweb.com/")
        self.url_entry.pack(fill=tk.X, pady=5, ipady=5)
        
        # Modern animated buttons
        self.scan_btn = AnimatedButton(control_frame, width=270, height=45, 
                                     text="Start Security Scan", 
                                     bg="#00a8ff", hover_bg="#00ffcc",
                                     text_color="#121212", corner_radius=12,
                                     command=self.start_scan)
        self.scan_btn.pack(fill=tk.X, pady=10)
        
        self.export_btn = AnimatedButton(control_frame, width=270, height=45,
                                       text="Generate Report", 
                                       bg="#9c88ff", hover_bg="#00ffcc",
                                       text_color="#121212", corner_radius=12,
                                       command=self.export_report)
        self.export_btn.pack(fill=tk.X, pady=5)
        
        # Scan history
        history_frame = tk.Frame(left_panel, bg="#1e1e1e")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        history_label = tk.Label(history_frame, text="Scan History", font=self.label_font, 
                               bg="#1e1e1e", fg="#00ffcc")
        history_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Custom styled listbox
        self.history_listbox = tk.Listbox(history_frame, bg="#252525", fg="white", 
                                        selectbackground="#00ffcc", selectforeground="#121212", 
                                        font=self.label_font, relief=tk.FLAT,
                                        highlightthickness=0)
        scrollbar = ttk.Scrollbar(history_frame, orient="vertical")
        scrollbar.config(command=self.history_listbox.yview)
        self.history_listbox.config(yscrollcommand=scrollbar.set)
        
        self.history_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.history_listbox.bind('<<ListboxSelect>>', self.load_selected_scan)
        
        # Clear history button
        self.clear_btn = AnimatedButton(history_frame, width=270, height=40,
                                      text="Clear History", 
                                      bg="#ff4444", hover_bg="#ff7675",
                                      text_color="#121212", corner_radius=10,
                                      command=self.clear_history)
        self.clear_btn.pack(fill=tk.X, pady=(10, 20))
        
        # Output area
        output_frame = tk.Frame(right_panel, bg="#121212")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        # Custom title bar for output
        output_title = tk.Frame(output_frame, bg="#1e1e1e")
        output_title.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(output_title, text="Scan Results", font=self.label_font,
                bg="#1e1e1e", fg="#00ffcc").pack(side=tk.LEFT, padx=10, pady=5)
        
        # Modern scrolled text
        self.output_box = scrolledtext.ScrolledText(output_frame, font=self.output_font, 
                                                  bg="#1e1e1e", fg="#e0e0e0", 
                                                  insertbackground="white", wrap=tk.WORD,
                                                  relief=tk.FLAT, padx=15, pady=15,
                                                  highlightthickness=0)
        self.output_box.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colored text
        self.output_box.tag_config("red", foreground="#ff4444")
        self.output_box.tag_config("green", foreground="#44ff44")
        self.output_box.tag_config("yellow", foreground="#ffff44")
        self.output_box.tag_config("cyan", foreground="#00ffcc")
        self.output_box.tag_config("white", foreground="#ffffff")
        self.output_box.tag_config("header", foreground="#00ffcc", font=("Consolas", 14, "bold"))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = tk.Frame(right_panel, bg="#1e1e1e", height=25)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        tk.Label(status_bar, textvariable=self.status_var, 
                font=("Helvetica", 10), bg="#1e1e1e", fg="#00ffcc", 
                anchor=tk.W).pack(side=tk.LEFT, padx=10)
        
        # Progress bar (hidden by default)
        self.progress = ttk.Progressbar(status_bar, orient=tk.HORIZONTAL, 
                                      length=100, mode='determinate')
        self.progress.pack(side=tk.RIGHT, padx=10)
        self.progress.pack_forget()
    
    def insert_colored_text(self, text, color="white", newline=True):
        """Helper function to insert colored text"""
        if newline:
            text += "\n"
        self.output_box.insert(tk.END, text, color)
        self.output_box.see(tk.END)
        self.output_box.update()
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan")
            return
        
        self.output_box.delete(1.0, tk.END)
        self.insert_colored_text(f"CyberScanner Pro - Vulnerability Assessment", "header")
        self.insert_colored_text(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "cyan")
        
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        try:
            self.update_status(f"Connecting to {url}...")
            self.progress.pack(side=tk.RIGHT, padx=10)
            
            # Simulate progress
            for i in range(101):
                self.progress['value'] = i
                self.root.update()
                time.sleep(0.01)
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Create scan record
            self.current_scan = {
                'url': url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Completed',
                'security_headers': {},
                'cookie_analysis': {},
                'vulnerabilities': {}
            }
            
            # Check security headers
            self.insert_colored_text("\n[SECURITY HEADERS ANALYSIS]", "header")
            self.current_scan['security_headers']['missing'] = []
            for header in ['Content-Security-Policy', 'X-Frame-Options', 
                         'Strict-Transport-Security', 'X-Content-Type-Options', 
                         'Referrer-Policy']:
                if header not in response.headers:
                    self.insert_colored_text(f"[-] Missing header: {header}", "red")
                    self.current_scan['security_headers']['missing'].append(header)
                else:
                    self.insert_colored_text(f"[+] Found: {header}: {response.headers[header]}", "green")
                    self.current_scan['security_headers'][header] = response.headers[header]
            
            # Check cookies
            self.insert_colored_text("\n[COOKIE ANALYSIS]", "header")
            self.current_scan['cookie_analysis'] = {'flags': {}, 'issues': []}
            if 'set-cookie' in response.headers:
                cookies = response.headers['set-cookie'].lower()
                
                flags_to_check = {
                    'httponly': ('HttpOnly flag missing', 'HttpOnly flag present'),
                    'secure': ('Secure flag missing', 'Secure flag present'),
                    'samesite': ('SameSite attribute missing', 'SameSite attribute present')
                }
                
                for flag, (missing_msg, present_msg) in flags_to_check.items():
                    if flag not in cookies:
                        self.insert_colored_text(f"[-] {missing_msg}", "red")
                        self.current_scan['cookie_analysis']['issues'].append(missing_msg)
                    else:
                        self.insert_colored_text(f"[+] {present_msg}", "green")
                        self.current_scan['cookie_analysis']['flags'][flag] = True
            else:
                self.insert_colored_text("[-] No cookies found", "yellow")
                self.current_scan['cookie_analysis']['issues'].append("No cookies found")
            
            # Vulnerability checks
            self.insert_colored_text("\n[VULNERABILITY CHECKS]", "header")
            self.current_scan['vulnerabilities'] = {}
            
            # SQL Injection
            self.update_status("Testing for SQL Injection...")
            self.insert_colored_text("\n[SQL INJECTION TEST]", "cyan")
            if "?" in url:
                test_url = url + "' OR '1'='1"
                try:
                    sqli_res = requests.get(test_url)
                    if any(term in sqli_res.text.lower() for term in ["sql", "error", "syntax", "unclosed"]):
                        self.insert_colored_text("[!] Potential SQL Injection vulnerability detected", "red")
                        self.current_scan['vulnerabilities']['sql_injection'] = {
                            'status': 'Vulnerable',
                            'evidence': 'Error message in response'
                        }
                    else:
                        self.insert_colored_text("[+] No SQLi vulnerability detected", "green")
                        self.current_scan['vulnerabilities']['sql_injection'] = {
                            'status': 'Not vulnerable',
                            'evidence': 'No error messages detected'
                        }
                except Exception as e:
                    self.insert_colored_text(f"[-] Error testing SQLi: {str(e)}", "yellow")
                    self.current_scan['vulnerabilities']['sql_injection'] = {
                        'status': 'Test failed',
                        'error': str(e)
                    }
            else:
                self.insert_colored_text("[-] No parameters found in URL to test SQLi", "yellow")
                self.current_scan['vulnerabilities']['sql_injection'] = {
                    'status': 'Not tested',
                    'reason': 'No URL parameters found'
                }
            
            # XSS
            self.update_status("Testing for XSS...")
            self.insert_colored_text("\n[CROSS-SITE SCRIPTING TEST]", "cyan")
            try:
                xss_res = requests.get(url, params={'input': "<script>alert('xss')</script>"})
                if "<script>alert('xss')</script>" in xss_res.text:
                    self.insert_colored_text("[!] XSS vulnerability detected (payload reflected)", "red")
                    self.current_scan['vulnerabilities']['xss'] = {
                        'status': 'Vulnerable',
                        'evidence': 'Payload reflected in response'
                    }
                else:
                    self.insert_colored_text("[+] No XSS vulnerability detected", "green")
                    self.current_scan['vulnerabilities']['xss'] = {
                        'status': 'Not vulnerable',
                        'evidence': 'Payload not reflected'
                    }
            except Exception as e:
                self.insert_colored_text(f"[-] Error testing XSS: {str(e)}", "yellow")
                self.current_scan['vulnerabilities']['xss'] = {
                    'status': 'Test failed',
                    'error': str(e)
                }
            
            # Save scan to history
            self.save_scan()
            self.insert_colored_text("\n[SCAN COMPLETED]", "header")
            self.insert_colored_text(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "cyan")
            self.update_status("Scan completed successfully")
            self.progress.pack_forget()
            
        except requests.exceptions.RequestException as e:
            self.insert_colored_text(f"[-] Could not connect to URL: {e}", "red")
            self.update_status(f"Error: {str(e)}")
            self.progress.pack_forget()
            messagebox.showerror("Connection Error", str(e))
    
    def save_scan(self):
        if self.current_scan:
            self.scan_history.append(self.current_scan)
            self.update_history_listbox()
            self.save_history()
    
    def load_history(self):
        try:
            if os.path.exists("scan_history.json"):
                with open("scan_history.json", "r") as f:
                    self.scan_history = json.load(f)
                self.update_history_listbox()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load scan history: {str(e)}")
    
    def save_history(self):
        try:
            with open("scan_history.json", "w") as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Could not save scan history: {str(e)}")
    
    def update_history_listbox(self):
        self.history_listbox.delete(0, tk.END)
        for scan in reversed(self.scan_history):
            display_text = f"{scan['timestamp']} - {scan['url']}"
            self.history_listbox.insert(tk.END, display_text)
    
    def load_selected_scan(self, event):
        selection = self.history_listbox.curselection()
        if selection:
            index = len(self.scan_history) - selection[0] - 1
            scan = self.scan_history[index]
            self.display_scan_report(scan)
    
    def display_scan_report(self, scan):
        self.output_box.delete(1.0, tk.END)
        self.insert_colored_text("CyberScanner Pro - Scan Report", "header")
        self.insert_colored_text(f"\nURL: {scan['url']}", "white")
        self.insert_colored_text(f"Scan Date: {scan['timestamp']}", "white")
        self.insert_colored_text(f"Status: {scan['status']}\n", "white")
        
        # Security Headers
        self.insert_colored_text("\n[SECURITY HEADERS]", "header")
        if 'missing' in scan['security_headers'] and scan['security_headers']['missing']:
            for header in scan['security_headers']['missing']:
                self.insert_colored_text(f"[-] Missing: {header}", "red")
        for header, value in scan['security_headers'].items():
            if header != 'missing':
                self.insert_colored_text(f"[+] {header}: {value}", "green")
        
        # Cookie Analysis
        self.insert_colored_text("\n[COOKIE ANALYSIS]", "header")
        if scan['cookie_analysis'].get('issues'):
            for issue in scan['cookie_analysis']['issues']:
                self.insert_colored_text(f"[-] {issue}", "red")
        for flag, present in scan['cookie_analysis'].get('flags', {}).items():
            if present:
                self.insert_colored_text(f"[+] {flag.capitalize()} flag present", "green")
        
        # Vulnerabilities
        self.insert_colored_text("\n[VULNERABILITIES]", "header")
        for vuln, details in scan['vulnerabilities'].items():
            vuln_name = vuln.replace('_', ' ').upper()
            if details['status'].lower() in ['vulnerable', 'test failed']:
                color = "red"
            elif details['status'].lower() == 'not tested':
                color = "yellow"
            else:
                color = "green"
            
            self.insert_colored_text(f"\n{vuln_name}: {details['status']}", color)
            if 'evidence' in details:
                self.insert_colored_text(f"Evidence: {details['evidence']}", "white")
            if 'error' in details:
                self.insert_colored_text(f"Error: {details['error']}", "yellow")
    
    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            self.scan_history = []
            self.update_history_listbox()
            try:
                if os.path.exists("scan_history.json"):
                    os.remove("scan_history.json")
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete history file: {str(e)}")
    
    def export_report(self):
        if not self.scan_history:
            messagebox.showwarning("Warning", "No scan history to export")
            return
        
        file_types = [
            ("JSON File", "*.json"),
            ("HTML Report", "*.html"),
            ("CSV File", "*.csv"),
            ("Text File", "*.txt")
        ]
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=file_types,
            title="Save Scan Report"
        )
        
        if not file_path:
            return
        
        try:
            scan = self.current_scan if self.current_scan else self.scan_history[-1]
            
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(scan, f, indent=2)
            
            elif file_path.endswith('.html'):
                self.generate_html_report(file_path, scan)
            
            elif file_path.endswith('.csv'):
                self.generate_csv_report(file_path, scan)
            
            elif file_path.endswith('.txt'):
                self.generate_text_report(file_path, scan)
            
            messagebox.showinfo("Success", f"Report saved to {file_path}")
            if messagebox.askyesno("Open Report", "Would you like to open the report now?"):
                webbrowser.open(file_path)
        
        except Exception as e:
            messagebox.showerror("Error", f"Could not export report: {str(e)}")
    
    def generate_html_report(self, file_path, scan):
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CyberScanner Pro Report - {scan['url']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
        h1, h2 {{ color: #0066cc; }}
        .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .vulnerable {{ color: #d9534f; font-weight: bold; }}
        .secure {{ color: #5cb85c; }}
        .warning {{ color: #f0ad4e; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CyberScanner Pro Report</h1>
        <p><strong>URL:</strong> {scan['url']}</p>
        <p><strong>Scan Date:</strong> {scan['timestamp']}</p>
    </div>
    
    <h2>Security Headers</h2>
    <table>
        <tr><th>Header</th><th>Status</th><th>Value</th></tr>"""
        
        # Security Headers
        for header in ['Content-Security-Policy', 'X-Frame-Options', 
                     'Strict-Transport-Security', 'X-Content-Type-Options', 
                     'Referrer-Policy']:
            if header in scan['security_headers']:
                html += f"""
        <tr>
            <td>{header}</td>
            <td class="secure">Present</td>
            <td>{scan['security_headers'][header]}</td>
        </tr>"""
            else:
                html += f"""
        <tr>
            <td>{header}</td>
            <td class="vulnerable">Missing</td>
            <td>-</td>
        </tr>"""
        
        # Cookie Analysis
        html += """
    </table>
    
    <h2>Cookie Analysis</h2>
    <table>
        <tr><th>Check</th><th>Status</th></tr>"""
        
        cookie_flags = {
            'httponly': 'HttpOnly Flag',
            'secure': 'Secure Flag',
            'samesite': 'SameSite Attribute'
        }
        
        for flag, name in cookie_flags.items():
            if scan['cookie_analysis'].get('flags', {}).get(flag, False):
                html += f"""
        <tr>
            <td>{name}</td>
            <td class="secure">Present</td>
        </tr>"""
            else:
                html += f"""
        <tr>
            <td>{name}</td>
            <td class="vulnerable">Missing</td>
        </tr>"""
        
        # Vulnerabilities
        html += """
    </table>
    
    <h2>Vulnerability Tests</h2>
    <table>
        <tr><th>Test</th><th>Status</th><th>Details</th></tr>"""
        
        for vuln, details in scan['vulnerabilities'].items():
            vuln_name = vuln.replace('_', ' ').title()
            status_class = "vulnerable" if details['status'].lower() in ['vulnerable', 'test failed'] else "secure"
            
            html += f"""
        <tr>
            <td>{vuln_name}</td>
            <td class="{status_class}">{details['status']}</td>
            <td>"""
            
            if 'evidence' in details:
                html += details['evidence']
            elif 'error' in details:
                html += details['error']
            
            html += "</td>\n        </tr>"
        
        html += """
    </table>
</body>
</html>"""
        
        with open(file_path, 'w') as f:
            f.write(html)
    
    def generate_csv_report(self, file_path, scan):
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['CyberScanner Pro Report'])
            writer.writerow(['URL:', scan['url']])
            writer.writerow(['Scan Date:', scan['timestamp']])
            writer.writerow([])
            
            # Security Headers
            writer.writerow(['SECURITY HEADERS'])
            writer.writerow(['Header', 'Status', 'Value'])
            for header in ['Content-Security-Policy', 'X-Frame-Options', 
                          'Strict-Transport-Security', 'X-Content-Type-Options', 
                          'Referrer-Policy']:
                if header in scan['security_headers']:
                    writer.writerow([header, 'PRESENT', scan['security_headers'][header]])
                else:
                    writer.writerow([header, 'MISSING', ''])
            writer.writerow([])
            
            # Cookie Analysis
            writer.writerow(['COOKIE ANALYSIS'])
            writer.writerow(['Check', 'Status'])
            cookie_flags = OrderedDict([
                ('httponly', 'HttpOnly Flag'),
                ('secure', 'Secure Flag'),
                ('samesite', 'SameSite Attribute')
            ])
            
            for flag, name in cookie_flags.items():
                status = 'PRESENT' if scan['cookie_analysis'].get('flags', {}).get(flag, False) else 'MISSING'
                writer.writerow([name, status])
            writer.writerow([])
            
            # Vulnerabilities
            writer.writerow(['VULNERABILITY TESTS'])
            writer.writerow(['Test', 'Status', 'Details'])
            for vuln, details in scan['vulnerabilities'].items():
                vuln_name = vuln.replace('_', ' ').title()
                row = [vuln_name, details['status']]
                if 'evidence' in details:
                    row.append(details['evidence'])
                elif 'error' in details:
                    row.append(details['error'])
                else:
                    row.append('')
                writer.writerow(row)
    
    def generate_text_report(self, file_path, scan):
        with open(file_path, 'w') as f:
            f.write(f"CyberScanner Pro Report\n")
            f.write("="*50 + "\n\n")
            f.write(f"URL: {scan['url']}\n")
            f.write(f"Scan Date: {scan['timestamp']}\n\n")
            
            # Security Headers
            f.write("SECURITY HEADERS\n")
            f.write("-"*50 + "\n")
            for header in ['Content-Security-Policy', 'X-Frame-Options', 
                         'Strict-Transport-Security', 'X-Content-Type-Options', 
                         'Referrer-Policy']:
                if header in scan['security_headers']:
                    f.write(f"[+] {header}: {scan['security_headers'][header]}\n")
                else:
                    f.write(f"[-] Missing: {header}\n")
            f.write("\n")
            
            # Cookie Analysis
            f.write("COOKIE ANALYSIS\n")
            f.write("-"*50 + "\n")
            cookie_flags = OrderedDict([
                ('httponly', 'HttpOnly Flag'),
                ('secure', 'Secure Flag'),
                ('samesite', 'SameSite Attribute')
            ])
            
            for flag, name in cookie_flags.items():
                if scan['cookie_analysis'].get('flags', {}).get(flag, False):
                    f.write(f"[+] {name}: Present\n")
                else:
                    f.write(f"[-] {name}: Missing\n")
            f.write("\n")
            
            # Vulnerabilities
            f.write("VULNERABILITY TESTS\n")
            f.write("-"*50 + "\n")
            for vuln, details in scan['vulnerabilities'].items():
                vuln_name = vuln.replace('_', ' ').title()
                f.write(f"{vuln_name}: {details['status']}\n")
                if 'evidence' in details:
                    f.write(f"Evidence: {details['evidence']}\n")
                elif 'error' in details:
                    f.write(f"Error: {details['error']}\n")
                f.write("\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberScanner(root)
    root.mainloop()