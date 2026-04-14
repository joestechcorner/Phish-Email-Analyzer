"""
Phishing Email Analyzer - GUI Version
Graphical interface with external window
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import os
from analyzer import PhishingAnalyzer


class PhishingAnalyzerGUI:
    """GUI application for phishing email analysis"""
    
    def __init__(self, root):
        """
        Initialize the GUI window
        
        Args:
            root: tkinter root window
        """
        self.root = root
        self.root.title("Phishing Email Analyzer")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Set minimum window size
        self.root.minsize(800, 600)
        
        # Initialize analyzer
        self.analyzer = PhishingAnalyzer(
            "top-10000-domains.txt",
            "hard_keywords.txt", 
            "soft_keywords.txt"
        )
        
        # Color scheme
        self.colors = {
            'bg': '#f0f0f0',
            'header_bg': '#2c3e50',
            'header_fg': '#ffffff',
            'benign': '#27ae60',      # Green
            'suspicious': '#f39c12',   # Orange/Yellow
            'malicious': '#e74c3c',    # Red
            'button': '#3498db',       # Blue
            'button_hover': '#2980b9'  # Darker blue
        }
        
        # Configure root background
        self.root.configure(bg=self.colors['bg'])
        
        # Build the interface
        self.create_widgets()
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # ===== HEADER =====
        header_frame = tk.Frame(self.root, bg=self.colors['header_bg'], height=80)
        header_frame.pack(fill='x', pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(
            header_frame,
            text="🛡️ PHISHING EMAIL ANALYZER",
            font=('Arial', 24, 'bold'),
            bg=self.colors['header_bg'],
            fg=self.colors['header_fg']
        )
        title_label.pack(pady=20)
        
        # ===== FILE SELECTION SECTION =====
        file_frame = tk.Frame(self.root, bg=self.colors['bg'])
        file_frame.pack(fill='x', padx=20, pady=10)
        
        # File path label
        tk.Label(
            file_frame,
            text="Selected File:",
            font=('Arial', 11, 'bold'),
            bg=self.colors['bg']
        ).pack(anchor='w')
        
        # File path display and browse button
        path_frame = tk.Frame(file_frame, bg=self.colors['bg'])
        path_frame.pack(fill='x', pady=5)
        
        # Entry for file path
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(
            path_frame,
            textvariable=self.file_path_var,
            font=('Arial', 10),
            relief='solid',
            bd=1
        )
        self.file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        # Browse button
        self.browse_btn = tk.Button(
            path_frame,
            text="📁 Browse",
            command=self.browse_file,
            font=('Arial', 10, 'bold'),
            bg=self.colors['button'],
            fg='white',
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2'
        )
        self.browse_btn.pack(side='left')
        
        # Analyze button
        self.analyze_btn = tk.Button(
            file_frame,
            text="🔍 ANALYZE EMAIL",
            command=self.analyze_email,
            font=('Arial', 12, 'bold'),
            bg=self.colors['button'],
            fg='white',
            relief='flat',
            padx=30,
            pady=12,
            cursor='hand2'
        )
        self.analyze_btn.pack(pady=10)
        
        # ===== RESULTS SECTION =====
        results_frame = tk.Frame(self.root, bg=self.colors['bg'])
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Score display frame (will show score after analysis)
        self.score_frame = tk.Frame(results_frame, bg='white', relief='solid', bd=2)
        self.score_frame.pack(fill='x', pady=(0, 15))
        
        # Initialize score labels (hidden initially)
        self.score_label = tk.Label(
            self.score_frame,
            text="--",
            font=('Arial', 48, 'bold'),
            bg='white'
        )
        
        self.risk_label = tk.Label(
            self.score_frame,
            text="",
            font=('Arial', 16, 'bold'),
            bg='white'
        )
        
        # Progress bar for visual risk meter
        self.progress_frame = tk.Frame(results_frame, bg=self.colors['bg'])
        self.progress_frame.pack(fill='x', pady=(0, 15))
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            length=400,
            mode='determinate',
            maximum=100
        )
        
        # Results text area with scrollbar
        results_label = tk.Label(
            results_frame,
            text="Analysis Results:",
            font=('Arial', 11, 'bold'),
            bg=self.colors['bg']
        )
        results_label.pack(anchor='w', pady=(0, 5))
        
        # Scrolled text widget for detailed results
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=('Consolas', 10),
            wrap='word',
            relief='solid',
            bd=1,
            height=15
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Configure text tags for colored output
        self.results_text.tag_config('red', foreground=self.colors['malicious'], font=('Consolas', 10, 'bold'))
        self.results_text.tag_config('yellow', foreground=self.colors['suspicious'], font=('Consolas', 10, 'bold'))
        self.results_text.tag_config('green', foreground=self.colors['benign'], font=('Consolas', 10, 'bold'))
        self.results_text.tag_config('bold', font=('Consolas', 10, 'bold'))
        self.results_text.tag_config('header', font=('Consolas', 11, 'bold'))
        
        # Initial message
        self.results_text.insert('1.0', "Select an email file (.txt or .eml) and click 'ANALYZE EMAIL' to begin.\n\n")
        self.results_text.insert('end', "The analyzer will scan for:\n")
        self.results_text.insert('end', "• Suspicious URLs\n")
        self.results_text.insert('end', "• Phishing keywords\n")
        self.results_text.insert('end', "• Sender authenticity\n")
        self.results_text.insert('end', "• Urgent language patterns\n")
        self.results_text.insert('end', "• Email spoofing indicators\n")
        self.results_text.config(state='disabled')
        
        # ===== FOOTER =====
        footer_frame = tk.Frame(self.root, bg=self.colors['bg'])
        footer_frame.pack(fill='x', padx=20, pady=10)
        
        # Clear button
        clear_btn = tk.Button(
            footer_frame,
            text="🗑️ Clear Results",
            command=self.clear_results,
            font=('Arial', 10),
            bg='#95a5a6',
            fg='white',
            relief='flat',
            padx=15,
            pady=6,
            cursor='hand2'
        )
        clear_btn.pack(side='left')
        
        # Status label
        self.status_label = tk.Label(
            footer_frame,
            text="Ready",
            font=('Arial', 9),
            bg=self.colors['bg'],
            fg='#7f8c8d'
        )
        self.status_label.pack(side='right')
    
    def browse_file(self):
        """Open file dialog to select email file"""
        filename = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[
                ("Email Files", "*.eml *.txt"),
                ("Text Files", "*.txt"),
                ("Email Files", "*.eml"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            self.file_path_var.set(filename)
            self.status_label.config(text=f"Selected: {os.path.basename(filename)}")
    
    def analyze_email(self):
        """Perform analysis on selected email file"""
        filepath = self.file_path_var.get()
        
        # Validate file selection
        if not filepath:
            messagebox.showwarning("No File Selected", "Please select an email file to analyze.")
            return
        
        if not os.path.exists(filepath):
            messagebox.showerror("File Not Found", f"The file '{filepath}' does not exist.")
            return
        
        # Update status
        self.status_label.config(text="Analyzing...")
        self.root.update()
        
        try:
            # Perform analysis
            result = self.analyzer.analyze_file(filepath)
            
            # Display results
            self.display_results(result)
            
            # Update status
            self.status_label.config(text=f"Analysis complete - Risk: {result['risk_level']}")
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{str(e)}")
            self.status_label.config(text="Error occurred")
    
    def display_results(self, result):
        """
        Display analysis results in the GUI
        
        Args:
            result: Dictionary containing analysis results
        """
        score = result['score']
        risk_level = result['risk_level']
        
        # Determine color based on risk level
        if risk_level == 'BENIGN':
            color = self.colors['benign']
            tag = 'green'
        elif risk_level == 'SUSPICIOUS':
            color = self.colors['suspicious']
            tag = 'yellow'
        else:  # MALICIOUS
            color = self.colors['malicious']
            tag = 'red'
        
        # Update score display
        self.score_frame.config(bg=color)
        self.score_label.config(
            text=f"{score}/100",
            fg='white',
            bg=color
        )
        self.score_label.pack(pady=(15, 5))
        
        self.risk_label.config(
            text=risk_level,
            fg='white',
            bg=color
        )
        self.risk_label.pack(pady=(0, 15))
        
        # Update progress bar
        self.progress_bar.pack(fill='x')
        self.progress_bar['value'] = score
        
        # Style progress bar based on score
        style = ttk.Style()
        if score <= 30:
            style.configure("TProgressbar", background=self.colors['benign'])
        elif score <= 60:
            style.configure("TProgressbar", background=self.colors['suspicious'])
        else:
            style.configure("TProgressbar", background=self.colors['malicious'])
        
        # Clear and update results text
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', 'end')
        
        # Add divider
        self.results_text.insert('end', "="*80 + "\n", 'bold')
        self.results_text.insert('end', "ANALYSIS RESULTS\n", 'header')
        self.results_text.insert('end', "="*80 + "\n\n", 'bold')
        
        # Summary section
        self.results_text.insert('end', "SUMMARY:\n", 'bold')
        self.results_text.insert('end', f"• Sender: {result['sender'] if result['sender'] else 'Not found'}\n")
        self.results_text.insert('end', f"• Total URLs: {result['url_count']}\n")
        self.results_text.insert('end', f"• Suspicious URLs: {result['suspicious_url_count']}\n")
        self.results_text.insert('end', f"• Risk Score: {score}/100\n")
        self.results_text.insert('end', f"• Classification: ", 'bold')
        self.results_text.insert('end', f"{risk_level}\n\n", tag)
        
        # Detailed findings
        if result['details']:
            self.results_text.insert('end', "DETAILED FINDINGS:\n", 'bold')
            for detail in result['details']:
                # Color code based on severity
                if '🚨' in detail or 'HIGH-RISK' in detail:
                    self.results_text.insert('end', detail + "\n", 'red')
                elif '⚠️' in detail:
                    self.results_text.insert('end', detail + "\n", 'yellow')
                else:
                    self.results_text.insert('end', detail + "\n")
            self.results_text.insert('end', "\n")
        
        # Recommendations
        self.results_text.insert('end', "RECOMMENDED ACTIONS:\n", 'bold')
        for rec in result['recommendations']:
            if rec.startswith('🚨'):
                self.results_text.insert('end', rec + "\n", 'red')
            elif rec.startswith('⚠️'):
                self.results_text.insert('end', rec + "\n", 'yellow')
            elif rec.startswith('✓'):
                self.results_text.insert('end', rec + "\n", 'green')
            else:
                self.results_text.insert('end', rec + "\n")
        
        self.results_text.insert('end', "\n" + "="*80 + "\n", 'bold')
        
        self.results_text.config(state='disabled')
        
        # Show warning/success message box for high-risk emails
        if risk_level == 'MALICIOUS':
            messagebox.showwarning(
                "⚠️ HIGH RISK EMAIL DETECTED",
                f"This email scored {score}/100 and is classified as MALICIOUS.\n\n"
                "DO NOT interact with this email!\n"
                "Block, delete, and report immediately."
            )
        elif risk_level == 'SUSPICIOUS':
            messagebox.showinfo(
                "⚠️ Suspicious Email",
                f"This email scored {score}/100 and requires review.\n\n"
                "Quarantine this email and verify sender through alternative channels."
            )
    
    def clear_results(self):
        """Clear all results and reset the interface"""
        # Clear file selection
        self.file_path_var.set("")
        
        # Hide score display
        self.score_label.pack_forget()
        self.risk_label.pack_forget()
        self.score_frame.config(bg='white')
        
        # Hide progress bar
        self.progress_bar.pack_forget()
        self.progress_bar['value'] = 0
        
        # Clear results text
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', 'end')
        self.results_text.insert('1.0', "Select an email file (.txt or .eml) and click 'ANALYZE EMAIL' to begin.\n\n")
        self.results_text.insert('end', "The analyzer will scan for:\n")
        self.results_text.insert('end', "• Suspicious URLs\n")
        self.results_text.insert('end', "• Phishing keywords\n")
        self.results_text.insert('end', "• Sender authenticity\n")
        self.results_text.insert('end', "• Urgent language patterns\n")
        self.results_text.insert('end', "• Email spoofing indicators\n")
        self.results_text.config(state='disabled')
        
        # Reset status
        self.status_label.config(text="Ready")


def main():
    """Main entry point for GUI application"""
    root = tk.Tk()
    app = PhishingAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
