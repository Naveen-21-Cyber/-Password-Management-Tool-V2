import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import string
import hashlib
import requests
import pyperclip
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import secrets
import re

class EnhancedPasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Enhanced Password Management System")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize encryption
        self.key_file = 'password_key.key'
        self.data_file = 'passwords.json'
        self.setup_encryption()
        
        # Load stored passwords
        self.stored_passwords = self.load_passwords()
        self.password_history = []
        self.current_password = ""
        
        self.setup_modern_style()
        self.create_interface()
        self.status_var = tk.StringVar(value="✨ Welcome to Enhanced Password Manager!")
        self.create_status_bar()

    def setup_encryption(self):
        """Setup encryption key for password storage"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def setup_modern_style(self):
        """Enhanced modern styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles with modern colors
        style.configure('Modern.TNotebook', background='#2b2b2b', borderwidth=0)
        style.configure('Modern.TNotebook.Tab', background='#404040', foreground='white', 
                       padding=[20, 10], font=('Segoe UI', 11, 'bold'))
        style.map('Modern.TNotebook.Tab', background=[('selected', '#0078d4')])
        
        style.configure('Modern.TFrame', background='#2b2b2b')
        style.configure('Modern.TLabel', background='#2b2b2b', foreground='white', 
                       font=('Segoe UI', 11))
        style.configure('Modern.TButton', background='#0078d4', foreground='white',
                       font=('Segoe UI', 10, 'bold'), padding=[10, 5])
        style.map('Modern.TButton', background=[('active', '#106ebe')])
        
        style.configure('Modern.TEntry', fieldbackground='#404040', foreground='white',
                       font=('Segoe UI', 11), insertcolor='white')

    def create_interface(self):
        """Create the main interface"""
        self.notebook = ttk.Notebook(self.root, style='Modern.TNotebook')
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        self.create_generator_tab()
        self.create_vault_tab()
        self.create_analyzer_tab()
        self.create_tools_tab()

    def create_generator_tab(self):
        """Advanced password generator with multiple options"""
        frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(frame, text="🎲 Generator")
        
        # Title
        title = ttk.Label(frame, text="Advanced Password Generator", 
                         font=('Segoe UI', 16, 'bold'), style='Modern.TLabel')
        title.pack(pady=20)
        
        # Generator options frame
        options_frame = ttk.Frame(frame, style='Modern.TFrame')
        options_frame.pack(pady=10, padx=40, fill='x')
        
        # Length control
        length_frame = ttk.Frame(options_frame, style='Modern.TFrame')
        length_frame.pack(fill='x', pady=5)
        ttk.Label(length_frame, text="Length:", style='Modern.TLabel').pack(side='left')
        self.length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(length_frame, from_=8, to=128, variable=self.length_var, 
                                orient='horizontal', length=200)
        length_scale.pack(side='left', padx=10)
        self.length_label = ttk.Label(length_frame, text="16", style='Modern.TLabel')
        self.length_label.pack(side='left', padx=5)
        length_scale.configure(command=self.update_length_label)
        
        # Character set options
        chars_frame = ttk.Frame(options_frame, style='Modern.TFrame')
        chars_frame.pack(fill='x', pady=10)
        
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=True)
        
        checkboxes = [
            ("Uppercase (A-Z)", self.use_upper),
            ("Lowercase (a-z)", self.use_lower),
            ("Digits (0-9)", self.use_digits),
            ("Symbols (!@#$...)", self.use_symbols),
            ("Exclude ambiguous (0,O,l,1)", self.exclude_ambiguous)
        ]
        
        for i, (text, var) in enumerate(checkboxes):
            cb = ttk.Checkbutton(chars_frame, text=text, variable=var)
            cb.grid(row=i//3, column=i%3, sticky='w', padx=10, pady=2)
        
        # Preset buttons
        preset_frame = ttk.Frame(options_frame, style='Modern.TFrame')
        preset_frame.pack(pady=15)
        
        presets = [
            ("🔒 Ultra Secure", self.preset_ultra_secure),
            ("💼 Business", self.preset_business),
            ("📱 PIN Code", self.preset_pin),
            ("🎯 Memorable", self.preset_memorable)
        ]
        
        for text, command in presets:
            ttk.Button(preset_frame, text=text, command=command, 
                      style='Modern.TButton').pack(side='left', padx=5)
        
        # Generate button
        ttk.Button(frame, text="🎲 Generate Password", command=self.generate_advanced_password,
                  style='Modern.TButton').pack(pady=20)
        
        # Password display
        self.password_display = tk.Text(frame, height=3, width=80, font=('Consolas', 14, 'bold'),
                                       bg='#1e1e1e', fg='#00ff00', insertbackground='white',
                                       wrap='word', state='disabled')
        self.password_display.pack(pady=10, padx=40)
        
        # Action buttons
        action_frame = ttk.Frame(frame, style='Modern.TFrame')
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="📋 Copy", command=self.copy_password,
                  style='Modern.TButton').pack(side='left', padx=5)
        ttk.Button(action_frame, text="💾 Save to Vault", command=self.save_to_vault,
                  style='Modern.TButton').pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔄 Regenerate", command=self.generate_advanced_password,
                  style='Modern.TButton').pack(side='left', padx=5)

    def create_vault_tab(self):
        """Password vault for storing and managing passwords"""
        frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(frame, text="🏦 Vault")
        
        ttk.Label(frame, text="Password Vault", font=('Segoe UI', 16, 'bold'),
                 style='Modern.TLabel').pack(pady=20)
        
        # Add password section
        add_frame = ttk.LabelFrame(frame, text="Add New Entry", padding=15)
        add_frame.pack(fill='x', padx=20, pady=10)
        
        # Entry fields
        fields_frame = ttk.Frame(add_frame)
        fields_frame.pack(fill='x')
        
        self.site_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.vault_password_var = tk.StringVar()
        
        entries = [
            ("Website/Service:", self.site_var),
            ("Username/Email:", self.username_var),
            ("Password:", self.vault_password_var)
        ]
        
        for i, (label, var) in enumerate(entries):
            ttk.Label(fields_frame, text=label).grid(row=i, column=0, sticky='w', pady=5)
            entry = ttk.Entry(fields_frame, textvariable=var, width=40, style='Modern.TEntry')
            if "Password" in label:
                entry.configure(show='*')
            entry.grid(row=i, column=1, padx=10, pady=5, sticky='ew')
        
        fields_frame.columnconfigure(1, weight=1)
        
        ttk.Button(add_frame, text="💾 Save Entry", command=self.save_vault_entry,
                  style='Modern.TButton').pack(pady=10)
        
        # Password list
        list_frame = ttk.LabelFrame(frame, text="Stored Passwords", padding=15)
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Treeview for password list
        columns = ('Site', 'Username', 'Last Modified')
        self.vault_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.vault_tree.heading(col, text=col)
            self.vault_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.vault_tree.yview)
        self.vault_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vault_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Vault action buttons
        vault_actions = ttk.Frame(list_frame)
        vault_actions.pack(pady=10)
        
        ttk.Button(vault_actions, text="👁️ View", command=self.view_password,
                  style='Modern.TButton').pack(side='left', padx=5)
        ttk.Button(vault_actions, text="📋 Copy Password", command=self.copy_vault_password,
                  style='Modern.TButton').pack(side='left', padx=5)
        ttk.Button(vault_actions, text="🗑️ Delete", command=self.delete_vault_entry,
                  style='Modern.TButton').pack(side='left', padx=5)
        
        self.refresh_vault_display()

    def create_analyzer_tab(self):
        """Password analysis and security checking"""
        frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(frame, text="🔍 Analyzer")
        
        ttk.Label(frame, text="Password Security Analyzer", font=('Segoe UI', 16, 'bold'),
                 style='Modern.TLabel').pack(pady=20)
        
        # Analysis input
        input_frame = ttk.Frame(frame, style='Modern.TFrame')
        input_frame.pack(pady=20, padx=40, fill='x')
        
        ttk.Label(input_frame, text="Enter password to analyze:", style='Modern.TLabel').pack()
        self.analyze_entry = ttk.Entry(input_frame, font=('Consolas', 12), width=50,
                                      style='Modern.TEntry', show='*')
        self.analyze_entry.pack(pady=10)
        
        # Show/Hide password
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(input_frame, text="Show password", variable=self.show_password,
                       command=self.toggle_password_visibility).pack()
        
        # Analysis buttons
        button_frame = ttk.Frame(frame, style='Modern.TFrame')
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="🔍 Analyze Strength", command=self.analyze_password,
                  style='Modern.TButton').pack(side='left', padx=10)
        ttk.Button(button_frame, text="🕵️ Check Breaches", command=self.check_breaches,
                  style='Modern.TButton').pack(side='left', padx=10)
        
        # Results display
        self.analysis_text = tk.Text(frame, height=20, width=100, font=('Consolas', 11),
                                   bg='#1e1e1e', fg='white', state='disabled')
        self.analysis_text.pack(pady=20, padx=40, fill='both', expand=True)

    def create_tools_tab(self):
        """Additional security tools"""
        frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(frame, text="🛠️ Tools")
        
        ttk.Label(frame, text="Security Tools", font=('Segoe UI', 16, 'bold'),
                 style='Modern.TLabel').pack(pady=20)
        
        # Tools grid
        tools_frame = ttk.Frame(frame, style='Modern.TFrame')
        tools_frame.pack(expand=True)
        
        tools = [
            ("🎯 Passphrase Generator", self.generate_passphrase),
            ("🔐 Encrypt Text", self.encrypt_text),
            ("📊 Vault Statistics", self.show_vault_stats),
            ("📤 Export Vault", self.export_vault),
            ("📥 Import Passwords", self.import_passwords),
            ("🧹 Clean Duplicates", self.clean_duplicates)
        ]
        
        for i, (text, command) in enumerate(tools):
            btn = ttk.Button(tools_frame, text=text, command=command, 
                           style='Modern.TButton', width=25)
            btn.grid(row=i//2, column=i%2, padx=20, pady=15, sticky='ew')

    def create_status_bar(self):
        """Create status bar"""
        status_frame = ttk.Frame(self.root, relief='sunken', borderwidth=1)
        status_frame.pack(side='bottom', fill='x')
        
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                               font=('Segoe UI', 10), background='#404040', foreground='white')
        status_label.pack(side='left', padx=10, pady=2)

    # Generator methods
    def update_length_label(self, value):
        self.length_label.configure(text=str(int(float(value))))

    def preset_ultra_secure(self):
        self.length_var.set(32)
        self.use_upper.set(True)
        self.use_lower.set(True)
        self.use_digits.set(True)
        self.use_symbols.set(True)
        self.exclude_ambiguous.set(True)

    def preset_business(self):
        self.length_var.set(16)
        self.use_upper.set(True)
        self.use_lower.set(True)
        self.use_digits.set(True)
        self.use_symbols.set(False)
        self.exclude_ambiguous.set(True)

    def preset_pin(self):
        self.length_var.set(6)
        self.use_upper.set(False)
        self.use_lower.set(False)
        self.use_digits.set(True)
        self.use_symbols.set(False)

    def preset_memorable(self):
        self.length_var.set(12)
        self.use_upper.set(False)
        self.use_lower.set(True)
        self.use_digits.set(True)
        self.use_symbols.set(False)

    def generate_advanced_password(self):
        """Generate password with advanced options"""
        length = self.length_var.get()
        charset = ""
        
        if self.use_lower.get():
            charset += string.ascii_lowercase
        if self.use_upper.get():
            charset += string.ascii_uppercase
        if self.use_digits.get():
            charset += string.digits
        if self.use_symbols.get():
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if self.exclude_ambiguous.get():
            ambiguous = "0O1lI"
            charset = ''.join(c for c in charset if c not in ambiguous)
        
        if not charset:
            messagebox.showerror("Error", "Please select at least one character type!")
            return
        
        self.current_password = ''.join(secrets.choice(charset) for _ in range(length))
        
        # Display password
        self.password_display.configure(state='normal')
        self.password_display.delete(1.0, tk.END)
        self.password_display.insert(1.0, self.current_password)
        self.password_display.configure(state='disabled')
        
        # Log generation
        self.password_history.append({
            'timestamp': datetime.now().isoformat(),
            'password': self.current_password,
            'length': length,
            'method': 'Advanced Generator'
        })
        
        self.status_var.set(f"✅ Generated {length}-character password")

    def copy_password(self):
        if self.current_password:
            pyperclip.copy(self.current_password)
            self.status_var.set("📋 Password copied to clipboard!")

    # Vault methods
    def save_to_vault(self):
        if not self.current_password:
            messagebox.showerror("Error", "No password to save!")
            return
        
        # Simple dialog for site/username
        site = tk.simpledialog.askstring("Site", "Enter website/service name:")
        if not site:
            return
        
        username = tk.simpledialog.askstring("Username", "Enter username/email:")
        if not username:
            return
        
        self.stored_passwords[site] = {
            'username': username,
            'password': self.current_password,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        
        self.save_passwords()
        self.refresh_vault_display()
        self.status_var.set(f"💾 Password saved for {site}")

    def save_vault_entry(self):
        site = self.site_var.get().strip()
        username = self.username_var.get().strip()
        password = self.vault_password_var.get().strip()
        
        if not (site and username and password):
            messagebox.showerror("Error", "Please fill all fields!")
            return
        
        self.stored_passwords[site] = {
            'username': username,
            'password': password,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        
        # Clear fields
        self.site_var.set("")
        self.username_var.set("")
        self.vault_password_var.set("")
        
        self.save_passwords()
        self.refresh_vault_display()
        self.status_var.set(f"💾 Entry saved for {site}")

    def refresh_vault_display(self):
        """Refresh the vault display"""
        for item in self.vault_tree.get_children():
            self.vault_tree.delete(item)
        
        for site, data in self.stored_passwords.items():
            modified = data.get('modified', data.get('created', 'Unknown'))
            if modified != 'Unknown':
                try:
                    modified = datetime.fromisoformat(modified).strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            self.vault_tree.insert('', 'end', values=(site, data['username'], modified))

    def view_password(self):
        selection = self.vault_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to view!")
            return
        
        item = self.vault_tree.item(selection[0])
        site = item['values'][0]
        
        if site in self.stored_passwords:
            password = self.stored_passwords[site]['password']
            messagebox.showinfo("Password", f"Password for {site}:\n{password}")

    def copy_vault_password(self):
        selection = self.vault_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to copy!")
            return
        
        item = self.vault_tree.item(selection[0])
        site = item['values'][0]
        
        if site in self.stored_passwords:
            password = self.stored_passwords[site]['password']
            pyperclip.copy(password)
            self.status_var.set(f"📋 Password for {site} copied!")

    def delete_vault_entry(self):
        selection = self.vault_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to delete!")
            return
        
        item = self.vault_tree.item(selection[0])
        site = item['values'][0]
        
        if messagebox.askyesno("Confirm", f"Delete entry for {site}?"):
            del self.stored_passwords[site]
            self.save_passwords()
            self.refresh_vault_display()
            self.status_var.set(f"🗑️ Entry for {site} deleted")

    # Analysis methods
    def toggle_password_visibility(self):
        self.analyze_entry.configure(show='' if self.show_password.get() else '*')

    def analyze_password(self):
        password = self.analyze_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password to analyze!")
            return
        
        analysis = self.comprehensive_analysis(password)
        
        self.analysis_text.configure(state='normal')
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, analysis)
        self.analysis_text.configure(state='disabled')

    def comprehensive_analysis(self, password):
        """Comprehensive password analysis"""
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        # Calculate entropy
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        
        entropy = length * (charset_size.bit_length() - 1) if charset_size > 0 else 0
        
        # Strength calculation
        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if length >= 16: score += 1
        if has_upper: score += 1
        if has_lower: score += 1
        if has_digit: score += 1
        if has_symbol: score += 1
        
        # Common patterns check
        common_patterns = []
        if re.search(r'(.)\1{2,}', password):
            common_patterns.append("Repeated characters")
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            common_patterns.append("Sequential numbers")
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            common_patterns.append("Sequential letters")
        
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]
        strength = strength_levels[min(score, len(strength_levels)-1)]
        
        analysis = f"""
🔍 PASSWORD ANALYSIS REPORT
{'='*50}

📏 Length: {length} characters
🔤 Character Types:
   • Uppercase letters: {'✅' if has_upper else '❌'}
   • Lowercase letters: {'✅' if has_lower else '❌'}
   • Numbers: {'✅' if has_digit else '❌'}
   • Symbols: {'✅' if has_symbol else '❌'}

🔢 Entropy: ~{entropy:.1f} bits
💪 Strength: {strength} ({score}/7)

⚠️  Potential Issues:
{chr(10).join(f'   • {pattern}' for pattern in common_patterns) if common_patterns else '   ✅ No common patterns detected'}

💡 Recommendations:
"""
        
        if length < 12:
            analysis += "   • Increase length to at least 12 characters\n"
        if not has_upper:
            analysis += "   • Add uppercase letters\n"
        if not has_lower:
            analysis += "   • Add lowercase letters\n"
        if not has_digit:
            analysis += "   • Add numbers\n"
        if not has_symbol:
            analysis += "   • Add special symbols\n"
        if not common_patterns and score >= 6:
            analysis += "   ✅ This is a strong password!\n"
        
        return analysis

    def check_breaches(self):
        password = self.analyze_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password to check!")
            return
        
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
            
            if response.status_code == 200:
                hashes = {line.split(':')[0]: int(line.split(':')[1]) 
                         for line in response.text.splitlines()}
                
                result = "🕵️ BREACH CHECK RESULTS\n" + "="*40 + "\n\n"
                
                if suffix in hashes:
                    count = hashes[suffix]
                    result += f"⚠️  WARNING: This password has been found in {count:,} data breaches!\n"
                    result += "🚨 Recommendation: Change this password immediately!\n"
                else:
                    result += "✅ Good news! This password was not found in known data breaches.\n"
                    result += "💡 However, always use unique passwords for each account.\n"
                
                self.analysis_text.configure(state='normal')
                self.analysis_text.delete(1.0, tk.END)
                self.analysis_text.insert(1.0, result)
                self.analysis_text.configure(state='disabled')
                
            else:
                messagebox.showerror("Error", "Failed to check password against breach database")
                
        except Exception as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")

    # Tool methods
    def generate_passphrase(self):
        """Generate memorable passphrase"""
        words = ['apple', 'ocean', 'mountain', 'river', 'forest', 'thunder', 'crystal', 'phoenix',
                'dragon', 'castle', 'garden', 'sunset', 'silver', 'golden', 'purple', 'rainbow']
        
        passphrase = '-'.join(secrets.choice(words) for _ in range(4))
        passphrase += '-' + str(secrets.randbelow(9999))
        
        messagebox.showinfo("Passphrase Generated", f"Your passphrase:\n\n{passphrase}")
        pyperclip.copy(passphrase)

    def encrypt_text(self):
        text = tk.simpledialog.askstring("Encrypt", "Enter text to encrypt:")
        if text:
            encrypted = self.cipher.encrypt(text.encode()).decode()
            messagebox.showinfo("Encrypted", f"Encrypted text:\n\n{encrypted}")

    def show_vault_stats(self):
        total = len(self.stored_passwords)
        weak = sum(1 for data in self.stored_passwords.values() 
                  if len(data['password']) < 12)
        
        stats = f"""
📊 VAULT STATISTICS
{'='*30}

Total entries: {total}
Weak passwords: {weak}
Strong passwords: {total - weak}
Vault health: {((total - weak) / total * 100) if total > 0 else 0:.1f}%
"""
        messagebox.showinfo("Vault Statistics", stats)

    def export_vault(self):
        if not self.stored_passwords:
            messagebox.showinfo("Info", "No passwords to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.stored_passwords, f, indent=2)
            messagebox.showinfo("Success", "Vault exported successfully!")

    def import_passwords(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    imported = json.load(f)
                
                self.stored_passwords.update(imported)
                self.save_passwords()
                self.refresh_vault_display()
                messagebox.showinfo("Success", f"Imported {len(imported)} entries!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import: {str(e)}")

    def clean_duplicates(self):
        """Remove duplicate passwords from vault"""
        seen_passwords = {}
        duplicates = []
        
        for site, data in self.stored_passwords.items():
            password = data['password']
            if password in seen_passwords:
                duplicates.append((site, seen_passwords[password]))
            else:
                seen_passwords[password] = site
        
        if duplicates:
            msg = "Duplicate passwords found:\n\n"
            for site1, site2 in duplicates:
                msg += f"• {site1} and {site2}\n"
            msg += "\nConsider using unique passwords for each service!"
            messagebox.showwarning("Duplicates Found", msg)
        else:
            messagebox.showinfo("Clean Vault", "No duplicate passwords found!")

    # Data persistence methods
    def load_passwords(self):
        """Load encrypted passwords from file"""
        if not os.path.exists(self.data_file):
            return {}
        
        try:
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()
            
            if encrypted_data:
                decrypted_data = self.cipher.decrypt(encrypted_data)
                return json.loads(decrypted_data.decode())
            return {}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
            return {}

    def save_passwords(self):
        """Save passwords with encryption"""
        try:
            data = json.dumps(self.stored_passwords).encode()
            encrypted_data = self.cipher.encrypt(data)
            
            with open(self.data_file, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")

if __name__ == "__main__":
    # Check for required modules
    try:
        import tkinter.simpledialog
    except ImportError:
        print("Error: tkinter.simpledialog not available")
        exit(1)
    
    root = tk.Tk()
    app = EnhancedPasswordManager(root)
    root.mainloop()