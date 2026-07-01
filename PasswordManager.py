import os
import sqlite3
import secrets
import string
import time
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

CATEGORIES = ("Personal", "Professional")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
VERIFICATION_VALUE = "LOCK_VALID_2026"
PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
KEY_SIZE = 32

COLOR_BACKGROUND = "#000000"
COLOR_TEXT = "#FFFFFF"
COLOR_FIELD_BACKGROUND = "#0D0D0D"
COLOR_BORDER = "#3A3A3A"
COLOR_ACCENT = "#1A1A1A"
COLOR_HOVER = "#262626"
COLOR_ERROR = "#FF5555"
COLOR_SUCCESS = "#55FF88"
COLOR_MEDIUM = "#FFC107"


class CryptoEngine:

    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt(key, plain_data):
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plain_data.encode("utf-8"), None)
        return nonce, ciphertext

    @staticmethod
    def decrypt(key, nonce, encrypted_data):
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, encrypted_data, None)
        return data.decode("utf-8")


class IdGenerator:

    CONTROL_TABLE = string.ascii_uppercase + string.digits

    def generate(self):
        timestamp = format(int(time.time() * 1000), "x")
        random_part = secrets.token_hex(5)
        base = (timestamp + random_part).upper()
        control_sum = sum(ord(character) for character in base)
        control_character = self.CONTROL_TABLE[control_sum % len(self.CONTROL_TABLE)]
        segments = [base[i:i + 4] for i in range(0, len(base), 4)]
        return "-".join(segments) + "-" + control_character


class PasswordGenerator:

    UPPERCASE = string.ascii_uppercase
    LOWERCASE = string.ascii_lowercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"

    def generate(self, length, use_upper, use_lower, use_digits, use_symbols):
        character_sets = []
        if use_upper:
            character_sets.append(self.UPPERCASE)
        if use_lower:
            character_sets.append(self.LOWERCASE)
        if use_digits:
            character_sets.append(self.DIGITS)
        if use_symbols:
            character_sets.append(self.SYMBOLS)
        if not character_sets:
            character_sets = [self.UPPERCASE, self.LOWERCASE, self.DIGITS, self.SYMBOLS]
        random_generator = secrets.SystemRandom()
        effective_length = max(length, len(character_sets))
        required_characters = [random_generator.choice(character_set) for character_set in character_sets]
        all_characters = "".join(character_sets)
        additional_characters = [
            random_generator.choice(all_characters)
            for _ in range(effective_length - len(required_characters))
        ]
        password_list = required_characters + additional_characters
        random_generator.shuffle(password_list)
        return "".join(password_list)


class Database:

    def __init__(self, path):
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.create_tables()

    def create_tables(self):
        cursor = self.connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                verification_nonce BLOB NOT NULL,
                verification_ciphertext BLOB NOT NULL,
                creation_date TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                service TEXT NOT NULL,
                account_username TEXT NOT NULL,
                nonce BLOB NOT NULL,
                encrypted_password BLOB NOT NULL,
                creation_date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
        self.connection.commit()

    def create_user(self, username, salt, verification_nonce, verification_ciphertext):
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, salt, verification_nonce, verification_ciphertext, creation_date) VALUES (?, ?, ?, ?, ?)",
            (username, salt, verification_nonce, verification_ciphertext, datetime.now().isoformat()),
        )
        self.connection.commit()
        return cursor.lastrowid

    def get_user(self, username):
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT id, username, salt, verification_nonce, verification_ciphertext FROM users WHERE username = ?",
            (username,),
        )
        return cursor.fetchone()

    def add_entry(self, entry_id, user_id, category, service, account_username, nonce, encrypted_password):
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO entries (id, user_id, category, service, account_username, nonce, encrypted_password, creation_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entry_id, user_id, category, service, account_username, nonce, encrypted_password, datetime.now().isoformat()),
        )
        self.connection.commit()

    def get_entries(self, user_id, category_filter=None):
        cursor = self.connection.cursor()
        if category_filter and category_filter != "All":
            cursor.execute(
                "SELECT id, category, service, account_username, nonce, encrypted_password, creation_date FROM entries WHERE user_id = ? AND category = ? ORDER BY creation_date DESC",
                (user_id, category_filter),
            )
        else:
            cursor.execute(
                "SELECT id, category, service, account_username, nonce, encrypted_password, creation_date FROM entries WHERE user_id = ? ORDER BY creation_date DESC",
                (user_id,),
            )
        return cursor.fetchall()

    def delete_entry(self, entry_id, user_id):
        cursor = self.connection.cursor()
        cursor.execute(
            "DELETE FROM entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id),
        )
        self.connection.commit()


def create_button(parent, text, command, width=18):
    return tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        bg=COLOR_ACCENT,
        fg=COLOR_TEXT,
        activebackground=COLOR_HOVER,
        activeforeground=COLOR_TEXT,
        relief="flat",
        bd=1,
        highlightbackground=COLOR_BORDER,
        highlightthickness=1,
        cursor="hand2",
        font=("Segoe UI", 10),
    )


def create_field(parent, width=30, show=None):
    field = tk.Entry(
        parent,
        width=width,
        bg=COLOR_FIELD_BACKGROUND,
        fg=COLOR_TEXT,
        insertbackground=COLOR_TEXT,
        relief="flat",
        highlightthickness=1,
        highlightbackground=COLOR_BORDER,
        highlightcolor=COLOR_TEXT,
        font=("Segoe UI", 10),
    )
    if show is not None:
        field.configure(show=show)
    return field


def create_label(parent, text, size=10, bold=False):
    font = ("Segoe UI", size, "bold") if bold else ("Segoe UI", size)
    return tk.Label(parent, text=text, bg=COLOR_BACKGROUND, fg=COLOR_TEXT, font=font)


class LoginScreen(tk.Frame):

    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BACKGROUND)
        self.controller = controller
        container = tk.Frame(self, bg=COLOR_BACKGROUND)
        container.place(relx=0.5, rely=0.5, anchor="center")

        create_label(container, "PASSWORD MANAGER", 18, True).grid(row=0, column=0, columnspan=2, pady=(0, 30))
        create_label(container, "Username").grid(row=1, column=0, sticky="w", pady=8, padx=5)
        self.username_field = create_field(container, 32)
        self.username_field.grid(row=1, column=1, pady=8, padx=5)

        create_label(container, "Master password").grid(row=2, column=0, sticky="w", pady=8, padx=5)
        self.password_field = create_field(container, 32, show="*")
        self.password_field.grid(row=2, column=1, pady=8, padx=5)

        self.message_label = tk.Label(container, text="", bg=COLOR_BACKGROUND, fg=COLOR_ERROR, font=("Segoe UI", 9))
        self.message_label.grid(row=3, column=0, columnspan=2, pady=5)

        create_button(container, "Login", self.attempt_login, 34).grid(row=4, column=0, columnspan=2, pady=(15, 5))
        create_button(container, "Create an account", self.go_to_register, 34).grid(row=5, column=0, columnspan=2, pady=5)

        self.password_field.bind("<Return>", lambda event: self.attempt_login())

    def attempt_login(self):
        username = self.username_field.get().strip()
        password = self.password_field.get()
        if not username or not password:
            self.message_label.configure(text="Please fill in all fields")
            return
        success, message = self.controller.login(username, password)
        if not success:
            self.message_label.configure(text=message)
            self.password_field.delete(0, tk.END)

    def go_to_register(self):
        self.reset()
        self.controller.show_screen("RegisterScreen")

    def reset(self):
        self.username_field.delete(0, tk.END)
        self.password_field.delete(0, tk.END)
        self.message_label.configure(text="")


class RegisterScreen(tk.Frame):

    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BACKGROUND)
        self.controller = controller
        container = tk.Frame(self, bg=COLOR_BACKGROUND)
        container.place(relx=0.5, rely=0.5, anchor="center")

        create_label(container, "CREATE ACCOUNT", 18, True).grid(row=0, column=0, columnspan=2, pady=(0, 30))
        create_label(container, "Username").grid(row=1, column=0, sticky="w", pady=8, padx=5)
        self.username_field = create_field(container, 32)
        self.username_field.grid(row=1, column=1, pady=8, padx=5)

        create_label(container, "Master password").grid(row=2, column=0, sticky="w", pady=8, padx=5)
        self.password_field = create_field(container, 32, show="*")
        self.password_field.grid(row=2, column=1, pady=8, padx=5)

        create_label(container, "Confirm password").grid(row=3, column=0, sticky="w", pady=8, padx=5)
        self.confirm_field = create_field(container, 32, show="*")
        self.confirm_field.grid(row=3, column=1, pady=8, padx=5)

        self.message_label = tk.Label(container, text="", bg=COLOR_BACKGROUND, fg=COLOR_ERROR, font=("Segoe UI", 9))
        self.message_label.grid(row=4, column=0, columnspan=2, pady=5)

        create_button(container, "Create account", self.attempt_register, 34).grid(row=5, column=0, columnspan=2, pady=(15, 5))
        create_button(container, "Back to login", self.go_to_login, 34).grid(row=6, column=0, columnspan=2, pady=5)

    def attempt_register(self):
        username = self.username_field.get().strip()
        password = self.password_field.get()
        confirm = self.confirm_field.get()
        if not username or not password or not confirm:
            self.message_label.configure(text="Please fill in all fields")
            return
        if len(password) < 8:
            self.message_label.configure(text="Password must contain at least 8 characters")
            return
        if password != confirm:
            self.message_label.configure(text="Passwords do not match")
            return
        success, message = self.controller.register(username, password)
        if success:
            self.reset()
            messagebox.showinfo("Account created", "Your account has been created successfully")
            self.controller.show_screen("LoginScreen")
        else:
            self.message_label.configure(text=message)

    def go_to_login(self):
        self.reset()
        self.controller.show_screen("LoginScreen")

    def reset(self):
        self.username_field.delete(0, tk.END)
        self.password_field.delete(0, tk.END)
        self.confirm_field.delete(0, tk.END)
        self.message_label.configure(text="")


class MainScreen(tk.Frame):

    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BACKGROUND)
        self.controller = controller
        self.password_generator = PasswordGenerator()
        self.id_generator = IdGenerator()
        self.selected_category = tk.StringVar(value=CATEGORIES[0])
        self.category_filter = tk.StringVar(value="All")
        self.password_visible = False
        self.entries_cache = {}

        top_bar = tk.Frame(self, bg=COLOR_ACCENT, height=50)
        top_bar.pack(side="top", fill="x")
        self.user_label = tk.Label(top_bar, text="", bg=COLOR_ACCENT, fg=COLOR_TEXT, font=("Segoe UI", 11, "bold"))
        self.user_label.pack(side="left", padx=20, pady=12)
        create_button(top_bar, "Logout", self.logout, 16).pack(side="right", padx=20, pady=8)

        body = tk.Frame(self, bg=COLOR_BACKGROUND)
        body.pack(side="top", fill="both", expand=True, padx=20, pady=20)

        left_panel = tk.Frame(body, bg=COLOR_BACKGROUND, width=380)
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        left_panel.pack_propagate(False)

        right_panel = tk.Frame(body, bg=COLOR_BACKGROUND)
        right_panel.pack(side="left", fill="both", expand=True)

        self.build_left_panel(left_panel)
        self.build_right_panel(right_panel)

    def build_left_panel(self, parent):
        create_label(parent, "NEW ENTRY", 13, True).pack(anchor="w", pady=(0, 15))

        create_label(parent, "Service / Website").pack(anchor="w")
        self.service_field = create_field(parent, 40)
        self.service_field.pack(anchor="w", pady=(2, 10))

        create_label(parent, "Account username").pack(anchor="w")
        self.account_username_field = create_field(parent, 40)
        self.account_username_field.pack(anchor="w", pady=(2, 10))

        create_label(parent, "Password").pack(anchor="w")
        password_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        password_frame.pack(anchor="w", pady=(2, 4), fill="x")
        self.password_entry_field = create_field(password_frame, 32, show="*")
        self.password_entry_field.pack(side="left")
        create_button(password_frame, "Show", self.toggle_visibility, 10).pack(side="left", padx=(6, 0))
        self.password_entry_field.bind("<KeyRelease>", self.evaluate_password_strength)

        self.strength_label = tk.Label(parent, text="Strength: ", bg=COLOR_BACKGROUND, fg=COLOR_TEXT, font=("Segoe UI", 9))
        self.strength_label.pack(anchor="w", pady=(0, 10))

        create_label(parent, "Category").pack(anchor="w")
        category_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        category_frame.pack(anchor="w", pady=(2, 10))
        for category in CATEGORIES:
            tk.Radiobutton(
                category_frame,
                text=category,
                value=category,
                variable=self.selected_category,
                bg=COLOR_BACKGROUND,
                fg=COLOR_TEXT,
                selectcolor=COLOR_BACKGROUND,
                activebackground=COLOR_BACKGROUND,
                activeforeground=COLOR_TEXT,
                font=("Segoe UI", 10),
            ).pack(side="left", padx=(0, 15))

        create_label(parent, "Unique ID").pack(anchor="w")
        id_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        id_frame.pack(anchor="w", pady=(2, 15), fill="x")
        self.id_field = create_field(id_frame, 32)
        self.id_field.configure(state="readonly", readonlybackground=COLOR_FIELD_BACKGROUND)
        self.id_field.pack(side="left")
        create_button(id_frame, "New", self.generate_new_id, 10).pack(side="left", padx=(6, 0))

        separator = tk.Frame(parent, bg=COLOR_BORDER, height=1)
        separator.pack(fill="x", pady=15)

        create_label(parent, "PASSWORD GENERATOR", 13, True).pack(anchor="w", pady=(0, 10))

        length_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        length_frame.pack(anchor="w", fill="x", pady=(0, 10))
        create_label(length_frame, "Length").pack(side="left")
        self.length_variable = tk.IntVar(value=20)
        tk.Spinbox(
            length_frame,
            from_=8,
            to=128,
            textvariable=self.length_variable,
            width=6,
            bg=COLOR_FIELD_BACKGROUND,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            relief="flat",
            buttonbackground=COLOR_ACCENT,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        ).pack(side="left", padx=10)

        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)

        options_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        options_frame.pack(anchor="w", fill="x", pady=(0, 10))
        self.create_checkbox_option(options_frame, "Uppercase (A-Z)", self.use_upper_var).pack(anchor="w")
        self.create_checkbox_option(options_frame, "Lowercase (a-z)", self.use_lower_var).pack(anchor="w")
        self.create_checkbox_option(options_frame, "Digits (0-9)", self.use_digits_var).pack(anchor="w")
        self.create_checkbox_option(options_frame, "Symbols (!@#$...)", self.use_symbols_var).pack(anchor="w")

        create_button(parent, "Generate a complex password", self.generate_password, 40).pack(anchor="w", pady=(5, 15))
        create_button(parent, "Add this entry", self.add_entry, 40).pack(anchor="w", pady=(0, 5))

        self.status_label = tk.Label(parent, text=" ", bg=COLOR_BACKGROUND, fg=COLOR_SUCCESS, font=("Segoe UI", 9), wraplength=350, justify="left")
        self.status_label.pack(anchor="w", pady=(10, 0))

    def create_checkbox_option(self, parent, text, variable):
        return tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg=COLOR_BACKGROUND,
            fg=COLOR_TEXT,
            selectcolor=COLOR_BACKGROUND,
            activebackground=COLOR_BACKGROUND,
            activeforeground=COLOR_TEXT,
            font=("Segoe UI", 10),
        )

    def build_right_panel(self, parent):
        filter_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        filter_frame.pack(anchor="w", fill="x", pady=(0, 10))
        create_label(filter_frame, "Filter by category").pack(side="left", padx=(0, 10))
        filter_options = ("All",) + CATEGORIES
        filter_menu = ttk.Combobox(filter_frame, textvariable=self.category_filter, values=filter_options, state="readonly", width=20)
        filter_menu.pack(side="left")
        filter_menu.bind("<<ComboboxSelected>>", lambda event: self.refresh_list())

        columns = ("service", "username", "category", "date")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=18)
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("category", text="Category")
        self.tree.heading("date", text="Date added")
        self.tree.column("service", width=200)
        self.tree.column("username", width=200)
        self.tree.column("category", width=130)
        self.tree.column("date", width=160)
        self.tree.pack(fill="both", expand=True, pady=(0, 10))

        actions_frame = tk.Frame(parent, bg=COLOR_BACKGROUND)
        actions_frame.pack(anchor="w", fill="x")
        create_button(actions_frame, "Show password", self.show_selected_password, 24).pack(side="left", padx=(0, 10))
        create_button(actions_frame, "Copy password", self.copy_selected_password, 24).pack(side="left", padx=(0, 10))
        create_button(actions_frame, "Delete entry", self.delete_selected_entry, 24).pack(side="left")

    def activate(self):
        self.user_label.configure(text="Logged in as: " + self.controller.current_user["username"])
        self.reset_form()
        self.category_filter.set("All")
        self.refresh_list()

    def reset_form(self):
        self.service_field.delete(0, tk.END)
        self.account_username_field.delete(0, tk.END)
        self.password_entry_field.delete(0, tk.END)
        self.password_entry_field.configure(show="*")
        self.password_visible = False
        self.selected_category.set(CATEGORIES[0])
        self.generate_new_id()
        self.strength_label.configure(text="Strength: ", fg=COLOR_TEXT)
        self.status_label.configure(text=" ")

    def generate_new_id(self):
        new_id = self.id_generator.generate()
        self.id_field.configure(state="normal")
        self.id_field.delete(0, tk.END)
        self.id_field.insert(0, new_id)
        self.id_field.configure(state="readonly")

    def toggle_visibility(self):
        self.password_visible = not self.password_visible
        self.password_entry_field.configure(show="" if self.password_visible else "*")

    def generate_password(self):
        length = self.length_variable.get()
        password = self.password_generator.generate(
            length,
            self.use_upper_var.get(),
            self.use_lower_var.get(),
            self.use_digits_var.get(),
            self.use_symbols_var.get(),
        )
        self.password_entry_field.configure(show="")
        self.password_visible = True
        self.password_entry_field.delete(0, tk.END)
        self.password_entry_field.insert(0, password)
        self.evaluate_password_strength()
        self.status_label.configure(text="Password generated: " + str(len(password)) + " characters", fg=COLOR_SUCCESS)

    def evaluate_password_strength(self, event=None):
        password = self.password_entry_field.get()
        score = 0
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        if any(character.isupper() for character in password):
            score += 1
        if any(character.islower() for character in password):
            score += 1
        if any(character.isdigit() for character in password):
            score += 1
        if any(character in PasswordGenerator.SYMBOLS for character in password):
            score += 2
        if not password:
            self.strength_label.configure(text="Strength: ", fg=COLOR_TEXT)
        elif score >= 6:
            self.strength_label.configure(text="Strength: VERY HIGH", fg=COLOR_SUCCESS)
        elif score >= 4:
            self.strength_label.configure(text="Strength: HIGH", fg=COLOR_SUCCESS)
        elif score >= 2:
            self.strength_label.configure(text="Strength: MEDIUM", fg=COLOR_MEDIUM)
        else:
            self.strength_label.configure(text="Strength: WEAK", fg=COLOR_ERROR)

    def add_entry(self):
        service = self.service_field.get().strip()
        account_username = self.account_username_field.get().strip()
        password = self.password_entry_field.get()
        category = self.selected_category.get()
        entry_id = self.id_field.get()

        if not service or not account_username or not password:
            self.status_label.configure(text="All fields must be filled in", fg=COLOR_ERROR)
            return

        nonce, encrypted_password = CryptoEngine.encrypt(self.controller.session_key, password)
        try:
            self.controller.database.add_entry(
                entry_id,
                self.controller.current_user["id"],
                category,
                service,
                account_username,
                nonce,
                encrypted_password,
            )
        except sqlite3.IntegrityError:
            self.generate_new_id()
            self.status_label.configure(text="ID conflict, please try again", fg=COLOR_ERROR)
            return

        self.reset_form()
        self.status_label.configure(text="Entry added successfully", fg=COLOR_SUCCESS)
        self.refresh_list()

    def refresh_list(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.entries_cache = {}
        current_filter = self.category_filter.get()
        rows = self.controller.database.get_entries(self.controller.current_user["id"], current_filter)
        for entry_id, category, service, account_username, nonce, encrypted_password, creation_date in rows:
            display_date = creation_date.split("T")[0]
            self.tree.insert("", "end", iid=entry_id, values=(service, account_username, category, display_date))
            self.entries_cache[entry_id] = (nonce, encrypted_password)

    def get_selection(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No selection", "Please select an entry from the list")
            return None
        return selection[0]

    def show_selected_password(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        nonce, encrypted_password = self.entries_cache[entry_id]
        try:
            clear_password = CryptoEngine.decrypt(self.controller.session_key, nonce, encrypted_password)
            messagebox.showinfo("Password", clear_password)
        except InvalidTag:
            messagebox.showerror("Error", "Unable to decrypt this entry")

    def copy_selected_password(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        nonce, encrypted_password = self.entries_cache[entry_id]
        try:
            clear_password = CryptoEngine.decrypt(self.controller.session_key, nonce, encrypted_password)
            self.clipboard_clear()
            self.clipboard_append(clear_password)
            self.status_label.configure(text="Password copied to clipboard", fg=COLOR_SUCCESS)
        except InvalidTag:
            messagebox.showerror("Error", "Unable to decrypt this entry")

    def delete_selected_entry(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        confirmation = messagebox.askyesno("Confirmation", "Permanently delete this entry?")
        if confirmation:
            self.controller.database.delete_entry(entry_id, self.controller.current_user["id"])
            self.refresh_list()

    def logout(self):
        self.controller.logout()


class Application(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Password Manager - AES-256 Encryption")
        self.geometry("1100x700")
        self.minsize(1000, 650)
        self.configure(bg=COLOR_BACKGROUND)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=COLOR_FIELD_BACKGROUND,
            foreground=COLOR_TEXT,
            fieldbackground=COLOR_FIELD_BACKGROUND,
            bordercolor=COLOR_BORDER,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        style.configure("Treeview.Heading", background=COLOR_ACCENT, foreground=COLOR_TEXT, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", COLOR_HOVER)])
        style.configure("TCombobox", fieldbackground=COLOR_FIELD_BACKGROUND, background=COLOR_FIELD_BACKGROUND, foreground=COLOR_TEXT, arrowcolor=COLOR_TEXT)

        self.database = Database(DB_PATH)
        self.current_user = None
        self.session_key = None

        container = tk.Frame(self, bg=COLOR_BACKGROUND)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.screens = {}
        for ScreenClass in (LoginScreen, RegisterScreen, MainScreen):
            name = ScreenClass.__name__
            screen = ScreenClass(container, self)
            self.screens[name] = screen
            screen.grid(row=0, column=0, sticky="nsew")

        self.show_screen("LoginScreen")

    def show_screen(self, name):
        screen = self.screens[name]
        screen.tkraise()
        if name == "MainScreen":
            screen.activate()

    def register(self, username, password):
        existing = self.database.get_user(username)
        if existing is not None:
            return False, "This username already exists"
        salt = os.urandom(SALT_SIZE)
        key = CryptoEngine.derive_key(password, salt)
        verification_nonce, verification_ciphertext = CryptoEngine.encrypt(key, VERIFICATION_VALUE)
        try:
            self.database.create_user(username, salt, verification_nonce, verification_ciphertext)
        except sqlite3.IntegrityError:
            return False, "This username already exists"
        return True, "Account created"

    def login(self, username, password):
        row = self.database.get_user(username)
        if row is None:
            return False, "Incorrect username or password"
        user_id, name, salt, verification_nonce, verification_ciphertext = row
        key = CryptoEngine.derive_key(password, salt)
        try:
            decrypted_value = CryptoEngine.decrypt(key, verification_nonce, verification_ciphertext)
        except InvalidTag:
            return False, "Incorrect username or password"
        if decrypted_value != VERIFICATION_VALUE:
            return False, "Incorrect username or password"
        self.current_user = {"id": user_id, "username": name}
        self.session_key = key
        self.show_screen("MainScreen")
        return True, "Login successful"

    def logout(self):
        self.current_user = None
        self.session_key = None
        self.screens["LoginScreen"].reset()
        self.show_screen("LoginScreen")


if __name__ == "__main__":
    application = Application()
    application.mainloop()