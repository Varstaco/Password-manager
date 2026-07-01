import os
import sys
import sqlite3
import secrets
import string
import time
from datetime import datetime

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QStackedWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QFrame,
    QRadioButton,
    QButtonGroup,
    QCheckBox,
    QSpinBox,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QAbstractItemView,
    QProgressBar,
)

CATEGORIES = ("Personal", "Professional")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
VERIFICATION_VALUE = "LOCK_VALID_2026"
PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
KEY_SIZE = 32

BG = "#0E0C0A"
SURFACE = "#17140F"
SURFACE_ALT = "#1D1913"
BORDER = "#332D22"
FOCUS = "#C9A15C"
TEXT_PRIMARY = "#F2EFE7"
TEXT_SECONDARY = "#948B78"
ACCENT = "#C9A15C"
ACCENT_HOVER = "#D9B571"
ACCENT_PRESSED = "#B48D4C"
ACCENT_TEXT = "#14110A"
SUCCESS = "#7FC29B"
ERROR = "#E0645A"
WARNING = "#E0B04D"

SANS_FONT = "'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif"
MONO_FONT = "'Cascadia Code', 'Consolas', 'JetBrains Mono', monospace"

STYLE_SHEET = """
QMainWindow, QWidget {{
    background-color: {BG};
    color: {TEXT_PRIMARY};
    font-family: {SANS_FONT};
    font-size: 10pt;
}}
QFrame#card {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QFrame#topBar {{
    background-color: {SURFACE};
    border-bottom: 1px solid {BORDER};
}}
QFrame#leftPanel {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QFrame#hline {{
    background-color: {BORDER};
    max-height: 1px;
    min-height: 1px;
    border: none;
}}
QLabel#brand {{
    font-size: 21pt;
    font-weight: 600;
    letter-spacing: 3px;
    color: {TEXT_PRIMARY};
}}
QLabel#tagline {{
    color: {TEXT_SECONDARY};
    font-size: 9pt;
}}
QLabel#sectionTitle {{
    font-size: 11pt;
    font-weight: 700;
    color: {ACCENT};
    letter-spacing: 1px;
}}
QLabel#fieldLabel {{
    color: {TEXT_SECONDARY};
    font-size: 9pt;
    font-weight: 600;
}}
QLabel#userLabel {{
    color: {TEXT_PRIMARY};
    font-weight: 600;
}}
QLabel#emptyState {{
    color: {TEXT_SECONDARY};
    font-size: 10pt;
}}
QLineEdit, QSpinBox, QComboBox {{
    background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 10px;
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_TEXT};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {FOCUS};
}}
QLineEdit:read-only {{
    color: {TEXT_SECONDARY};
}}
QLineEdit#idField, QLineEdit#passwordField {{
    font-family: {MONO_FONT};
    letter-spacing: 1px;
}}
QPushButton {{
    background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 9px 16px;
    color: {TEXT_PRIMARY};
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: #241F17;
    border: 1px solid #453D2C;
}}
QPushButton:pressed {{
    background-color: {SURFACE};
}}
QPushButton[primary="true"] {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
    color: {ACCENT_TEXT};
}}
QPushButton[primary="true"]:hover {{
    background-color: {ACCENT_HOVER};
    border: 1px solid {ACCENT_HOVER};
}}
QPushButton[primary="true"]:pressed {{
    background-color: {ACCENT_PRESSED};
    border: 1px solid {ACCENT_PRESSED};
}}
QPushButton[compact="true"] {{
    padding: 6px 12px;
    font-size: 9pt;
}}
QPushButton[ghost="true"] {{
    background-color: transparent;
    border: 1px solid {BORDER};
    color: {TEXT_SECONDARY};
}}
QPushButton[ghost="true"]:hover {{
    color: {TEXT_PRIMARY};
    border: 1px solid #453D2C;
}}
QRadioButton, QCheckBox {{
    color: {TEXT_PRIMARY};
    spacing: 8px;
    font-size: 10pt;
}}
QRadioButton::indicator, QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid #4A4230;
    background-color: {SURFACE_ALT};
}}
QRadioButton::indicator {{
    border-radius: 8px;
}}
QCheckBox::indicator {{
    border-radius: 4px;
}}
QRadioButton::indicator:checked, QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
}}
QTableWidget {{
    background-color: {SURFACE};
    alternate-background-color: {SURFACE_ALT};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 14px;
    color: {TEXT_PRIMARY};
    selection-background-color: #3A3115;
    selection-color: {TEXT_PRIMARY};
}}
QHeaderView::section {{
    background-color: {SURFACE};
    color: {TEXT_SECONDARY};
    padding: 10px;
    border: none;
    border-bottom: 1px solid {BORDER};
    font-weight: 600;
    font-size: 9pt;
}}
QTableWidget::item {{
    padding: 6px;
    border-bottom: 1px solid {BORDER};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {SURFACE_ALT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_TEXT};
    outline: none;
}}
QProgressBar {{
    background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    max-height: 6px;
    min-height: 6px;
}}
QProgressBar::chunk {{
    border-radius: 3px;
}}
QScrollBar:vertical {{
    background: {BG};
    width: 11px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QMessageBox {{
    background-color: {SURFACE};
}}
""".format(
    BG=BG,
    SURFACE=SURFACE,
    SURFACE_ALT=SURFACE_ALT,
    BORDER=BORDER,
    FOCUS=FOCUS,
    TEXT_PRIMARY=TEXT_PRIMARY,
    TEXT_SECONDARY=TEXT_SECONDARY,
    ACCENT=ACCENT,
    ACCENT_HOVER=ACCENT_HOVER,
    ACCENT_PRESSED=ACCENT_PRESSED,
    ACCENT_TEXT=ACCENT_TEXT,
    SANS_FONT=SANS_FONT,
    MONO_FONT=MONO_FONT,
)


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


def make_label(text, object_name=None):
    label = QLabel(text)
    if object_name:
        label.setObjectName(object_name)
    return label


def make_field(password=False, object_name=None):
    field = QLineEdit()
    if password:
        field.setEchoMode(QLineEdit.Password)
    if object_name:
        field.setObjectName(object_name)
    return field


def make_button(text, primary=False, compact=False, ghost=False):
    button = QPushButton(text)
    button.setCursor(Qt.PointingHandCursor)
    if primary:
        button.setProperty("primary", "true")
    if compact:
        button.setProperty("compact", "true")
    if ghost:
        button.setProperty("ghost", "true")
    return button


def make_separator():
    line = QFrame()
    line.setObjectName("hline")
    line.setFixedHeight(1)
    return line


class LoginScreen(QWidget):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignCenter)

        card = QFrame()
        card.setObjectName("card")
        card.setFixedWidth(420)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 40, 40, 36)
        card_layout.setSpacing(2)

        brand = make_label("VAULT", "brand")
        brand.setAlignment(Qt.AlignCenter)
        tagline = make_label("Encrypted password manager", "tagline")
        tagline.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(brand)
        card_layout.addWidget(tagline)
        card_layout.addSpacing(30)

        form = QFormLayout()
        form.setSpacing(14)
        form.setLabelAlignment(Qt.AlignLeft)

        self.username_field = make_field()
        self.password_field = make_field(password=True)

        form.addRow(make_label("Username", "fieldLabel"), self.username_field)
        form.addRow(make_label("Master password", "fieldLabel"), self.password_field)
        card_layout.addLayout(form)

        self.message_label = make_label("", "errorLabel")
        self.message_label.setStyleSheet("color: " + ERROR + ";")
        self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setWordWrap(True)
        card_layout.addSpacing(8)
        card_layout.addWidget(self.message_label)

        login_button = make_button("Login", primary=True)
        login_button.clicked.connect(self.attempt_login)
        register_button = make_button("Create an account", ghost=True)
        register_button.clicked.connect(self.go_to_register)

        card_layout.addSpacing(10)
        card_layout.addWidget(login_button)
        card_layout.addSpacing(8)
        card_layout.addWidget(register_button)

        outer.addWidget(card)

        self.password_field.returnPressed.connect(self.attempt_login)
        self.username_field.returnPressed.connect(self.password_field.setFocus)

    def attempt_login(self):
        username = self.username_field.text().strip()
        password = self.password_field.text()
        if not username or not password:
            self.message_label.setText("Please fill in all fields")
            return
        success, message = self.controller.login(username, password)
        if not success:
            self.message_label.setText(message)
            self.password_field.clear()

    def go_to_register(self):
        self.reset()
        self.controller.show_screen("register")

    def reset(self):
        self.username_field.clear()
        self.password_field.clear()
        self.message_label.setText("")


class RegisterScreen(QWidget):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignCenter)

        card = QFrame()
        card.setObjectName("card")
        card.setFixedWidth(420)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 40, 40, 36)
        card_layout.setSpacing(2)

        brand = make_label("CREATE ACCOUNT", "brand")
        brand.setAlignment(Qt.AlignCenter)
        tagline = make_label("Your master password encrypts everything", "tagline")
        tagline.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(brand)
        card_layout.addWidget(tagline)
        card_layout.addSpacing(30)

        form = QFormLayout()
        form.setSpacing(14)
        form.setLabelAlignment(Qt.AlignLeft)

        self.username_field = make_field()
        self.password_field = make_field(password=True)
        self.confirm_field = make_field(password=True)

        form.addRow(make_label("Username", "fieldLabel"), self.username_field)
        form.addRow(make_label("Master password", "fieldLabel"), self.password_field)
        form.addRow(make_label("Confirm password", "fieldLabel"), self.confirm_field)
        card_layout.addLayout(form)

        self.message_label = make_label("", "errorLabel")
        self.message_label.setStyleSheet("color: " + ERROR + ";")
        self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setWordWrap(True)
        card_layout.addSpacing(8)
        card_layout.addWidget(self.message_label)

        create_account_button = make_button("Create account", primary=True)
        create_account_button.clicked.connect(self.attempt_register)
        back_button = make_button("Back to login", ghost=True)
        back_button.clicked.connect(self.go_to_login)

        card_layout.addSpacing(10)
        card_layout.addWidget(create_account_button)
        card_layout.addSpacing(8)
        card_layout.addWidget(back_button)

        outer.addWidget(card)

        self.confirm_field.returnPressed.connect(self.attempt_register)

    def attempt_register(self):
        username = self.username_field.text().strip()
        password = self.password_field.text()
        confirm = self.confirm_field.text()
        if not username or not password or not confirm:
            self.message_label.setText("Please fill in all fields")
            return
        if len(password) < 8:
            self.message_label.setText("Password must contain at least 8 characters")
            return
        if password != confirm:
            self.message_label.setText("Passwords do not match")
            return
        success, message = self.controller.register(username, password)
        if success:
            self.reset()
            QMessageBox.information(self, "Account created", "Your account has been created successfully")
            self.controller.show_screen("login")
        else:
            self.message_label.setText(message)

    def go_to_login(self):
        self.reset()
        self.controller.show_screen("login")

    def reset(self):
        self.username_field.clear()
        self.password_field.clear()
        self.confirm_field.clear()
        self.message_label.setText("")


class MainScreen(QWidget):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.password_generator = PasswordGenerator()
        self.id_generator = IdGenerator()
        self.password_visible = False
        self.entries_cache = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_bar_layout = QHBoxLayout(top_bar)
        top_bar_layout.setContentsMargins(24, 16, 24, 16)
        self.user_label = make_label("", "userLabel")
        top_bar_layout.addWidget(self.user_label)
        top_bar_layout.addStretch()
        logout_button = make_button("Logout", ghost=True, compact=True)
        logout_button.clicked.connect(self.logout)
        top_bar_layout.addWidget(logout_button)
        root.addWidget(top_bar)

        body = QHBoxLayout()
        body.setContentsMargins(24, 24, 24, 24)
        body.setSpacing(24)
        root.addLayout(body)

        left_panel = QFrame()
        left_panel.setObjectName("leftPanel")
        left_panel.setFixedWidth(380)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(24, 24, 24, 24)
        left_layout.setSpacing(2)
        left_layout.setAlignment(Qt.AlignTop)

        right_panel = QVBoxLayout()
        right_panel.setSpacing(12)

        body.addWidget(left_panel)
        body.addLayout(right_panel, 1)

        self.build_left_panel(left_layout)
        self.build_right_panel(right_panel)

    def build_left_panel(self, layout):
        layout.addWidget(make_label("NEW ENTRY", "sectionTitle"))
        layout.addSpacing(18)

        layout.addWidget(make_label("Service or website", "fieldLabel"))
        self.service_field = make_field()
        layout.addWidget(self.service_field)
        layout.addSpacing(12)

        layout.addWidget(make_label("Account username", "fieldLabel"))
        self.account_username_field = make_field()
        layout.addWidget(self.account_username_field)
        layout.addSpacing(12)

        layout.addWidget(make_label("Password", "fieldLabel"))
        password_row = QHBoxLayout()
        password_row.setSpacing(8)
        self.password_entry_field = make_field(password=True, object_name="passwordField")
        self.toggle_button = make_button("Show", compact=True)
        self.toggle_button.clicked.connect(self.toggle_visibility)
        password_row.addWidget(self.password_entry_field, 1)
        password_row.addWidget(self.toggle_button)
        layout.addLayout(password_row)

        layout.addSpacing(8)
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 7)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        layout.addWidget(self.strength_bar)
        layout.addSpacing(4)
        self.strength_label = make_label("", "fieldLabel")
        layout.addWidget(self.strength_label)

        self.password_entry_field.textChanged.connect(self.evaluate_password_strength)

        layout.addSpacing(16)
        layout.addWidget(make_label("Category", "fieldLabel"))
        category_row = QHBoxLayout()
        category_row.setSpacing(18)
        self.category_group = QButtonGroup(self)
        for index, category in enumerate(CATEGORIES):
            radio = QRadioButton(category)
            if index == 0:
                radio.setChecked(True)
            self.category_group.addButton(radio, index)
            category_row.addWidget(radio)
        category_row.addStretch()
        layout.addLayout(category_row)

        layout.addSpacing(16)
        layout.addWidget(make_label("Vault ID", "fieldLabel"))
        id_row = QHBoxLayout()
        id_row.setSpacing(8)
        self.id_field = make_field(object_name="idField")
        self.id_field.setReadOnly(True)
        new_id_button = make_button("New", compact=True)
        new_id_button.clicked.connect(self.generate_new_id)
        id_row.addWidget(self.id_field, 1)
        id_row.addWidget(new_id_button)
        layout.addLayout(id_row)

        layout.addSpacing(22)
        layout.addWidget(make_separator())
        layout.addSpacing(22)

        layout.addWidget(make_label("PASSWORD GENERATOR", "sectionTitle"))
        layout.addSpacing(18)

        length_row = QHBoxLayout()
        length_row.addWidget(make_label("Length", "fieldLabel"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(20)
        self.length_spin.setFixedWidth(80)
        length_row.addWidget(self.length_spin)
        length_row.addStretch()
        layout.addLayout(length_row)

        layout.addSpacing(12)
        self.use_upper_check = QCheckBox("Uppercase (A-Z)")
        self.use_upper_check.setChecked(True)
        self.use_lower_check = QCheckBox("Lowercase (a-z)")
        self.use_lower_check.setChecked(True)
        self.use_digits_check = QCheckBox("Digits (0-9)")
        self.use_digits_check.setChecked(True)
        self.use_symbols_check = QCheckBox("Symbols (!@#$...)")
        self.use_symbols_check.setChecked(True)
        for checkbox in (self.use_upper_check, self.use_lower_check, self.use_digits_check, self.use_symbols_check):
            layout.addWidget(checkbox)

        layout.addSpacing(18)
        generate_button = make_button("Generate password", primary=True)
        generate_button.clicked.connect(self.generate_password)
        layout.addWidget(generate_button)

        layout.addSpacing(8)
        add_button = make_button("Add entry", primary=True)
        add_button.clicked.connect(self.add_entry)
        layout.addWidget(add_button)

        layout.addSpacing(12)
        self.status_label = make_label(" ", "fieldLabel")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def build_right_panel(self, layout):
        filter_row = QHBoxLayout()
        filter_row.addWidget(make_label("Filter by category", "fieldLabel"))
        self.category_filter = QComboBox()
        self.category_filter.addItems(("All",) + CATEGORIES)
        self.category_filter.setFixedWidth(180)
        self.category_filter.currentTextChanged.connect(lambda _: self.refresh_list())
        filter_row.addWidget(self.category_filter)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Category", "Date added"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        layout.addWidget(self.table, 1)

        self.empty_label = make_label("No entries in this vault yet", "emptyState")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setVisible(False)
        layout.addWidget(self.empty_label)

        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)
        show_button = make_button("Show password")
        show_button.clicked.connect(self.show_selected_password)
        copy_button = make_button("Copy password")
        copy_button.clicked.connect(self.copy_selected_password)
        delete_button = make_button("Delete entry", ghost=True)
        delete_button.clicked.connect(self.delete_selected_entry)
        actions_row.addWidget(show_button)
        actions_row.addWidget(copy_button)
        actions_row.addWidget(delete_button)
        actions_row.addStretch()
        layout.addLayout(actions_row)

    def activate(self):
        self.user_label.setText("Logged in as: " + self.controller.current_user["username"])
        self.reset_form()
        self.category_filter.setCurrentText("All")
        self.refresh_list()

    def reset_form(self):
        self.service_field.clear()
        self.account_username_field.clear()
        self.password_entry_field.clear()
        self.password_entry_field.setEchoMode(QLineEdit.Password)
        self.toggle_button.setText("Show")
        self.password_visible = False
        self.category_group.button(0).setChecked(True)
        self.generate_new_id()
        self.set_strength("", TEXT_SECONDARY, 0)
        self.set_status(" ", TEXT_SECONDARY)

    def generate_new_id(self):
        self.id_field.setText(self.id_generator.generate())

    def toggle_visibility(self):
        self.password_visible = not self.password_visible
        self.password_entry_field.setEchoMode(QLineEdit.Normal if self.password_visible else QLineEdit.Password)
        self.toggle_button.setText("Hide" if self.password_visible else "Show")

    def selected_category(self):
        return self.category_group.checkedButton().text()

    def set_status(self, text, color):
        self.status_label.setStyleSheet("color: " + color + ";")
        self.status_label.setText(text)

    def set_strength(self, text, color, value):
        self.strength_label.setStyleSheet("color: " + color + ";")
        self.strength_label.setText(text)
        self.strength_bar.setValue(value)
        self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: " + color + "; }")

    def generate_password(self):
        length = self.length_spin.value()
        password = self.password_generator.generate(
            length,
            self.use_upper_check.isChecked(),
            self.use_lower_check.isChecked(),
            self.use_digits_check.isChecked(),
            self.use_symbols_check.isChecked(),
        )
        self.password_entry_field.setEchoMode(QLineEdit.Normal)
        self.toggle_button.setText("Hide")
        self.password_visible = True
        self.password_entry_field.setText(password)
        self.set_status("Password generated: " + str(len(password)) + " characters", SUCCESS)

    def evaluate_password_strength(self):
        password = self.password_entry_field.text()
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
            self.set_strength("", TEXT_SECONDARY, 0)
        elif score >= 6:
            self.set_strength("Strength: very high", SUCCESS, score)
        elif score >= 4:
            self.set_strength("Strength: high", SUCCESS, score)
        elif score >= 2:
            self.set_strength("Strength: medium", WARNING, score)
        else:
            self.set_strength("Strength: weak", ERROR, score)

    def add_entry(self):
        service = self.service_field.text().strip()
        account_username = self.account_username_field.text().strip()
        password = self.password_entry_field.text()
        category = self.selected_category()
        entry_id = self.id_field.text()

        if not service or not account_username or not password:
            self.set_status("All fields must be filled in", ERROR)
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
            self.set_status("ID conflict, please try again", ERROR)
            return

        self.reset_form()
        self.set_status("Entry added successfully", SUCCESS)
        self.refresh_list()

    def refresh_list(self):
        self.table.setRowCount(0)
        self.entries_cache = {}
        current_filter = self.category_filter.currentText()
        rows = self.controller.database.get_entries(self.controller.current_user["id"], current_filter)
        for entry_id, category, service, account_username, nonce, encrypted_password, creation_date in rows:
            display_date = creation_date.split("T")[0]
            row_index = self.table.rowCount()
            self.table.insertRow(row_index)
            service_item = QTableWidgetItem(service)
            service_item.setData(Qt.UserRole, entry_id)
            self.table.setItem(row_index, 0, service_item)
            self.table.setItem(row_index, 1, QTableWidgetItem(account_username))
            self.table.setItem(row_index, 2, QTableWidgetItem(category))
            self.table.setItem(row_index, 3, QTableWidgetItem(display_date))
            self.entries_cache[entry_id] = (nonce, encrypted_password)
        has_entries = self.table.rowCount() > 0
        self.table.setVisible(has_entries)
        self.empty_label.setVisible(not has_entries)

    def get_selection(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No selection", "Please select an entry from the list")
            return None
        row = selected_rows[0].row()
        return self.table.item(row, 0).data(Qt.UserRole)

    def show_selected_password(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        nonce, encrypted_password = self.entries_cache[entry_id]
        try:
            clear_password = CryptoEngine.decrypt(self.controller.session_key, nonce, encrypted_password)
            QMessageBox.information(self, "Password", clear_password)
        except InvalidTag:
            QMessageBox.critical(self, "Error", "Unable to decrypt this entry")

    def copy_selected_password(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        nonce, encrypted_password = self.entries_cache[entry_id]
        try:
            clear_password = CryptoEngine.decrypt(self.controller.session_key, nonce, encrypted_password)
            QApplication.clipboard().setText(clear_password)
            self.set_status("Password copied to clipboard", SUCCESS)
        except InvalidTag:
            QMessageBox.critical(self, "Error", "Unable to decrypt this entry")

    def delete_selected_entry(self):
        entry_id = self.get_selection()
        if entry_id is None:
            return
        confirmation = QMessageBox.question(
            self,
            "Confirmation",
            "Permanently delete this entry?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirmation == QMessageBox.Yes:
            self.controller.database.delete_entry(entry_id, self.controller.current_user["id"])
            self.refresh_list()

    def logout(self):
        self.controller.logout()


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vault — AES-256 Password Manager")
        self.resize(1180, 720)
        self.setMinimumSize(1040, 660)

        self.database = Database(DB_PATH)
        self.current_user = None
        self.session_key = None

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_screen = LoginScreen(self)
        self.register_screen = RegisterScreen(self)
        self.main_screen = MainScreen(self)

        self.stack.addWidget(self.login_screen)
        self.stack.addWidget(self.register_screen)
        self.stack.addWidget(self.main_screen)

        self.show_screen("login")

    def show_screen(self, name):
        mapping = {
            "login": self.login_screen,
            "register": self.register_screen,
            "main": self.main_screen,
        }
        screen = mapping[name]
        self.stack.setCurrentWidget(screen)
        if name == "main":
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
        self.show_screen("main")
        return True, "Login successful"

    def logout(self):
        self.current_user = None
        self.session_key = None
        self.login_screen.reset()
        self.show_screen("login")


if __name__ == "__main__":
    application = QApplication(sys.argv)
    application.setStyleSheet(STYLE_SHEET)
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
