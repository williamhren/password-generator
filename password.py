"""Random Password Generator.

Implements the Software Design Specification (Python 3.12, tkinter, Windows 11).
Nothing is stored, logged or written to disk.

Layers (SDS 3.1) and components (SDS 3.2):
    PasswordApp        - tkinter window (presentation layer)
    StrengthBar        - Appendix B colour scale shown in the window
    InputValidator     - validate(length, sets)
    CharacterPool      - build_pool(sets)
    PasswordGenerator  - generate(length, pool)   (only class that uses `secrets`)
    EntropyCalculator  - entropy(length, pool_size), strength_label(bits)
    ClipboardHandler   - copy(password)
    PasswordLog        - passwords saved when Copy is clicked, with time and purpose
    LogWindow          - the "Logs" window that lists the saved passwords

NOTE: the original SDS (R-06) says passwords are not stored. This version adds a
log of COPIED passwords on request. Clicking Copy asks what the password is for,
then saves Timestamp, Purpose and Password as one row of LOG_FILE (a CSV file
with a header row). The log is plain text, so anyone who can open that file can
read the passwords.
"""

import csv
import math
import secrets
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

# --- Appendix A: character pool (88 characters in total) -------------------
CHARACTER_SETS = {
    "lowercase": "abcdefghijklmnopqrstuvwxyz",  # 26
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",  # 26
    "digits": "0123456789",                     # 10
    "symbols": "!@#$%^&*()-_=+[]{};:,.<>?/",    # 26
}

# --- Requirements ----------------------------------------------------------
DEFAULT_LENGTH = 16   # SDS 4.1: Length field default
MIN_LENGTH = 4        # SDS 1.4 / R-02: minimum length
# The SDS does not yet define a maximum (listed as a next step). 128 keeps the
# window responsive; change it here once the specification fixes a value.
MAX_LENGTH = 128

# --- Password log ---------------------------------------------------------
LOG_FILE = Path(__file__).with_name("password_log.csv")  # header + one row per password
LEGACY_LOG_FILE = Path(__file__).with_name("password_log.txt")  # older "time<TAB>password" log
LOG_COLUMNS = ("Timestamp", "Purpose", "Password")
TIMESTAMP_FORMAT = "%m/%d/%Y %I:%M %p"          # e.g. 10/28/2026 04:25 PM
LEGACY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"   # used by earlier versions of the log
MAX_PURPOSE_LENGTH = 100
NO_PURPOSE = "(not recorded)"  # purpose given to entries imported from the older log
MAX_UNIQUE_ATTEMPTS = 1000  # tries to find a password that is not in the log

# --- Appendix B: entropy strength scale (upper bound exclusive, label) -----
STRENGTH_SCALE = (
    (40, "Weak"),
    (60, "Fair"),
    (80, "Good"),
    (100, "Strong"),
)
EXCELLENT_MAX = 128   # 100 to 128 is Excellent; above 128 is Exceptional

# Bar segments for the strength meter: (label, start bits, end bits, colour).
# The last segment ends at BAR_MAX_BITS only so it can be drawn.
BAR_MAX_BITS = 160
BAR_SEGMENTS = (
    ("Weak", 0, 40, "#D32F2F"),
    ("Fair", 40, 60, "#F57C00"),
    ("Good", 60, 80, "#FBC02D"),
    ("Strong", 80, 100, "#7CB342"),
    ("Excellent", 100, 128, "#2E7D32"),
    ("Exceptional", 128, BAR_MAX_BITS, "#00695C"),
)


class InputValidator:
    """Rejects a non-number, a length out of range, or no character set."""

    @staticmethod
    def validate(length, sets):
        """Return the length as an int, or raise ValueError.

        length: text from the Length field.
        sets:   names of the checked character sets.
        """
        try:
            value = int(str(length).strip())
        except ValueError:
            raise ValueError("Length must be a whole number.") from None
        if value < MIN_LENGTH:
            raise ValueError(f"Length must be at least {MIN_LENGTH}.")
        if value > MAX_LENGTH:
            raise ValueError(f"Length must be at most {MAX_LENGTH}.")
        if not sets:
            raise ValueError("Select at least one character set.")
        return value


    @staticmethod
    def validate_purpose(text):
        """Return the purpose without surrounding spaces, or raise ValueError."""
        purpose = " ".join(str(text).split())  # trims and collapses whitespace/newlines
        if not purpose:
            raise ValueError("Please enter what the password is for.")
        if len(purpose) > MAX_PURPOSE_LENGTH:
            raise ValueError(f"Keep it to {MAX_PURPOSE_LENGTH} characters or fewer.")
        return purpose


class CharacterPool:
    """Merges the selected Appendix A sets into one pool."""

    @staticmethod
    def build_pool(sets):
        """Return one string of all characters in the selected sets."""
        # Iterate CHARACTER_SETS so the order is fixed and duplicates cannot occur.
        return "".join(chars for name, chars in CHARACTER_SETS.items() if name in sets)


class PasswordGenerator:
    """Generates the password. The only class that depends on `secrets`."""

    @staticmethod
    def generate(length, pool):
        """Pick `length` characters from `pool`, each with secrets.choice."""
        return "".join(secrets.choice(pool) for _ in range(length))


    @staticmethod
    def generate_unique(length, pool, used):
        """Like generate(), but never returns a password that is in `used`."""
        for _ in range(MAX_UNIQUE_ATTEMPTS):
            password = PasswordGenerator.generate(length, pool)
            if password not in used:
                return password
        raise RuntimeError(
            "Could not find a password that is not in the log. "
            "Use a longer length or more character sets."
        )


class EntropyCalculator:
    """Computes entropy in bits and the Appendix B strength label."""

    @staticmethod
    def entropy(length, pool_size):
        """Return length x log2(pool_size)."""
        return length * math.log2(pool_size)

    @staticmethod
    def strength_label(bits):
        """Return Weak, Fair, Good, Strong, Excellent or Exceptional."""
        for upper_bound, label in STRENGTH_SCALE:
            if bits < upper_bound:
                return label
        return "Excellent" if bits <= EXCELLENT_MAX else "Exceptional"


class ClipboardHandler:
    """Copies the password to the clipboard through tkinter."""

    def __init__(self, widget):
        self._widget = widget

    def copy(self, password):
        """Clear the tkinter clipboard and append the password."""
        self._widget.clipboard_clear()
        self._widget.clipboard_append(password)


class PasswordLog:
    """Passwords saved when Copy is clicked: Timestamp, Purpose and Password.

    Kept in memory and stored in a CSV file (one header row, one row per
    password) so it survives restarts. The csv module handles commas, quotes and
    any other characters in the purpose, so rows never get mixed up.
    """

    def __init__(self, path=None, legacy_path=None):
        self._path = Path(path or LOG_FILE)
        self._legacy_path = Path(legacy_path or LEGACY_LOG_FILE)
        self._entries = []  # list of (timestamp, purpose, password), oldest first
        self._passwords = set()
        self._load()

    @staticmethod
    def _normalize_timestamp(timestamp):
        """Return `timestamp` as mm/dd/yyyy hh:mm AM/PM; leave unknown text as it is."""
        for fmt in (TIMESTAMP_FORMAT, LEGACY_TIMESTAMP_FORMAT):
            try:
                return datetime.strptime(timestamp, fmt).strftime(TIMESTAMP_FORMAT)
            except ValueError:
                continue
        return timestamp

    def _remember(self, timestamp, purpose, password):
        if password:
            self._entries.append((self._normalize_timestamp(timestamp), purpose, password))
            self._passwords.add(password)

    def _load(self):
        if self._path.exists():
            with self._path.open(newline="", encoding="utf-8-sig") as file:
                rows = list(csv.DictReader(file))
            for row in rows:
                self._remember(
                    row.get("Timestamp") or "",
                    row.get("Purpose") or "",
                    row.get("Password") or "",
                )
            # Rewrite the file if older rows used the previous timestamp format.
            if any(
                (row.get("Timestamp") or "") != entry[0]
                for row, entry in zip(rows, self._entries)
            ):
                self._write_all()
        elif self._legacy_path.exists():
            self._import_legacy()

    def _import_legacy(self):
        """Bring in passwords from the older 'timestamp<TAB>password' log."""
        with self._legacy_path.open(encoding="utf-8") as file:
            for line in file:
                timestamp, separator, password = line.rstrip("\r\n").partition("\t")
                if separator:
                    self._remember(timestamp, NO_PURPOSE, password)
        self._write_all()

    def _write_all(self):
        """Rewrite the whole file: header row, then every entry."""
        with self._path.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            writer.writerow(LOG_COLUMNS)
            writer.writerows(self._entries)

    def add(self, password, purpose):
        """Save `password` with the current time and its purpose."""
        timestamp = datetime.now().strftime(TIMESTAMP_FORMAT)
        if not self._path.exists() or self._path.stat().st_size == 0:
            self._write_all()
        with self._path.open("a", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow((timestamp, purpose, password))
        self._remember(timestamp, purpose, password)

    def clear(self):
        """Delete every logged password, in memory and in the file."""
        self._entries.clear()
        self._passwords.clear()
        self._write_all()

    @property
    def entries(self):
        """Logged (timestamp, purpose, password) rows, oldest first."""
        return list(self._entries)

    def search(self, query):
        """Return matching rows, newest first.

        Every word in `query` must appear (any case) in the time, the purpose or
        the password. An empty query returns all rows.
        """
        words = query.lower().split()
        return [
            entry
            for entry in reversed(self._entries)
            if all(word in " ".join(entry).lower() for word in words)
        ]

    @property
    def passwords(self):
        """Set of logged passwords, used to avoid generating a repeat."""
        return self._passwords


class LogWindow(tk.Toplevel):
    """Lists the logged passwords, newest first, with a search bar and a Copy button."""

    def __init__(self, master, log, clipboard):
        super().__init__(master)
        self.title("Password Logs")
        self._log = log
        self._clipboard = clipboard

        frame = ttk.Frame(self, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(1, weight=1)

        # Search bar: filters the table as you type.
        ttk.Label(frame, text="Search:").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(6, 6), pady=(0, 8))
        ttk.Button(frame, text="Clear", command=self.clear_search).grid(
            row=0, column=2, columnspan=2, sticky="e", pady=(0, 8)
        )
        self.search_var.trace_add("write", lambda *_: self.refresh())
        self.search_entry.bind("<Escape>", lambda _event: self.clear_search())

        self.table = ttk.Treeview(
            frame, columns=("time", "purpose", "password"), show="headings", height=12
        )
        self.table.heading("time", text="Time", anchor="w")
        self.table.heading("purpose", text="Purpose", anchor="w")
        self.table.heading("password", text="Password", anchor="w")
        self.table.column("time", width=175, stretch=False, anchor="w")
        self.table.column("purpose", width=220, anchor="w")
        self.table.column("password", width=260, anchor="w")
        self.table.grid(row=1, column=0, columnspan=3, sticky="nsew")
        self.table.bind("<<TreeviewSelect>>", lambda _event: self._update_copy_button())
        self.table.bind("<Double-1>", lambda _event: self.copy_selected())

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        scrollbar.grid(row=1, column=3, sticky="ns")
        self.table.configure(yscrollcommand=scrollbar.set)

        self.count_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.count_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        buttons = ttk.Frame(frame)
        buttons.grid(row=2, column=1, columnspan=3, sticky="e", pady=(8, 0))
        self.copy_button = ttk.Button(
            buttons, text="Copy", command=self.copy_selected, state="disabled"
        )
        self.copy_button.grid(row=0, column=0, padx=(0, 8))
        ttk.Button(buttons, text="Clear log", command=self.clear).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(buttons, text="Close", command=self.destroy).grid(row=0, column=2)

        self.refresh()
        self.search_entry.focus_set()

    def _count_text(self):
        total = len(self._log.entries)
        if self.search_var.get().strip():
            return f"{len(self.table.get_children())} of {total} shown"
        return f"{total} saved"

    def _update_copy_button(self):
        state = "normal" if self.table.selection() else "disabled"
        self.copy_button.configure(state=state)

    def copy_selected(self):
        """Copy the password of the selected row to the clipboard."""
        selection = self.table.selection()
        if not selection:
            return
        _timestamp, purpose, password = self.table.item(selection[0], "values")
        self._clipboard.copy(str(password))
        self.count_var.set(f"Copied password for: {purpose}")
        self.after(2500, self._restore_count)

    def _restore_count(self):
        if self.winfo_exists():
            self.count_var.set(self._count_text())

    def refresh(self):
        """Reload the table from the log, applying the search text."""
        query = self.search_var.get()
        rows = self._log.search(query)
        self.table.delete(*self.table.get_children())
        for timestamp, purpose, password in rows:
            self.table.insert("", "end", values=(timestamp, purpose, password))
        self.count_var.set(self._count_text())
        self._update_copy_button()

    def clear_search(self):
        self.search_var.set("")  # the trace refreshes the table

    def clear(self):
        if messagebox.askyesno(
            "Clear log", "Delete all logged passwords?", parent=self
        ):
            self._log.clear()
            self.refresh()


class StrengthBar(tk.Canvas):
    """Colour bar of the Appendix B scale, with a marker at the current entropy."""

    WIDTH = 420
    BAR_TOP = 14
    BAR_HEIGHT = 16

    def __init__(self, master):
        super().__init__(
            master, width=self.WIDTH, height=64, highlightthickness=0, bd=0
        )
        self._draw_scale()

    def _x(self, bits):
        return min(bits, BAR_MAX_BITS) / BAR_MAX_BITS * self.WIDTH

    def _draw_scale(self):
        top, bottom = self.BAR_TOP, self.BAR_TOP + self.BAR_HEIGHT
        for label, start, end, colour in BAR_SEGMENTS:
            left, right = self._x(start), self._x(end)
            self.create_rectangle(left, top, right, bottom, fill=colour, outline="white")
            # Tick label under each boundary, then the band name.
            self.create_text(left + 1, bottom + 8, text=str(start), anchor="w",
                             font=("Segoe UI", 7), fill="#555555")
            self.create_text((left + right) / 2, bottom + 22, text=label,
                             font=("Segoe UI", 7), fill="#333333")
        self.create_text(self.WIDTH, bottom + 8, text="bits", anchor="e",
                         font=("Segoe UI", 7), fill="#555555")

    def set_value(self, bits):
        """Move the marker to `bits`, or hide it when bits is None."""
        self.delete("marker")
        if bits is None:
            return
        x = self._x(bits)
        top = self.BAR_TOP
        self.create_polygon(x - 5, top - 12, x + 5, top - 12, x, top - 1,
                            fill="#0E1A2B", outline="", tags="marker")
        self.create_line(x, top, x, top + self.BAR_HEIGHT, fill="#0E1A2B",
                         width=2, tags="marker")


class PasswordApp:
    """The tkinter window (SDS 4.0). Layout uses grid(), never place()."""

    def __init__(self, root):
        self.root = root
        root.title("Password Generator")
        root.resizable(False, False)

        self.clipboard = ClipboardHandler(root)
        self.log = PasswordLog()
        self.log_window = None

        self.length_var = tk.StringVar(value=str(DEFAULT_LENGTH))
        self.set_vars = {name: tk.BooleanVar(value=True) for name in CHARACTER_SETS}
        self.password_var = tk.StringVar()
        self.entropy_var = tk.StringVar()
        self.message_var = tk.StringVar()

        self._build_widgets()

    # -- layout -------------------------------------------------------------
    def _build_widgets(self):
        frame = ttk.Frame(self.root, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Length:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.length_var, width=6).grid(
            row=0, column=1, sticky="w", padx=(6, 0)
        )

        checks = ttk.Frame(frame)
        checks.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        for column, name in enumerate(CHARACTER_SETS):
            ttk.Checkbutton(
                checks, text=name.capitalize(), variable=self.set_vars[name]
            ).grid(row=0, column=column, sticky="w", padx=(0, 10))

        ttk.Entry(
            frame, textvariable=self.password_var, width=42, state="readonly"
        ).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        ttk.Label(frame, textvariable=self.entropy_var).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )
        self.strength_bar = StrengthBar(frame)
        self.strength_bar.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(frame, textvariable=self.message_var, foreground="#B00020").grid(
            row=5, column=0, columnspan=2, sticky="w"
        )

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(buttons, text="Generate", command=self.on_generate).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(buttons, text="Copy", command=self.on_copy).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(buttons, text="Logs", command=self.on_logs).grid(row=0, column=2)

    # -- behavior -----------------------------------------------------------
    def selected_sets(self):
        """Names of the checked character sets."""
        return [name for name, var in self.set_vars.items() if var.get()]

    def on_generate(self):
        """Validate, build the pool, generate, score, then show the result."""
        sets = self.selected_sets()
        try:
            length = InputValidator.validate(self.length_var.get(), sets)
        except ValueError as error:
            self.show_error(error)
            return
        pool = CharacterPool.build_pool(sets)
        try:
            password = PasswordGenerator.generate_unique(
                length, pool, self.log.passwords
            )
        except RuntimeError as error:
            self.show_error(error)
            return
        bits = EntropyCalculator.entropy(length, len(pool))
        self.show(password, bits, EntropyCalculator.strength_label(bits))

    def ask_purpose(self):
        """Ask what the password is for. Return the text, or None if cancelled."""
        while True:
            text = simpledialog.askstring(
                "Purpose",
                "What are you using this password for?",
                parent=self.root,
            )
            if text is None:
                return None
            try:
                return InputValidator.validate_purpose(text)
            except ValueError as error:
                messagebox.showwarning("Purpose", str(error), parent=self.root)

    def on_copy(self):
        """Ask the purpose, copy the password, and save it in the log."""
        password = self.password_var.get()
        if not password:
            self.message_var.set("Generate a password first.")
            return
        summary = self.entropy_var.get().split("  ·  ")[0]

        if password in self.log.passwords:  # already logged: copy again, no new entry
            self.clipboard.copy(password)
            self.message_var.set("")
            self.entropy_var.set(summary + "  ·  Copied (already in the log)")
            return

        purpose = self.ask_purpose()
        if purpose is None:
            self.message_var.set("Copy cancelled.")
            return
        self.clipboard.copy(password)
        try:
            self.log.add(password, purpose)
        except OSError as error:
            self.message_var.set(f"Copied, but the log could not be saved: {error}")
            return
        self.message_var.set("")
        self.entropy_var.set(summary + "  ·  Copied and logged")
        if self.log_window is not None and self.log_window.winfo_exists():
            self.log_window.refresh()

    def on_logs(self):
        """Open the Logs window, or bring it to the front if it is open."""
        if self.log_window is not None and self.log_window.winfo_exists():
            self.log_window.refresh()
            self.log_window.lift()
            return
        self.log_window = LogWindow(self.root, self.log, self.clipboard)

    def show(self, password, bits, label):
        self.message_var.set("")
        self.password_var.set(password)
        self.entropy_var.set(f"Entropy: {bits:.2f} bits ({label})")
        self.strength_bar.set_value(bits)

    def show_error(self, error):
        """Show the error instead of a password (SDS 3.4)."""
        self.password_var.set("")
        self.entropy_var.set("")
        self.strength_bar.set_value(None)
        self.message_var.set(str(error))


def main():
    root = tk.Tk()
    PasswordApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()