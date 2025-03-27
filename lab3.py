import os
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from tkinter.scrolledtext import ScrolledText


class User:
    def __init__(self, name, password="", is_blocked=False, password_restrictions=None):
        self.name = name
        self.password = password
        self.is_blocked = is_blocked
        self.password_restrictions = password_restrictions or PasswordRestrictions()


class PasswordRestrictions:
    def __init__(self, enable_length=False, min_length=0,
                 require_upper=False, require_digit=False, require_special=False):
        self.enable_length = enable_length
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_digit = require_digit
        self.require_special = require_special


class UserManager:
    USER_FILE = "users.txt"
    users = []

    @classmethod
    def initialize(cls):
        if not os.path.exists(cls.USER_FILE):
            # Create default ADMIN user with no restrictions
            cls.users.append(User("ADMIN", "admin123", False, PasswordRestrictions()))
            cls.save_users()
        else:
            cls.load_users()

    @classmethod
    def save_users(cls):
        with open(cls.USER_FILE, "w") as f:
            for user in cls.users:
                f.write(f"{user.name},{user.password},{int(user.is_blocked)},"
                        f"{int(user.password_restrictions.enable_length)},"
                        f"{user.password_restrictions.min_length},"
                        f"{int(user.password_restrictions.require_upper)},"
                        f"{int(user.password_restrictions.require_digit)},"
                        f"{int(user.password_restrictions.require_special)}\n")

    @classmethod
    def load_users(cls):
        cls.users = []
        with open(cls.USER_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(',')
                cls.users.append(User(
                    parts[0],
                    parts[1],
                    bool(int(parts[2])),
                    PasswordRestrictions(
                        bool(int(parts[3])),
                        int(parts[4]),
                        bool(int(parts[5])),
                        bool(int(parts[6])),
                        bool(int(parts[7]))
                    )))

    @ classmethod
    def get_user(cls, name):
        return next((u for u in cls.users if u.name == name), None)

    @classmethod
    def add_user(cls, name):
        if not cls.get_user(name):
            cls.users.append(User(name))
            cls.save_users()
            return True
        return False

    @classmethod
    def block_user(cls, name, block):
        user = cls.get_user(name)
        if user and user.name != "ADMIN":
            user.is_blocked = block
            cls.save_users()
            return True
        return False

    @classmethod
    def validate_password(cls, password, restrictions):
        if restrictions.enable_length and len(password) < restrictions.min_length:
            return False

        # Проверка, что пароль не состоит только из заглавных букв
        if restrictions.require_upper:
            if password.isupper():
                return False
            if not any(c.isupper() for c in password):
                return False

        if restrictions.require_digit and not any(c.isdigit() for c in password):
            return False

        if restrictions.require_special and all(c.isalnum() for c in password):
            return False

        return True

    @classmethod
    def change_password(cls, name, old_pass, new_pass):
        user = cls.get_user(name)
        if user and user.password == old_pass:
            user.password = new_pass
            cls.save_users()
            return True
        return False


class LoginForm:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("400x300")
        self.login_attempts = 0

        self.setup_ui()
        UserManager.initialize()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(main_frame, text="Name:").grid(row=0, column=0, sticky=tk.E, pady=5)
        self.name_entry = ttk.Entry(main_frame)
        self.name_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(main_frame, text="Password:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.pass_entry = ttk.Entry(main_frame, show="*")
        self.pass_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)

    def login(self):
        name = self.name_entry.get()
        password = self.pass_entry.get()
        user = UserManager.get_user(name)

        if not user:
            messagebox.showerror("Error", "User not found")
            return

        if user.is_blocked:
            messagebox.showerror("Error", "User is blocked")
            return

        if user.password != password:
            self.login_attempts += 1
            if self.login_attempts >= 3:
                messagebox.showerror("Error", "Too many incorrect attempts. Exiting.")
                self.root.destroy()
            else:
                messagebox.showerror("Error", "Incorrect password")
            return

        self.root.destroy()
        MainForm(user)


class MainForm:
    def __init__(self, user):
        self.user = user
        self.root = tk.Tk()
        self.root.title(f"Main Form - Welcome {user.name}")
        self.root.geometry("900x700")

        self.setup_ui()
        self.root.mainloop()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.create_password_tab()
        self.create_admin_tab()

        if self.user.name != "ADMIN":
            self.notebook.tab(1, state="disabled")

    def create_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Change Password")

        frame = ttk.Frame(tab, padding="20")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Old Password:").grid(row=0, column=0, sticky=tk.E, pady=5)
        self.old_pass = ttk.Entry(frame, show="*")
        self.old_pass.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="New Password:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.new_pass = ttk.Entry(frame, show="*")
        self.new_pass.grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.E, pady=5)
        self.confirm_pass = ttk.Entry(frame, show="*")
        self.confirm_pass.grid(row=2, column=1, sticky=tk.W, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Change Password",
                   command=self.change_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Log Out",
                   command=self.root.destroy).pack(side=tk.LEFT, padx=5)

    def create_admin_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Admin Actions")

        canvas = tk.Canvas(tab)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.setup_admin_controls(scrollable_frame)

    def setup_admin_controls(self, parent):
        ttk.Label(parent, text="Admin Actions:",
                  font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        self.user_list = tk.Listbox(parent, height=10)
        self.user_list.pack(fill=tk.X, pady=5)
        self.load_user_list()
        self.user_list.bind("<<ListboxSelect>>", self.on_user_select)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Add User",
                   command=self.add_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Block User",
                   command=lambda: self.block_user(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Unblock User",
                   command=lambda: self.block_user(False)).pack(side=tk.LEFT, padx=5)

        self.setup_password_requirements(parent)

        ttk.Button(parent, text="Log Out",
                   command=self.root.destroy).pack(pady=10)

    def setup_password_requirements(self, parent):
        frame = ttk.LabelFrame(parent, text="Password Requirements", padding=10)
        frame.pack(fill=tk.X, pady=5)

        self.enable_length = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Enable Length Restriction",
                        variable=self.enable_length).pack(anchor=tk.W)

        len_frame = ttk.Frame(frame)
        len_frame.pack(fill=tk.X, pady=5)

        ttk.Label(len_frame, text="Min Length:").pack(side=tk.LEFT, padx=5)
        self.min_length = ttk.Entry(len_frame, width=5)
        self.min_length.pack(side=tk.LEFT)

        # Добавляем валидацию для ввода только цифр
        vcmd = (frame.register(self.validate_min_length), '%P')
        self.min_length.config(validate="key", validatecommand=vcmd)

        self.require_upper = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Require Uppercase",
                        variable=self.require_upper).pack(anchor=tk.W)

        self.require_digit = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Require Digit",
                        variable=self.require_digit).pack(anchor=tk.W)

        self.require_special = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Require Special",
                        variable=self.require_special).pack(anchor=tk.W)

        ttk.Button(frame, text="Update Requirements",
                   command=self.update_requirements).pack(pady=5)

    def validate_min_length(self, new_value):
        """Валидация ввода - только цифры"""
        if new_value == "" or new_value.isdigit():
            return True
        return False

    def load_user_list(self):
        self.user_list.delete(0, tk.END)
        for user in UserManager.users:
            status = " (blocked)" if user.is_blocked else ""
            self.user_list.insert(tk.END, user.name + status)

    def on_user_select(self, event):
        selection = self.user_list.curselection()
        if selection:
            # Сохраняем текущий выбор перед обновлением
            self.current_selection = selection[0]

            user_name = self.user_list.get(selection[0]).split()[0]
            user = UserManager.get_user(user_name)
            if user:
                pr = user.password_restrictions
                self.enable_length.set(pr.enable_length)
                self.min_length.delete(0, tk.END)
                self.min_length.insert(0, str(pr.min_length))
                self.require_upper.set(pr.require_upper)
                self.require_digit.set(pr.require_digit)
                self.require_special.set(pr.require_special)

    def change_password(self):
        old = self.old_pass.get()
        new = self.new_pass.get()
        confirm = self.confirm_pass.get()

        if new != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return

        if not UserManager.validate_password(new, self.user.password_restrictions):
            error_msg = "Password doesn't meet requirements:"
            pr = self.user.password_restrictions

            if pr.enable_length and len(new) < pr.min_length:
                error_msg += f"\n- Minimum length {pr.min_length} characters"

            if pr.require_upper:
                if new.isupper():
                    error_msg += "\n- Cannot be ALL uppercase letters"
                else:
                    error_msg += "\n- Must contain at least one uppercase letter"

            if pr.require_digit and not any(c.isdigit() for c in new):
                error_msg += "\n- Must contain at least one digit"

            if pr.require_special and all(c.isalnum() for c in new):
                error_msg += "\n- Must contain at least one special character"

            messagebox.showerror("Error", error_msg)
            return

        if UserManager.change_password(self.user.name, old, new):
            messagebox.showinfo("Success", "Password changed")
        else:
            messagebox.showerror("Error", "Incorrect old password")

    def add_user(self):
        name = simpledialog.askstring("Add User", "Enter new user name:")
        if name:
            if UserManager.add_user(name):
                self.load_user_list()
            else:
                messagebox.showerror("Error", "Invalid or duplicate user name")

    def block_user(self, block):
        selection = self.user_list.curselection()
        if selection:
            user_name = self.user_list.get(selection[0]).split()[0]
            if user_name == "ADMIN":
                messagebox.showerror("Error", "Cannot block ADMIN")
                return

            if UserManager.block_user(user_name, block):
                self.load_user_list()
                action = "blocked" if block else "unblocked"
                messagebox.showinfo("Success", f"User {user_name} {action}")
            else:
                messagebox.showerror("Error", "Operation failed")

    def update_requirements(self):
        if hasattr(self, 'current_selection'):
            self.user_list.selection_set(self.current_selection)
            selection = self.user_list.curselection()
        else:
            selection = self.user_list.curselection()

        if not selection:
            messagebox.showerror("Error", "Select a user first")
            return

        user_name = self.user_list.get(selection[0]).split()[0]
        user = UserManager.get_user(user_name)
        if not user:
            messagebox.showerror("Error", "User not found")
            return

        try:
            min_len = int(self.min_length.get()) if self.min_length.get() else 0
            if min_len < 0:
                raise ValueError("Min length cannot be negative")

            user.password_restrictions = PasswordRestrictions(
                self.enable_length.get(),
                min_len,
                self.require_upper.get(),
                self.require_digit.get(),
                self.require_special.get()
            )

            # Проверка, что требования не противоречат друг другу
            if (user.password_restrictions.require_upper and
                    user.password_restrictions.require_digit == False and
                    user.password_restrictions.require_special == False):
                messagebox.showwarning("Warning",
                                       "With only 'Require Uppercase' enabled, passwords must contain:\n"
                                       "- At least one uppercase letter\n"
                                       "- But not ALL uppercase letters")

            UserManager.save_users()
            messagebox.showinfo("Success", "Requirements updated")

            current_idx = selection[0]
            self.load_user_list()
            self.user_list.selection_set(current_idx)
            self.user_list.see(current_idx)

        except ValueError as e:
            messagebox.showerror("Error", f"Invalid value: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginForm(root)
    root.mainloop()