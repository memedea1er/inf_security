import os
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from tkinter.scrolledtext import ScrolledText
import math
import time
import itertools
from threading import Thread


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


class PasswordStrengthAnalyzer:
    @staticmethod
    def get_alphabet_size(password: str) -> int:
        lowercase = any(c.islower() for c in password)
        uppercase = any(c.isupper() for c in password)
        digits = any(c.isdigit() for c in password)
        special = any(not c.isalnum() for c in password)

        alphabet_size = 0
        if lowercase:
            alphabet_size += 26
        if uppercase:
            alphabet_size += 26
        if digits:
            alphabet_size += 10
        if special:
            alphabet_size += 33

        return alphabet_size

    @staticmethod
    def calculate_combinations(password_length: int, alphabet_size: int) -> int:
        return alphabet_size ** password_length

    @staticmethod
    def estimate_brute_force_time(combinations: int, attempts_per_second: int, pause_time,
                                  attempts_before_pause) -> float:
        total_time = combinations / attempts_per_second + ((combinations - 1) * pause_time / attempts_before_pause)
        return total_time

    @staticmethod
    def format_time(seconds: float) -> str:
        minutes, sec = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        months, days = divmod(days, 30)
        years, months = divmod(months, 12)

        return f"{int(years)} лет {int(months)} месяцев {int(days)} дней {int(hours)} часов {int(minutes)} минут {int(sec)} секунд"

    @classmethod
    def analyze_password(cls, password: str, attempts_per_second=1000, pause_time=10, attempts_before_pause=1000):
        alphabet_size = cls.get_alphabet_size(password)
        combinations = cls.calculate_combinations(len(password), alphabet_size)
        time_seconds = cls.estimate_brute_force_time(combinations, attempts_per_second, pause_time,
                                                     attempts_before_pause)

        result = []
        result.append(f"Пароль: {password}")
        result.append(f"Длина пароля: {len(password)} символов")
        result.append(f"Мощность алфавита: {alphabet_size}")
        result.append(f"Число возможных комбинаций: {combinations}")
        result.append(f"Время подбора: {cls.format_time(time_seconds)}")

        return "\n".join(result)


class PasswordCracker:
    RUS_TO_LAT = {
        'а': 'f', 'б': ',', 'в': 'd', 'г': 'u', 'д': 'l', 'е': 't', 'ё': '`',
        'ж': ';', 'з': 'p', 'и': 'b', 'й': 'q', 'к': 'r', 'л': 'k', 'м': 'v',
        'н': 'y', 'о': 'j', 'п': 'g', 'р': 'h', 'с': 'c', 'т': 'n', 'у': 'e',
        'ф': 'a', 'х': '[', 'ц': 'w', 'ч': 'x', 'ш': 'i', 'щ': 'o', 'ъ': ']',
        'ы': 's', 'ь': 'm', 'э': "'", 'ю': '.', 'я': 'z'
    }

    @staticmethod
    def russian_to_latin_layout(russian_word):
        return ''.join(PasswordCracker.RUS_TO_LAT.get(c.lower(), c) for c in russian_word)

    @staticmethod
    def load_dictionary(filename="dictionary.txt"):
        if not os.path.exists(filename):
            return []
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    @staticmethod
    def dictionary_attack(username, login_function):
        """Атака по словарю с проверкой через функцию входа"""
        dictionary = PasswordCracker.load_dictionary()
        start_time = time.time()
        attempts = 0

        # Проверяем слова из словаря
        for word in dictionary:
            attempts += 1
            if login_function(username, word):
                return True, attempts, time.time() - start_time, word

            # Проверяем английскую раскладку
            lat_word = PasswordCracker.russian_to_latin_layout(word)
            attempts += 1
            if login_function(username, lat_word):
                return True, attempts, time.time() - start_time, lat_word

        return False, attempts, time.time() - start_time, None

    @staticmethod
    def brute_force_attack(username, login_function, max_length=6):
        """Полный перебор с проверкой через функцию входа"""
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
        start_time = time.time()
        attempts = 0

        for length in range(1, max_length + 1):
            for guess in itertools.product(charset, repeat=length):
                guess_str = ''.join(guess)
                attempts += 1
                if login_function(username, guess_str):
                    return True, attempts, time.time() - start_time, guess_str

        return False, attempts, time.time() - start_time, None


class LoginForm:
    def __init__(self, root):
        self.root = root
        self.root.title("Вход в систему")
        self.root.geometry("450x350")
        self.login_attempts = 0
        self.cracking = False  # Флаг выполнения подбора

        self.setup_ui()
        UserManager.initialize()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Поля ввода
        ttk.Label(main_frame, text="Логин:").grid(row=0, column=0, sticky=tk.E, pady=5)
        self.name_entry = ttk.Entry(main_frame)
        self.name_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(main_frame, text="Пароль:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.pass_entry = ttk.Entry(main_frame, show="*")
        self.pass_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Войти", command=self.login).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Анализ пароля",
                   command=self.check_password_strength).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Подобрать пароль",
                   command=self.show_crack_dialog).pack(side=tk.LEFT, padx=5)

    def show_crack_dialog(self):
        if self.cracking:
            messagebox.showwarning("Внимание", "Подбор уже выполняется!")
            return

        username = self.name_entry.get()
        if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя")
            return

        crack_dialog = tk.Toplevel(self.root)
        crack_dialog.title(f"Подбор пароля для {username}")
        crack_dialog.geometry("600x500")

        # Настройки подбора
        settings_frame = ttk.LabelFrame(crack_dialog, text="Настройки", padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        self.method_var = tk.StringVar(value="dictionary")
        ttk.Radiobutton(settings_frame, text="По словарю",
                        variable=self.method_var, value="dictionary").pack(anchor=tk.W)
        ttk.Radiobutton(settings_frame, text="Полный перебор",
                        variable=self.method_var, value="bruteforce").pack(anchor=tk.W)

        ttk.Label(settings_frame, text="Макс. длина (для brute force):").pack(anchor=tk.W)
        self.max_length = ttk.Entry(settings_frame)
        self.max_length.pack(anchor=tk.W)
        self.max_length.insert(0, "6")

        # Кнопки управления
        btn_frame = ttk.Frame(crack_dialog)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Начать подбор",
                   command=lambda: self.start_cracking(username, crack_dialog)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Остановить",
                   command=lambda: setattr(self, 'cracking', False)).pack(side=tk.LEFT, padx=5)

        # Вывод результатов
        result_frame = ttk.LabelFrame(crack_dialog, text="Результаты", padding=10)
        result_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)

        self.crack_result_text = ScrolledText(result_frame, wrap=tk.WORD)
        self.crack_result_text.pack(expand=True, fill=tk.BOTH)
        self.crack_result_text.insert(tk.END, "Готов к работе...")
        self.crack_result_text.config(state=tk.DISABLED)

    def start_cracking(self, username, dialog):
        def login_func(pwd):
            self.pass_entry.delete(0, tk.END)
            self.pass_entry.insert(0, pwd)
            return self.login(simulated=True)

        self.cracking = True
        self.crack_result_text.config(state=tk.NORMAL)
        self.crack_result_text.delete(1.0, tk.END)
        self.crack_result_text.insert(tk.END, f"Начало подбора для {username}...\n")
        self.crack_result_text.config(state=tk.DISABLED)

        # Запуск в отдельном потоке
        Thread(target=lambda: self.run_cracking(username, login_func, dialog), daemon=True).start()

    def run_cracking(self, username, login_func, dialog):
        start_time = time.time()
        attempts = 0
        found_pass = None

        if self.method_var.get() == "dictionary":
            dictionary = PasswordCracker.load_dictionary()

            # Проверка простых комбинаций
            simple_guesses = ["123456", "password", "qwerty", username]
            for guess in simple_guesses:
                if not self.cracking: break
                attempts += 1
                if login_func(guess):
                    found_pass = guess
                    break

            # Проверка словаря
            if not found_pass:
                for word in dictionary:
                    if not self.cracking: break

                    # Оригинальное слово
                    attempts += 1
                    if login_func(word):
                        found_pass = word
                        break

                    # Английская раскладка
                    lat_word = PasswordCracker.russian_to_latin_layout(word)
                    attempts += 1
                    if login_func(lat_word):
                        found_pass = lat_word
                        break

                    # С цифрами
                    for i in range(100):
                        if not self.cracking: break
                        attempts += 1
                        if login_func(f"{word}{i}"):
                            found_pass = f"{word}{i}"
                            break

                        attempts += 1
                        if login_func(f"{lat_word}{i}"):
                            found_pass = f"{lat_word}{i}"
                            break
        else:
            # Brute-force атака
            charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
            max_len = int(self.max_length.get())

            for length in range(1, max_len + 1):
                if not self.cracking: break

                for guess in itertools.product(charset, repeat=length):
                    if not self.cracking: break

                    guess_str = ''.join(guess)
                    attempts += 1
                    if login_func(guess_str):
                        found_pass = guess_str
                        break

        # Вывод результатов
        elapsed = time.time() - start_time
        self.crack_result_text.config(state=tk.NORMAL)
        self.crack_result_text.insert(tk.END, "\n=== Результат ===\n")

        if found_pass:
            self.crack_result_text.insert(tk.END, f"Пароль найден: {found_pass}\n")
            self.pass_entry.delete(0, tk.END)
            self.pass_entry.insert(0, found_pass)
        else:
            self.crack_result_text.insert(tk.END, "Пароль не найден\n")

        self.crack_result_text.insert(tk.END,
                                      f"Попыток: {attempts}\nВремя: {elapsed:.2f} сек.\n"
                                      f"Скорость: {attempts / elapsed:.1f} попыток/сек\n")

        self.crack_result_text.see(tk.END)
        self.crack_result_text.config(state=tk.DISABLED)
        self.cracking = False

    def login(self, simulated=False):
        username = self.name_entry.get()
        password = self.pass_entry.get()
        user = UserManager.get_user(username)

        if not user:
            if not simulated:
                messagebox.showerror("Ошибка", "Пользователь не найден")
            return False

        if user.is_blocked:
            if not simulated:
                messagebox.showerror("Ошибка", "Пользователь заблокирован")
            return False

        if user.password == password:
            if not simulated:
                self.root.destroy()
                MainForm(user)
            return True
        else:
            if not simulated:
                self.login_attempts += 1
                if self.login_attempts >= 3:
                    messagebox.showerror("Ошибка", "Слишком много попыток!")
                    self.root.destroy()
                else:
                    messagebox.showerror("Ошибка", "Неверный пароль")
            return False

    def check_password_strength(self):
        password = self.pass_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return

        analysis = PasswordStrengthAnalyzer.analyze_password(password)
        messagebox.showinfo("Анализ пароля", analysis)


class MainForm:
    def __init__(self, user):
        self.user = user
        self.root = tk.Tk()
        self.root.title(f"Главное меню - {user.name}")
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
        self.notebook.add(tab, text="Смена пароля")

        frame = ttk.Frame(tab, padding="20")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Текущий пароль:").grid(row=0, column=0, sticky=tk.E, pady=5)
        self.old_pass = ttk.Entry(frame, show="*")
        self.old_pass.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Новый пароль:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.new_pass = ttk.Entry(frame, show="*")
        self.new_pass.grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Подтверждение:").grid(row=2, column=0, sticky=tk.E, pady=5)
        self.confirm_pass = ttk.Entry(frame, show="*")
        self.confirm_pass.grid(row=2, column=1, sticky=tk.W, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Сменить пароль",
                   command=self.change_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Проверить сложность",
                   command=self.check_strength).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Выход",
                   command=self.root.destroy).pack(side=tk.LEFT, padx=5)

    def create_admin_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Администрирование")

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
        ttk.Label(parent, text="Действия администратора:",
                  font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        self.user_list = tk.Listbox(parent, height=10)
        self.user_list.pack(fill=tk.X, pady=5)
        self.load_user_list()
        self.user_list.bind("<<ListboxSelect>>", self.on_user_select)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Добавить пользователя",
                   command=self.add_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Заблокировать",
                   command=lambda: self.block_user(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Разблокировать",
                   command=lambda: self.block_user(False)).pack(side=tk.LEFT, padx=5)

        self.setup_password_requirements(parent)

        ttk.Button(parent, text="Выход",
                   command=self.root.destroy).pack(pady=10)

    def setup_password_requirements(self, parent):
        frame = ttk.LabelFrame(parent, text="Требования к паролю", padding=10)
        frame.pack(fill=tk.X, pady=5)

        self.enable_length = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Минимальная длина",
                        variable=self.enable_length).pack(anchor=tk.W)

        len_frame = ttk.Frame(frame)
        len_frame.pack(fill=tk.X, pady=5)

        ttk.Label(len_frame, text="Минимальная длина:").pack(side=tk.LEFT, padx=5)
        self.min_length = ttk.Entry(len_frame, width=5)
        self.min_length.pack(side=tk.LEFT)

        vcmd = (frame.register(self.validate_min_length), '%P')
        self.min_length.config(validate="key", validatecommand=vcmd)

        self.require_upper = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Заглавные буквы",
                        variable=self.require_upper).pack(anchor=tk.W)

        self.require_digit = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Цифры",
                        variable=self.require_digit).pack(anchor=tk.W)

        self.require_special = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Спецсимволы",
                        variable=self.require_special).pack(anchor=tk.W)

        ttk.Button(frame, text="Обновить требования",
                   command=self.update_requirements).pack(pady=5)

    def validate_min_length(self, new_value):
        if new_value == "" or new_value.isdigit():
            return True
        return False

    def load_user_list(self):
        self.user_list.delete(0, tk.END)
        for user in UserManager.users:
            status = " (заблокирован)" if user.is_blocked else ""
            self.user_list.insert(tk.END, user.name + status)

    def on_user_select(self, event):
        selection = self.user_list.curselection()
        if selection:
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
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        if not UserManager.validate_password(new, self.user.password_restrictions):
            error_msg = "Пароль не соответствует требованиям:"
            pr = self.user.password_restrictions

            if pr.enable_length and len(new) < pr.min_length:
                error_msg += f"\n- Минимальная длина {pr.min_length} символов"

            if pr.require_upper:
                if new.isupper():
                    error_msg += "\n- Не может состоять только из заглавных букв"
                else:
                    error_msg += "\n- Должен содержать хотя бы одну заглавную букву"

            if pr.require_digit and not any(c.isdigit() for c in new):
                error_msg += "\n- Должен содержать хотя бы одну цифру"

            if pr.require_special and all(c.isalnum() for c in new):
                error_msg += "\n- Должен содержать хотя бы один спецсимвол"

            messagebox.showerror("Ошибка", error_msg)
            return

        if UserManager.change_password(self.user.name, old, new):
            messagebox.showinfo("Успех", "Пароль изменен")
        else:
            messagebox.showerror("Ошибка", "Неверный текущий пароль")

    def check_strength(self):
        password = self.new_pass.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return

        result = PasswordStrengthAnalyzer.analyze_password(password)
        messagebox.showinfo("Анализ сложности пароля", result)

    def add_user(self):
        name = simpledialog.askstring("Добавить пользователя", "Введите имя нового пользователя:")
        if name:
            if UserManager.add_user(name):
                self.load_user_list()
            else:
                messagebox.showerror("Ошибка", "Некорректное или занятое имя пользователя")

    def block_user(self, block):
        selection = self.user_list.curselection()
        if selection:
            user_name = self.user_list.get(selection[0]).split()[0]
            if user_name == "ADMIN":
                messagebox.showerror("Ошибка", "Нельзя заблокировать ADMIN")
                return

            if UserManager.block_user(user_name, block):
                self.load_user_list()
                action = "заблокирован" if block else "разблокирован"
                messagebox.showinfo("Успех", f"Пользователь {user_name} {action}")
            else:
                messagebox.showerror("Ошибка", "Ошибка операции")

    def update_requirements(self):
        if hasattr(self, 'current_selection'):
            self.user_list.selection_set(self.current_selection)
            selection = self.user_list.curselection()
        else:
            selection = self.user_list.curselection()

        if not selection:
            messagebox.showerror("Ошибка", "Выберите пользователя")
            return

        user_name = self.user_list.get(selection[0]).split()[0]
        user = UserManager.get_user(user_name)
        if not user:
            messagebox.showerror("Ошибка", "Пользователь не найден")
            return

        try:
            min_len = int(self.min_length.get()) if self.min_length.get() else 0
            if min_len < 0:
                raise ValueError("Длина не может быть отрицательной")

            user.password_restrictions = PasswordRestrictions(
                self.enable_length.get(),
                min_len,
                self.require_upper.get(),
                self.require_digit.get(),
                self.require_special.get()
            )

            if (user.password_restrictions.require_upper and
                    user.password_restrictions.require_digit == False and
                    user.password_restrictions.require_special == False):
                messagebox.showwarning("Предупреждение",
                                       "При включенной опции 'Заглавные буквы' пароль должен:\n"
                                       "- Содержать хотя бы одну заглавную букву\n"
                                       "- Не состоять только из заглавных букв")

            UserManager.save_users()
            messagebox.showinfo("Успех", "Требования обновлены")

            current_idx = selection[0]
            self.load_user_list()
            self.user_list.selection_set(current_idx)
            self.user_list.see(current_idx)

        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректное значение: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginForm(root)
    root.mainloop()