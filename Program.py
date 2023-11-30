from tkinter import *
from tkinter import ttk, simpledialog, messagebox
import sqlite3
import hashlib
import os


class AuthenticationApp:
    def __init__(self, root):
        # Ініціалізація головного вікна додатку
        self.root = root
        self.root.title("Додаток для аутентифікації")
        self.root.geometry("400x400")
        self.create_tables()
        self.check_key_file()  # Виклик методу для перевірки ключового файлу
        self.setup_gui()
        self.max_login_attempts = 4  # Максимальна кількість невдалих спроб входу


    def create_tables(self):
        # Отримання шляху до поточної директорії
        current_directory = os.path.dirname(__file__)

        # Створення таблиць для баз даних користувачів та спроб входу в поточній директорії
        conn = sqlite3.connect(os.path.join(current_directory, "users.db"))
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT NOT NULL,
                           password TEXT NOT NULL,
                           role TEXT NOT NULL,
                           blocked INTEGER DEFAULT 0)''')
        conn.commit()
        conn.close()

        conn = sqlite3.connect(os.path.join(current_directory, "login_attempts.db"))
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT NOT NULL,
                           attempts INTEGER DEFAULT 0)''')
        conn.commit()
        conn.close()


    def check_key_file(self):
        # Перевірка наявності і вмісту файлу "key.txt"
        key_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../key.txt"))

        if not os.path.exists(key_file_path):
            messagebox.showerror("Error", "Файл key.txt не знайдений. Програма буде закрита.")
            self.root.destroy()
            return

        with open(key_file_path, "r") as key_file:
            correct_key = key_file.read().strip()

        if correct_key != "1111":
            messagebox.showerror("Error", "Неправильний ключ у файлі key.txt. Програма буде закрита.")
            self.root.destroy()


    def register(self):
        # Функція реєстрації користувача
        username = self.entry_username.get()
        role = self.combo_role.get()

        if role == "Адміністратор":
            admin_password = simpledialog.askstring("Пароль адміністратора", "Введіть пароль адміністратора:")
            if admin_password != "1234":
                messagebox.showerror("Помилка", "Неправильний пароль адміністратора.")
                return

        password = self.entry_password.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Додавання користувача до бази даних
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (username, hashed_password, role))
        conn.commit()
        conn.close()

        # Додавання запису про спробу входу користувача до бази даних
        conn = sqlite3.connect("login_attempts.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO login_attempts (username, attempts) VALUES (?, 0)", (username,))
        conn.commit()
        conn.close()

        messagebox.showinfo("Успішна реєстрація", f"Користувач {username} успішно зареєстрований!")

    def login(self):
        # Функція входу користувача
        username = self.entry_username_login.get()
        password = self.entry_password_login.get()

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Перевірка існування користувача в базі даних
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user:
            if self.is_account_blocked(username):
                self.label_result["text"] = "Акаунт заблокований. Зверніться для відновлення паролю."
            elif hashed_password == user[2]:
                self.label_result["text"] = f"Ласкаво просимо, {username}! Ваша роль - {user[3]}"
                self.reset_login_attempts(username)
            else:
                self.handle_failed_login(username)
        else:
            self.label_result["text"] = "Неправильне ім'я користувача або пароль"
            self.handle_failed_login(username)

        conn.close()

    def handle_failed_login(self, username):
        # Обробка невдалих спроб входу
        if not self.is_account_blocked(username):
            self.increment_login_attempts(username)
            attempts_used = self.login_attempts(username)
            attempts_left = self.max_login_attempts - attempts_used

            self.label_result["text"] = f"Неправильне ім'я користувача або пароль. " \
                                        f"Спроб використано: {attempts_used}. Залишилося спроб: {attempts_left}"

        if attempts_used >= self.max_login_attempts:
            self.block_account(username)
            self.label_result["text"] = "Акаунт заблокований. Зверніться для відновлення паролю."

    def is_account_blocked(self, username):
        # Перевірка блокування акаунта
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT blocked FROM users WHERE username=?", (username,))
        blocked = cursor.fetchone()[0]
        conn.close()
        return blocked

    def increment_login_attempts(self, username):
        # Збільшення кількості спроб входу для користувача
        conn = sqlite3.connect("login_attempts.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE login_attempts SET attempts = attempts + 1 WHERE username=?", (username,))
        conn.commit()
        conn.close()

    def login_attempts(self, username):
        # Отримання кількості спроб входу для користувача
        conn = sqlite3.connect("login_attempts.db")
        cursor = conn.cursor()
        cursor.execute("SELECT attempts FROM login_attempts WHERE username=?", (username,))
        attempts = cursor.fetchone()[0]
        conn.close()
        return attempts

    def reset_login_attempts(self, username):
        # Скидання кількості спроб входу для користувача
        conn = sqlite3.connect("login_attempts.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE login_attempts SET attempts = 0 WHERE username=?", (username,))
        conn.commit()
        conn.close()

    def block_account(self, username):
        # Блокування акаунта користувача
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET blocked=1 WHERE username=?", (username,))
        conn.commit()
        conn.close()

    def switch_to_registration(self):
        # Перехід до розділу реєстрації
        self.clear_login_entries()
        self.show_registration()
        self.label_result["text"] = ""

    def switch_to_login(self):
        # Перехід до розділу входу
        self.clear_registration_entries()
        self.show_login()
        self.label_result["text"] = ""

    def show_registration(self):
        # Показ розділу реєстрації
        self.login_frame.pack_forget()
        self.registration_frame.pack(side=TOP, pady=10)

    def show_login(self):
        # Показ розділу входу
        self.registration_frame.pack_forget()
        self.login_frame.pack(side=TOP, pady=10)

    def clear_login_entries(self):
        # Очищення полів для входу
        self.entry_username_login.delete(0, END)
        self.entry_password_login.delete(0, END)

    def clear_registration_entries(self):
        # Очищення полів для реєстрації
        self.entry_username.delete(0, END)
        self.entry_password.delete(0, END)

    def setup_gui(self):
        # Налаштування графічного інтерфейсу
        
        # Розділ реєстрації
        self.registration_frame = Frame(self.root)

        ttk.Label(self.registration_frame, text="Реєстрація").pack(side=TOP, pady=10)

        ttk.Label(self.registration_frame, text="Ім'я користувача:").pack(side=TOP, padx=10, pady=5, anchor=W)
        self.entry_username = ttk.Entry(self.registration_frame)
        self.entry_username.pack(side=TOP, padx=10, pady=5)

        ttk.Label(self.registration_frame, text="Пароль:").pack(side=TOP, padx=10, pady=5, anchor=W)
        self.entry_password = ttk.Entry(self.registration_frame, show="*")
        self.entry_password.pack(side=TOP, padx=10, pady=5)

        ttk.Label(self.registration_frame, text="Роль:").pack(side=TOP, padx=10, pady=5, anchor=W)
        roles = ["Адміністратор", "Користувач"]
        self.combo_role = ttk.Combobox(self.registration_frame, values=roles)
        self.combo_role.set("Користувач")  # Встановлення за замовчуванням
        self.combo_role.pack(side=TOP, padx=10, pady=5)

        ttk.Button(self.registration_frame, text="Зареєструватися", command=self.register).pack(side=TOP, pady=10)


        # Розділ входу
        self.login_frame = Frame(self.root)

        ttk.Label(self.login_frame, text="Вхід").pack(side=TOP, pady=10)

        ttk.Label(self.login_frame, text="Ім'я користувача:").pack(side=TOP, padx=10, pady=5, anchor=W)
        self.entry_username_login = ttk.Entry(self.login_frame)
        self.entry_username_login.pack(side=TOP, padx=10, pady=5)

        ttk.Label(self.login_frame, text="Пароль:").pack(side=TOP, padx=10, pady=5, anchor=W)
        self.entry_password_login = ttk.Entry(self.login_frame, show="*")
        self.entry_password_login.pack(side=TOP, padx=10, pady=5)

        ttk.Button(self.login_frame, text="Увійти", command=self.login).pack(side=TOP, pady=10)

        self.label_result = ttk.Label(self.root, text="")
        self.label_result.pack(side=TOP, pady=10)

        # Кнопки реєстрації та входу
        ttk.Button(self.root, text="Зареєструватися", command=self.switch_to_registration).pack(side=LEFT, pady=10)
        ttk.Button(self.root, text="Вхід", command=self.switch_to_login).pack(side=LEFT, pady=10)

        self.show_login()

if __name__ == "__main__":
    root = Tk()
    app = AuthenticationApp(root)
    root.mainloop()