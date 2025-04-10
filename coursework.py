import os
import json
import time
import numpy as np
import hashlib
from sklearn.neighbors import KNeighborsClassifier
from pynput import keyboard
from collections import defaultdict
import joblib

# Конфигурация
MAX_SAMPLES = 1000
INITIAL_SAMPLES = 3
DATA_FILE = "users_data.json"
MODELS_DIR = "models"


class AuthSystem:
    def __init__(self):
        # Создаем папку для моделей, если ее нет
        os.makedirs(MODELS_DIR, exist_ok=True)
        self.users = self.load_data()
        self.current_typing_data = {
            'hold_times': [],
            'latencies': [],
            'chars': []
        }
        self.last_press_time = None
        self.listener = None

    def save_data(self):
        # Сохраняем данные пользователей
        with open(DATA_FILE, "w") as f:
            save_data = {}
            for username, data in self.users.items():
                # Сохраняем модель в отдельный файл
                if data.get('model'):
                    model_path = os.path.join(MODELS_DIR, f"{username}_model.pkl")
                    joblib.dump(data['model'], model_path)

                save_data[username] = {
                    'password_hash': data['password_hash'],
                    'hold_times': data['hold_times'].tolist(),
                    'latencies': data['latencies'].tolist(),
                    'samples_trained': data.get('samples_trained', 0),
                    'has_model': data.get('model') is not None  # Флаг наличия модели
                }
            json.dump(save_data, f, indent=2)

    def load_data(self):
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                for username, user_data in data.items():
                    # Загружаем модель из файла
                    if user_data.get('has_model'):
                        model_path = os.path.join(MODELS_DIR, f"{username}_model.pkl")
                        try:
                            user_data['model'] = joblib.load(model_path)
                        except:
                            print(f"Не удалось загрузить модель для {username}")
                            user_data['model'] = None
                    else:
                        user_data['model'] = None

                    user_data['hold_times'] = np.array(user_data['hold_times'])
                    user_data['latencies'] = np.array(user_data['latencies'])
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def train_model(self, username):
        user = self.users[username]

        # Синхронизация данных
        min_len = min(len(user['hold_times']), len(user['latencies']))
        if min_len < INITIAL_SAMPLES:
            print(f"Недостаточно данных для обучения: {min_len}/{INITIAL_SAMPLES}")
            return False

        user['hold_times'] = user['hold_times'][:min_len]
        user['latencies'] = user['latencies'][:min_len]

        # Подготовка данных
        X = np.column_stack((user['hold_times'], user['latencies']))
        y = np.ones(X.shape[0])  # Все образцы принадлежат пользователю

        # Обучение модели
        user['model'] = KNeighborsClassifier(n_neighbors=3)
        user['model'].fit(X, y)
        user['samples_trained'] = X.shape[0]

        # Сохранение
        self.save_data()
        print(f"Модель успешно обучена на {X.shape[0]} образцах")
        return True

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        self.users[username] = {
            'password_hash': self.hash_password(password),
            'hold_times': np.array([], dtype=np.float32),
            'latencies': np.array([], dtype=np.float32),
            'samples_trained': 0
        }

    def start_listener(self):
        self.listener = keyboard.Listener(
            on_press=self.on_press,
            on_release=self.on_release
        )
        self.listener.start()
        time.sleep(0.5)

    def stop_listener(self):
        if self.listener:
            self.listener.stop()
            self.listener = None

    def on_press(self, key):
        try:
            char = key.char
            # print(f"[DEBUG] Нажата клавиша: '{char}'")
        except AttributeError:
            return

        current_time = time.time()
        if self.last_press_time is not None:
            latency = current_time - self.last_press_time
            self.current_typing_data['latencies'].append(latency)
            # print(f"[DEBUG] Задержка: {latency:.3f}s")

        self.last_press_time = current_time
        self.current_typing_data['chars'].append(char)

    def on_release(self, key):
        try:
            char = key.char
        except AttributeError:
            return

        if self.last_press_time is None:
            return

        current_time = time.time()
        hold_time = current_time - self.last_press_time
        self.current_typing_data['hold_times'].append(hold_time)
        # print(f"[DEBUG] Отпущена клавиша: '{char}', Удержание: {hold_time:.3f}s")

    def sync_data(self):
        min_len = min(
            len(self.current_typing_data['chars']),
            len(self.current_typing_data['hold_times']),
            len(self.current_typing_data['latencies']) + 1
        )
        self.current_typing_data['chars'] = self.current_typing_data['chars'][:min_len]
        self.current_typing_data['hold_times'] = self.current_typing_data['hold_times'][:min_len]
        self.current_typing_data['latencies'] = self.current_typing_data['latencies'][:min_len - 1]
        return min_len

    def analyze_typing(self, username):
        min_len = self.sync_data()
        print("\n=== Результаты анализа ===")
        print(f"Введенные символы: {''.join(self.current_typing_data['chars'])}")
        print(
            f"Удержания ({len(self.current_typing_data['hold_times'])}:{[f'{t:.3f}s' for t in self.current_typing_data['hold_times']]}")
        print(
            f"Задержки ({len(self.current_typing_data['latencies'])}: {[f'{t:.3f}s' for t in self.current_typing_data['latencies']]}")

        user = self.users[username]
        if not user.get('model'):
            print("Модель не обучена!")
            return True

        if min_len < 3:
            print("Недостаточно данных!")
            return False

        X_new = np.column_stack((
            np.mean(self.current_typing_data['hold_times']),
            np.mean(self.current_typing_data['latencies'])
        ))

        distances, _ = user['model'].kneighbors(X_new.reshape(1, -1))
        avg_distance = np.mean(distances)
        threshold = 0.5 / np.sqrt(user['samples_trained'])

        print(f"Среднее расстояние: {avg_distance:.3f}, Порог: {threshold:.3f}")
        return avg_distance < threshold


def main():
    auth = AuthSystem()

    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)

    username = input("Логин: ").strip()

    if username in auth.users:
        password = input("Пароль: ")
        if auth.users[username]['password_hash'] != auth.hash_password(password):
            print("⛔ Неверный пароль!")
            return

        print("\nВведите пароль для проверки:")
        auth.current_typing_data = defaultdict(list)
        auth.start_listener()
        input()
        auth.stop_listener()

        if auth.analyze_typing(username):
            print("\n✅ Аутентификация успешна!")
            # Обновляем данные
            auth.users[username]['hold_times'] = np.concatenate([
                auth.users[username]['hold_times'],
                np.array(auth.current_typing_data['hold_times'], dtype=np.float32)
            ])[-MAX_SAMPLES:]

            auth.users[username]['latencies'] = np.concatenate([
                auth.users[username]['latencies'],
                np.array(auth.current_typing_data['latencies'], dtype=np.float32)
            ])[-MAX_SAMPLES:]

            # Переобучаем и сохраняем модель
            if auth.train_model(username):
                auth.save_data()
            else:
                print("⚠️ Не удалось обновить модель")
        else:
            print("\n✅ Аутентификация не пройдена, требуется дополнительная проверка!")
    else:
        if input("Пользователь не найден. Зарегистрироваться? (y/n) ").lower() != 'y':
            return
        password = input("Придумайте пароль: ")
        auth.register_user(username, password)
        print("\nВведите пароль 3 раза:")
        for i in range(3):
            auth.current_typing_data = defaultdict(list)
            auth.start_listener()
            input(f"Попытка {i + 1}: ")
            auth.stop_listener()
            auth.sync_data()
            auth.users[username]['hold_times'] = np.concatenate([
                auth.users[username]['hold_times'],
                np.array(auth.current_typing_data['hold_times'], dtype=np.float32)
            ])
            auth.users[username]['latencies'] = np.concatenate([
                auth.users[username]['latencies'],
                np.array(auth.current_typing_data['latencies'], dtype=np.float32)
            ])
        if auth.train_model(username):
            auth.save_data()
            print("✅ Обучение завершено!")
        else:
            print("❌ Ошибка обучения!")


if __name__ == "__main__":
    main()
