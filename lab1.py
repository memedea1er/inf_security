import itertools
import math


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
        alphabet_size += 33  # Учтем спецсимволы (приблизительно)

    return alphabet_size


def calculate_combinations(password_length: int, alphabet_size: int) -> int:
    return alphabet_size ** password_length


def estimate_brute_force_time(combinations: int, attempts_per_second: int, pause_time, attempts_before_pause) -> float:
    total_time = combinations / attempts_per_second + ((combinations - 1) * pause_time / attempts_before_pause)
    return total_time


def format_time(seconds: float) -> str:
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    months, days = divmod(days, 30)
    years, months = divmod(months, 12)

    return f"{int(years)} лет {int(months)} месяцев {int(days)} дней {int(hours)} часов {int(minutes)} минут {int(sec)} секунд"


def analyze_password(password: str, attempts_per_second, pause_time, attempts_before_pause):
    alphabet_size = get_alphabet_size(password)
    combinations = calculate_combinations(len(password), alphabet_size)
    time_seconds = estimate_brute_force_time(combinations, attempts_per_second, pause_time, attempts_before_pause)

    print(f"Пароль: {password}")
    print(f"Мощность алфавита: {alphabet_size}")
    print(f"Число возможных комбинаций: {combinations}")
    print(f"Время подбора: {format_time(time_seconds)}")


# Пример работы
password = input("Введите пароль: ")
attempts_per_second = int(input("Введите количество попыток в секунду: "))
attempts_before_pause = int(input("Введите количество попыток до паузы: "))
pause_time = int(input("Введите время паузы: "))
analyze_password(password, attempts_per_second, pause_time, attempts_before_pause)
