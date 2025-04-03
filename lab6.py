import os
import sys
import random
from collections import defaultdict
from typing import Dict, List, TypeVar

TKey = TypeVar('TKey')

# Русский алфавит по умолчанию
ALPHABET = "абвгдежзийклмнопрстуфхцчшщъыьэюяё"


class FrequencyAnalysis:
    @staticmethod
    def get_letter_frequency(text: str) -> Dict[str, int]:
        """Анализ частоты букв в тексте"""
        freq = defaultdict(int)
        for ch in text.lower():
            if ch in ALPHABET:
                freq[ch] += 1
        return dict(freq)

    @staticmethod
    def get_bigram_frequency(text: str) -> Dict[str, int]:
        """Анализ частоты биграмм в тексте"""
        freq = defaultdict(int)
        filtered = [ch for ch in text.lower() if ch in ALPHABET]
        for i in range(len(filtered) - 1):
            bigram = filtered[i] + filtered[i + 1]
            freq[bigram] += 1
        return dict(freq)

    @staticmethod
    def get_top_n(dictionary: Dict[TKey, int], n: int) -> Dict[TKey, int]:
        """Возвращает n самых частых элементов"""
        return dict(sorted(dictionary.items(), key=lambda x: x[1], reverse=True)[:n])


class CaesarAnalysis:
    @staticmethod
    def determine_key(cipher_text: str, ref_letter_freq: Dict[str, int]) -> int:
        """Определяет ключ шифра Цезаря методом частотного анализа"""
        filtered = [ch for ch in cipher_text.lower() if ch in ALPHABET]
        if not filtered:
            return 0

        freq = FrequencyAnalysis.get_letter_frequency(''.join(filtered))
        if not freq:
            return 0

        most_freq_cipher = max(freq.items(), key=lambda x: x[1])[0]
        most_freq_reference = max(ref_letter_freq.items(), key=lambda x: x[1])[0]

        idx_cipher = ALPHABET.index(most_freq_cipher)
        idx_reference = ALPHABET.index(most_freq_reference)

        return (idx_cipher - idx_reference + len(ALPHABET)) % len(ALPHABET)

    @staticmethod
    def decrypt(cipher_text: str, key: int) -> str:
        """Дешифрует текст шифром Цезаря с заданным ключом"""
        return CaesarAnalysis.caesar_cipher(cipher_text, -key)

    @staticmethod
    def caesar_cipher(text: str, shift: int) -> str:
        """Шифр Цезаря - шифрование и дешифрование"""
        result = []
        alph_len = len(ALPHABET)
        for ch in text:
            lower_ch = ch.lower()
            if lower_ch not in ALPHABET:
                result.append(ch)
                continue

            idx = ALPHABET.index(lower_ch)
            new_index = (idx + shift) % alph_len
            if new_index < 0:
                new_index += alph_len

            new_char = ALPHABET[new_index]
            result.append(new_char.upper() if ch.isupper() else new_char)
        return ''.join(result)


class VigenereAnalysis:
    @staticmethod
    @staticmethod
    def determine_key_length(cipher_text: str, max_key_length: int = 33) -> int:
        """Определяет длину ключа шифра Виженера"""
        filtered = [ch for ch in cipher_text.lower() if ch in ALPHABET]
        best_ic = 0
        best_key_length = 1

        for key_len in range(1, max_key_length + 1):
            ic_sum = 0
            valid_columns = 0
            for i in range(key_len):
                subtext = ''.join([filtered[j] for j in range(i, len(filtered), key_len)])
                if len(subtext) > 1:  # Только для подстрок достаточной длины
                    ic_sum += VigenereAnalysis._calculate_ic(subtext)
                    valid_columns += 1

            if valid_columns > 0:
                avg_ic = ic_sum / valid_columns
                if avg_ic > best_ic:
                    best_ic = avg_ic
                    best_key_length = key_len

        return best_key_length

    @staticmethod
    def _calculate_ic(text: str) -> float:
        """Вычисляет индекс совпадений для текста"""
        freq = FrequencyAnalysis.get_letter_frequency(text)
        n = len(text)
        if n <= 1:
            return 0
        ic = sum(count * (count - 1) for count in freq.values())
        return ic / (n * (n - 1))

    @staticmethod
    def determine_key(cipher_text: str, key_length: int,
                      ref_letter_freq: Dict[str, int],
                      ref_bigram_freq: Dict[str, int]) -> str:
        """Определяет ключ шифра Виженера"""
        filtered = [ch for ch in cipher_text.lower() if ch in ALPHABET]
        key = []
        for i in range(key_length):
            subtext = ''.join([filtered[j] for j in range(i, len(filtered), key_length)])
            shift = VigenereAnalysis._determine_shift_for_subtext_combined(
                subtext, ref_letter_freq, ref_bigram_freq)
            key.append(ALPHABET[shift])
        return ''.join(key)

    @staticmethod
    def _determine_shift_for_subtext_combined(
            subtext: str,
            ref_letter_freq: Dict[str, int],
            ref_bigram_freq: Dict[str, int],
            weight_letter: float = 1.0,
            weight_bigram: float = 1.0) -> int:
        """Определяет оптимальный сдвиг для подстроки"""
        if not subtext:
            return 0

        alph_length = len(ALPHABET)
        best_score = float('inf')
        best_shift = 0

        for shift in range(alph_length):
            shifted = VigenereAnalysis._apply_shift(subtext, shift)
            sub_letter_freq = FrequencyAnalysis.get_letter_frequency(shifted)
            sub_bigram_freq = FrequencyAnalysis.get_bigram_frequency(shifted)

            letter_error = 0
            for letter, ref_count in ref_letter_freq.items():
                sub_count = sub_letter_freq.get(letter, 0)
                letter_error += abs(ref_count - sub_count)

            bigram_error = 0
            for bigram, ref_count in ref_bigram_freq.items():
                sub_count = sub_bigram_freq.get(bigram, 0)
                bigram_error += abs(ref_count - sub_count)

            total_error = weight_letter * letter_error + weight_bigram * bigram_error
            if total_error < best_score:
                best_score = total_error
                best_shift = shift

        return best_shift

    @staticmethod
    def _apply_shift(text: str, shift: int) -> str:
        """Применяет обратный сдвиг к тексту"""
        result = []
        alph_len = len(ALPHABET)
        for ch in text:
            idx = ALPHABET.index(ch)
            new_index = (idx - shift + alph_len) % alph_len
            result.append(ALPHABET[new_index])
        return ''.join(result)

    @staticmethod
    def decrypt(cipher_text: str, key: str) -> str:
        """Дешифрует текст шифром Виженера"""
        return VigenereAnalysis.vigenere_cipher(cipher_text, key, decrypt=True)

    @staticmethod
    def vigenere_cipher(text: str, key: str, alphabet: str = ALPHABET, decrypt: bool = False) -> str:
        """Шифр Виженера - шифрование и дешифрование"""
        result = []
        key_index = 0
        alph_len = len(alphabet)

        for ch in text:
            lower_ch = ch.lower()
            if lower_ch not in alphabet:
                result.append(ch)
                continue

            text_index = alphabet.index(lower_ch)
            lower_key_char = key[key_index % len(key)].lower()
            key_shift = alphabet.index(lower_key_char)

            if decrypt:
                key_shift = -key_shift

            new_index = (text_index + key_shift) % alph_len
            if new_index < 0:
                new_index += alph_len

            new_char = alphabet[new_index]
            result.append(new_char.upper() if ch.isupper() else new_char)
            key_index += 1

        return ''.join(result)

    @staticmethod
    def generate_alphabet(randomize: bool = False) -> str:
        """Генерирует алфавит (можно перемешать)"""
        alph = list(ALPHABET)
        if randomize:
            random.shuffle(alph)
        return ''.join(alph)

    @staticmethod
    def generate_vigenere_square(alphabet: str, key: str, randomize_others: bool = False) -> str:
        """Генерирует квадрат Виженера"""
        sorted_alphabet = sorted(alphabet)
        fixed_column = ''.join(sorted_alphabet)
        square = []

        for i in range(len(fixed_column)):
            fixed_letter = fixed_column[i]
            line = f"{fixed_letter} | "

            remaining = [ch for ch in sorted_alphabet if ch != fixed_letter]
            if randomize_others:
                random.shuffle(remaining)
            else:
                shift = i % len(remaining)
                remaining = remaining[shift:] + remaining[:shift]

            line += ''.join(remaining)
            square.append(line)

        return '\n'.join(square)


def main_menu():
    """Главное меню программы"""
    print("\n=== Инструмент частотного криптоанализа ===")
    print("1. Инструменты для шифра Цезаря")
    print("2. Инструменты для шифра Виженера")
    print("3. Выход")

    while True:
        choice = input("\nВыберите опцию (1-3): ").strip()

        if choice == "1":
            caesar_menu()
        elif choice == "2":
            vigenere_menu()
        elif choice == "3":
            print("Завершение работы программы...")
            sys.exit(0)
        else:
            print("Неверный выбор. Попробуйте снова.")


def read_file(filename: str) -> str:
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Ошибка: файл {filename} не найден")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при чтении файла: {e}")
        sys.exit(1)


def write_file(filename: str, content: str):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Результат сохранён в {filename}")
    except Exception as e:
        print(f"Ошибка при записи файла: {e}")
        sys.exit(1)


def caesar_menu():
    print("\n=== Шифр Цезаря ===")
    print("1. Зашифровать файл")
    print("2. Расшифровать файл с ключом")
    print("3. Взломать шифр (частотный анализ)")

    choice = input("Выберите операцию (1-3): ").strip()

    if choice == "1":
        input_file = input("Введите имя файла для шифрования: ")
        output_file = "encC_" + os.path.basename(input_file)
        try:
            key = int(input("Введите ключ сдвига (целое число): "))
            text = read_file(input_file)
            encrypted = CaesarAnalysis.caesar_cipher(text, key)
            write_file(output_file, encrypted)
        except ValueError:
            print("Ошибка: ключ должен быть целым числом")
        sys.exit(0)

    elif choice == "2":
        input_file = input("Введите имя файла для расшифровки: ")
        output_file = "decC_" + os.path.basename(input_file)
        try:
            key = int(input("Введите ключ сдвига (целое число): "))
            text = read_file(input_file)
            decrypted = CaesarAnalysis.decrypt(text, key)
            write_file(output_file, decrypted)
        except ValueError:
            print("Ошибка: ключ должен быть целым числом")
        sys.exit(0)

    elif choice == "3":
        input_file = input("Введите имя файла для взлома: ")
        output_file = "decC_" + os.path.basename(input_file)

        # Частоты букв русского языка
        ref_freq = {
            'о': 11, 'е': 9, 'а': 8, 'и': 7, 'н': 6, 'т': 6,
            'с': 5, 'р': 5, 'в': 4, 'л': 4, 'к': 3, 'м': 3,
            'д': 3, 'п': 2, 'у': 2, 'я': 2, 'ы': 2, 'ь': 2,
            'г': 2, 'з': 1, 'б': 1, 'ч': 1, 'й': 1, 'х': 1,
            'ж': 1, 'ш': 1, 'ю': 1, 'ц': 1, 'щ': 1, 'э': 1,
            'ф': 1, 'ъ': 1, 'ё': 1
        }

        try:
            text = read_file(input_file)
            key = CaesarAnalysis.determine_key(text, ref_freq)
            print(f"Найденный ключ: {key}")
            decrypted = CaesarAnalysis.decrypt(text, key)
            write_file(output_file, decrypted)
        except Exception as e:
            print(f"Ошибка при анализе: {e}")
        sys.exit(0)

    else:
        print("Неверный выбор")
        sys.exit(1)


def vigenere_menu():
    print("\n=== Шифр Виженера ===")
    print("1. Зашифровать файл")
    print("2. Расшифровать файл с ключом")
    print("3. Взломать шифр (автоматический анализ)")

    choice = input("Выберите операцию (1-3): ").strip()

    if choice == "1":
        input_file = input("Введите имя файла для шифрования: ")
        output_file = "encV_" + os.path.basename(input_file)
        key = input("Введите ключ шифрования: ")
        text = read_file(input_file)
        encrypted = VigenereAnalysis.vigenere_cipher(text, key)
        write_file(output_file, encrypted)
        sys.exit(0)

    elif choice == "2":
        input_file = input("Введите имя файла для расшифровки: ")
        output_file = "decV_" + os.path.basename(input_file)
        key = input("Введите ключ дешифровки: ")
        text = read_file(input_file)
        decrypted = VigenereAnalysis.decrypt(text, key)
        write_file(output_file, decrypted)
        sys.exit(0)

    elif choice == "3":
        input_file = input("Введите имя файла для взлома: ")
        output_file = "decV_" + os.path.basename(input_file)

        # Частоты букв и биграмм русского языка
        ref_letter_freq = {
            'о': 11, 'е': 9, 'а': 8, 'и': 7, 'н': 6, 'т': 6,
            'с': 5, 'р': 5, 'в': 4, 'л': 4, 'к': 3, 'м': 3,
            'д': 3, 'п': 2, 'у': 2, 'я': 2, 'ы': 2, 'ь': 2,
            'г': 2, 'з': 1, 'б': 1, 'ч': 1, 'й': 1, 'х': 1,
            'ж': 1, 'ш': 1, 'ю': 1, 'ц': 1, 'щ': 1, 'э': 1,
            'ф': 1, 'ъ': 1, 'ё': 1
        }

        ref_bigram_freq = {
            'ст': 30, 'но': 25, 'то': 25, 'на': 25, 'ен': 20,
            'ов': 20, 'ни': 20, 'ра': 20, 'во': 18, 'ко': 18
        }

        try:
            text = read_file(input_file)
            print("Анализ текста...")
            key_length = VigenereAnalysis.determine_key_length(text)
            print(f"Найденная длина ключа: {key_length}")
            key = VigenereAnalysis.determine_key(text, key_length, ref_letter_freq, ref_bigram_freq)
            print(f"Найденный ключ: {key}")
            decrypted = VigenereAnalysis.decrypt(text, key)
            write_file(output_file, decrypted)
        except Exception as e:
            print(f"Ошибка при анализе: {e}")
        sys.exit(0)

    else:
        print("Неверный выбор")
        sys.exit(1)


def main():
    print("=== Криптоанализ ===")
    print("1. Шифр Цезаря")
    print("2. Шифр Виженера")

    choice = input("Выберите шифр (1-2): ").strip()

    if choice == "1":
        caesar_menu()
    elif choice == "2":
        vigenere_menu()
    else:
        print("Неверный выбор")
        sys.exit(1)


if __name__ == "__main__":
    main()