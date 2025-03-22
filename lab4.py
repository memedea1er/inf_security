import random
import string

def caesar_cipher(text, key, decrypt=False):
    if decrypt:
        key = -key
    result = []
    for char in text:
        if char.isalpha():
            shift = (ord(char.lower()) - ord('a') + key) % 26
            if char.isupper():
                result.append(chr(shift + ord('A')))
            else:
                result.append(chr(shift + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def generate_vigenere_square(alphabet):
    square = []
    for i in range(len(alphabet)):
        square.append(alphabet[i:] + alphabet[:i])
    return square

def vigenere_cipher(text, key, alphabet, decrypt=False):
    key = key.upper()
    key_length = len(key)
    result = []
    for i, char in enumerate(text):
        if char.isalpha():
            key_char = key[i % key_length]
            shift = alphabet.index(key_char)
            if decrypt:
                shift = -shift
            char_index = alphabet.index(char.upper())
            new_index = (char_index + shift) % len(alphabet)
            new_char = alphabet[new_index]
            if char.isupper():
                result.append(new_char)
            else:
                result.append(new_char.lower())
        else:
            result.append(char)
    return ''.join(result)

def save_to_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)

def read_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.read()

def print_first_lines(original_file, encrypted_file, decrypted_file):
    print("Original text:")
    print(read_from_file(original_file).splitlines()[0])
    print("Encrypted text:")
    print(read_from_file(encrypted_file).splitlines()[0])
    print("Decrypted text:")
    print(read_from_file(decrypted_file).splitlines()[0])

def main():
    mode = input("Выберите режим (1 - Цезарь, 2 - Виженер): ")
    filename = input("Введите имя файла: ")
    text = read_from_file(filename)

    if mode == '1':
        key = int(input("Введите ключ для шифра Цезаря: "))
        encrypted_text = caesar_cipher(text, key)
        save_to_file(f"encV_{filename}", encrypted_text)
        decrypted_text = caesar_cipher(encrypted_text, key, decrypt=True)
        save_to_file(f"decV_{filename}", decrypted_text)
        print_first_lines(filename, f"encV_{filename}", f"decV_{filename}")

    elif mode == '2':
        key = input("Введите ключ для шифра Виженера: ")
        alphabet_choice = input("Выберите алфавит (1 - случайный, 2 - по порядку): ")
        if alphabet_choice == '1':
            alphabet = ''.join(random.sample(string.ascii_uppercase, 26))
        else:
            alphabet = string.ascii_uppercase
        square = generate_vigenere_square(alphabet)
        print("Квадрат Виженера:")
        for row in square:
            print(row)
        encrypted_text = vigenere_cipher(text, key, alphabet)
        save_to_file(f"encV_{filename}", encrypted_text)
        decrypted_text = vigenere_cipher(encrypted_text, key, alphabet, decrypt=True)
        save_to_file(f"decV_{filename}", decrypted_text)
        print_first_lines(filename, f"encV_{filename}", f"decV_{filename}")

if __name__ == "__main__":
    main()