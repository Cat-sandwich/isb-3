from path import settings

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import os


class symmetric_encryption:

    def __init__(self, size: int, decrypt_file: str, encrypt_file: str, symmetric_key_file: str = settings["symmetric_key"]) -> None:

        self.size = size
        self.sym_key_file = symmetric_key_file
        self.decrypt_file = decrypt_file
        self.encrypt_file = encrypt_file

    def __add_to_file(self, symmetric_key: bytes) -> None:
        """сериализация ключа симмеричного алгоритма в файл"""
        with open(self.sym_key_file, 'wb') as key_file:
            key_file.write(bytes(symmetric_key.key))

    def get_key(self) -> bytes:
        """десериализация ключа симметричного алгоритма"""
        with open(self.sym_key_file, mode='rb') as key_file:
            content = key_file.read()
            return content

    def generate_key(self) -> None:
        """генерация ключа симметричного алгоритма шифрования"""
        key = os.urandom(self.size)
        symmetric_key = AES(key)
        self.__add_to_file(symmetric_key)

    def padding_data(self, data: str) -> bytes:
        """добавляем ничего не значащие данные к шифруемой информации"""
        padder = padding.ANSIX923(32).padder()
        text = bytes(data, 'UTF-8')
        padded_text = padder.update(text)+padder.finalize()

        return padded_text

    def encryption(self, data: str) -> bytes:
        """шифрование текста симметричным алгоритмом"""
        size_blok = 1
        while (size_blok % 32 == 0):
            size_blok = random.randrange(1, 256)

        iv = os.urandom(size_blok)
        cipher = Cipher(algorithms.AES(self.get_key()), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_text = self.padding_data(data)
        c_text = encryptor.update(padded_text) + encryptor.finalize()
        return c_text

    def decryption(self, c_text) -> bytes:
        """дешифрование и депаддинг текста симметричным алгоритмом"""
        size_blok = 1
        while (size_blok % 32 == 0):
            size_blok = random.randrange(1, 256)
        iv = os.urandom(size_blok)
        cipher = Cipher(algorithms.AES(self.get_key()), modes.CBC(iv))

        decryptor = cipher.decryptor()
        dc_text = decryptor.update(c_text) + decryptor.finalize()

        unpadder = padding.ANSIX923(32).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        return unpadded_dc_text
