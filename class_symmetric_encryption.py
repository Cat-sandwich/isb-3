import os
import logging

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class symmetric_encryption:
    """Класс symmetric_encryption для генирации симметричного ключа шифрования (по заданному размеру), использует AES шифрование

    Размер ключа в битах: 128 или 192, или 256
    """

    def __init__(self, size: int, symmetric_key_file: str, decrypt_file: str = None, encrypt_file: str = None) -> None:
        """запись путей файлов в поля класса

        Параметры:
        self - поля класса
        size(int) - размер ключа
        symmetric_key_file(str) - путь к симметричному ключу 
        decrypt_file(str) - путь к расшифрованному файлу
        encrypt_file(str) - путь к зашифрованному файлу

        Возвращаемое значение:
        None
        """
        self.size = size
        self.sym_key_file = symmetric_key_file
        self.decrypt_file = decrypt_file
        self.encrypt_file = encrypt_file

    def __add_to_file(self, symmetric_key: bytes) -> None:
        """сериализация ключа симмеричного алгоритма в файл

        Параметры:
        self - поля класса
        symmetric_key(bytes) - симметричный ключ 

        Возвращаемое значение:
        None"""
        try:
            with open(self.sym_key_file, 'wb') as key_file:
                key_file.write(symmetric_key)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.sym_key_file}")

    def __add_encrypt_text_to_file(self, c_text: bytes):
        """Запись в файл зашифрованного текста

        Параметры:
        self - поля класса
        c_text(bytes) - зашифрованный текст 

        Возвращаемое значение:
        None"""
        try:
            with open(self.encrypt_file, "wb") as file:
                file.write(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encrypt_file}")

    def __add_text_to_file(self, c_text: bytes):
        """Запись в файл расшифрованного текста 

        Параметры:
        self - поля класса
        c_text(bytes) - расшифрованный текст 

        Возвращаемое значение:
        None"""
        try:
            with open(self.decrypt_file, "w") as file:
                file.write(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypt_file}")

    def __get_key(self) -> bytes:
        """десериализация ключа симметричного алгоритма

        Параметры:
        self - поля класса

        Возвращаемое значение:
        (bytes) - считанный ключ
        """
        try:
            with open(self.sym_key_file, mode='rb') as key_file:
                return key_file.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.sym_key_file}")

    def generate_key(self) -> None:
        """генерация ключа симметричного алгоритма шифрования

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None
        """
        key = os.urandom(self.size)
        self.__add_to_file(key)

    def __padding_data(self, data: str) -> bytes:
        """добавляем ничего не значащие данные к шифруемой информации

        Параметры:
        self - поля класса
        data(str) - строка данных, которую нужно дополнить

        Возвращаемое значение:
        padded_text(bytes) - дополненые данные
        """
        padder = padding.ANSIX923(AES.block_size).padder()
        text = bytes(data, 'UTF-8')
        padded_text = padder.update(text)+padder.finalize()

        return padded_text

    def encryption(self) -> None:
        """шифрование текста симметричным алгоритмом

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None"""
        data = str()
        try:
            with open(self.decrypt_file, 'r', encoding="UTF-8") as file:
                data = file.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypt_file}")
        iv = os.urandom(16)

        key = self.__get_key()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())

        data = self.__padding_data(data)

        encryptor = cipher.encryptor()
        c_text = iv + encryptor.update(data) + encryptor.finalize()

        self.__add_encrypt_text_to_file(c_text)

    def __de_padd(self, plain_text: str) -> bytes:
        """возвращает данные в исходный вид (убирает добавленные символы)

        Параметры:
        self - поля класса
        plain_text(str) - текст, у которого нужно убрать символы

        Возвращаемое значение:
        (bytes) - восстановленный текст
        """
        last_byte = plain_text[-1]
        if isinstance(last_byte, int):
            return last_byte
        else:
            return ord(last_byte)

    def decryption(self) -> bytes:
        """дешифрование и депаддинг текста симметричным алгоритмом

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None
        """
        c_text = bytes()
        try:
            with open(self.encrypt_file, 'rb') as file:
                c_text = file.read()
        except:
            logging.error(f"{self.encrypt_file} can't be opened")
            exit()

        iv = c_text[:16]
        c_text = c_text[16:]

        cipher = Cipher(algorithms.AES(self.__get_key()),
                        modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(c_text) + decryptor.finalize()

        padding_size = self.__de_padd(plaintext)

        plaintext = plaintext[:-padding_size]
        plaintext = plaintext.decode('UTF-8')
        self.__add_text_to_file(plaintext)
