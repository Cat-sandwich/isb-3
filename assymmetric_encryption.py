import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


class assymmetric_encryption:
    """Класс assymmetric_encryption для генирации пары асимметричных ключей шифрования"""

    def __init__(self, public_k_file: str = None, private_k_file: str = None, decrypted_file: str = None, encrypt_file: str = None) -> None:
        """запись путей файлов в поля класса

        Параметры:
        self - поля класса
        public_k_file(str) - путь к открытому ключу 
        private_k_file(str) - путь к закрытому ключу 
        decrypted_file(str) - путь к расшифрованному файлу
        encrypt_file(str) - путь к зашифрованному файлу

        Возвращаемое значение:
        None
        """
        self.public_pem = public_k_file
        self.private_pem = private_k_file
        self.encryption_file = encrypt_file
        self.decrypted_file = decrypted_file

    def generate_keys(self) -> None:
        """генерация пары ключей для асимметричного алгоритма шифрования

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        self.__add_to_file_private_key(private_key)
        self.__add_to_file_public_key(public_key)

    def __add_to_file_public_key(self, public_key: str) -> None:
        """сериализация открытого ключа в файл

        Параметры:
        self - поля класса
        public_key(str) - открытый ключ

        Возвращаемое значение:
        None
        """
        try:
            with open(self.public_pem, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}")

    def __add_to_file_private_key(self, private_key: str) -> None:
        """сериализация закрытого ключа в файл

        Параметры:
        self - поля класса
        private_key(str) - закрытый ключ

        Возвращаемое значение:
        None
        """
        try:
            with open(self.private_pem, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}")

    def __add_to_file_encryption_text(self, c_text: bytes) -> None:
        """десериализация расшифрованного текста в файл

        Параметры:
        self - поля класса
        c_text(bytes) - текст в байтах, который нужно записать в файл

        Возвращаемое значение:
        None"""
        try:
            with open(self.encryption_file, 'wb') as file:
                file.write(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encryption_file}")

    def __add_to_file_decryption_text(self, data: str) -> None:
        """сериализация расшифрованного текста в файл

        Параметры:
        self - поля класса
        data(str) - строка, которую надо записать в файл

        Возвращаемое значение:
        None
        """
        try:
            with open(self.decrypted_file, 'wb') as file:
                file.write(data)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted_file}")

    def __get_public_key(self) -> str:
        """десериализация открытого ключа

        Параметры:
        self - поля класса

        Возвращаемое значение:
        d_public_key(str) - считанный ключ
        """
        try:
            with open(self.public_pem, 'rb') as pem_in:
                public_bytes = pem_in.read()
            d_public_key = load_pem_public_key(public_bytes)
            return d_public_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}")

    def __get_private_key(self) -> str:
        """десериализация закрытого ключа

        Параметры:
        self - поля класса

        Возвращаемое значение:
        d_private_key(str) - считанный ключ
        """
        try:
            with open(self.private_pem, 'rb') as pem_in:
                private_bytes = pem_in.read()
            d_private_key = load_pem_private_key(private_bytes, password=None,)
            return d_private_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}")

    def __get_encryption_text(self) -> bytes:
        """десериализация зашифрованного текста

        Параметры:
        self - поля класса

        Возвращаемое значение:
        c_text(bytes) - считанный зашифрованный текст
        """
        try:
            with open(self.encryption_file, 'rb') as file:
                c_text = file.read()
                return c_text
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encryption_file}")

    def encryption(self) -> None:
        """шифрование текста при помощи RSA-OAEP

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None
        """

        data = str()
        try:
            with open(self.decrypted_file, 'rb') as file:
                data = file.read()

            if type(data) != bytes:
                text = bytes(data, "UTF-8")
            else:
                text = data

            public_key = self.__get_public_key()
            c_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(
                algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self.__add_to_file_encryption_text(c_text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted_file}")

    def decryption(self) -> None:
        """дешифрование текста асимметричным алгоритмом

        Параметры:
        self - поля класса

        Возвращаемое значение:
        None
        """
        private_key = self.__get_private_key()
        c_text = self.__get_encryption_text()
        dc_text = private_key.decrypt(c_text, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.__add_to_file_decryption_text(dc_text)
