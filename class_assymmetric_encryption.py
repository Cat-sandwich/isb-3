from path import settings

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


class class_assymmetric_encryption():

    def __init__(self, decrypted_file: str = settings['decrypted_file'], chiphed_file: str = settings["encrypted_file"], public_k_file: str = settings["public_key"], private_k_file: str = settings["private_key"]):
        self.public_pem = public_k_file
        self.private_pem = private_k_file
        self.encryption_file = chiphed_file
        self.decrypted_file = decrypted_file

    def generate_keys(self) -> None:
        """генерация пары ключей для асимметричного алгоритма шифрования"""
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        self.__add_to_file_private_key(private_key)
        self.__add_to_file_public_key(public_key)

    def __add_to_file_public_key(self, public_key: str) -> None:
        """сериализация открытого ключа в файл"""
        with open(self.public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def __add_to_file_private_key(self, private_key: str) -> None:
        """сериализация закрытого ключа в файл"""
        with open(self.private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))

    def __add_to_file_encryption_text(self, c_text: bytes):
        """десериализация расшифрованного текста в файл"""
        with open(self.encryption_file, 'wb') as file:
            file.write(c_text)

    def __add_to_file_decryption_text(self, data: str):
        """сериализация расшифрованного текста в файл"""
        with open(self.decrypted_file, 'wb') as file:
            file.write(data)

    def __get_public_key(self) -> str:
        """десериализация открытого ключа"""
        with open(self.public_pem, 'rb') as pem_in:
            public_bytes = pem_in.read()
        d_public_key = load_pem_public_key(public_bytes)
        return d_public_key

    def __get_private_key(self) -> str:
        """десериализация закрытого ключа"""
        with open(self.private_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        d_private_key = load_pem_private_key(private_bytes, password=None,)
        return d_private_key

    def __get_encryption_text(self):
        """десериализация зашифрованного текста"""
        with open(self.encryption_file, 'rb') as file:
            c_text = file.read()
            return c_text

    def encryption(self, data: str) -> None:
        """шифрование текста при помощи RSA-OAEP"""
        text = bytes(data, 'UTF-8')
        c_text = self.__get_public_key().encrypt(text, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.__add_to_file_encryption_text(c_text)

    def decryption(self) -> None:
        """дешифрование текста асимметричным алгоритмом"""
        private_key = self.__get_private_key(self.private_pem)
        c_text = self.__get_encryption_text()
        dc_text = private_key.decrypt(c_text, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

        self.__add_to_file_decryption_text(dc_text)
