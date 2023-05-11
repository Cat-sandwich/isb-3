from class_assymmetric_encryption import assymmetric_encryption
from class_symmetric_encryption import symmetric_encryption


def encrypt_data(decrypted_file: str, private_key: str, symmetric_key: str, encrypted_file: str, symmetric_key_decrypted, size: int) -> None:
    """Шифрование данных"""

    assym_SYM = assymmetric_encryption(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, ciphed_file=symmetric_key)
    assym_SYM.decryption()

    sym = symmetric_encryption(size, symmetric_key_decrypted,
                               encrypted_file, decrypted_file)
    sym.encryption()


def decrypt_data(encrypted_file: str, private_key: str,
                 symmetric_key: str, decrypted_file, symmetric_key_decrypted: str, size: int) -> None:
    """дешифровка данных"""

    assym_SYM = assymmetric_encryption(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, ciphed_file=symmetric_key)
    assym_SYM.decryption()

    sym = symmetric_encryption(size, symmetric_key_decrypted,
                               encrypted_file, decrypted_file)
    sym.decryption()


def keys_generator(private_key: str, public_key: str, symmetric_key: str, symmetric_key_decrypted: str, size: int) -> None:
    """Генерация ключей"""

    assym = assymmetric_encryption(
        public_key, private_key, symmetric_key_decrypted, symmetric_key)

    assym.generate_keys()

    symm = symmetric_encryption(size, symmetric_key_decrypted)
    symm.generate_key()

    assym.encryption()
