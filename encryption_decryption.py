from assymmetric_encryption import assymmetric_encryption
from symmetric_encryption import symmetric_encryption


def encrypt_data(decrypted_file: str, private_key: str, symmetric_key: str, encrypted_file: str, symmetric_key_decrypted, size: int) -> None:
    """шифрование данных

    Параметры:   
    decrypted_file(str) - путь расшифрованному тексту
    private_key(str) - путь к закрытому ключу
    symmetric_key(str) - путь к симметричному ключу
    encrypted_file(str) - путь к зашифрованному тексту
    symmetric_key_decrypted(str) - путь к симметричному расшифрованному ключу
    size(int) - размер ключа

    Возвращаемое значение:
    None
    """

    assym_SYM = assymmetric_encryption(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, encrypt_file=symmetric_key)
    assym_SYM.decryption()

    sym = symmetric_encryption(size, symmetric_key_decrypted,
                               decrypted_file, encrypted_file)
    sym.encryption()


def decrypt_data(encrypted_file: str, private_key: str,
                 symmetric_key: str, decrypted_file, symmetric_key_decrypted: str, size: int) -> None:
    """дешифровка данных

    Параметры:
    encrypted_file(str) - путь к зашифрованному тексту
    private_key(str) - путь к закрытому ключу
    symmetric_key(str) - путь к симметричному ключу
    decrypted_file(str) - путь расшифрованному тексту
    symmetric_key_decrypted(str) - путь к симметричному расшифрованному ключу
    size(int) - размер ключа

    Возвращаемое значение:
    None
    """

    assym_SYM = assymmetric_encryption(
        private_k_file=private_key, decrypted_file=symmetric_key_decrypted, encrypt_file=symmetric_key)
    assym_SYM.decryption()

    sym = symmetric_encryption(size, symmetric_key_decrypted, decrypted_file,
                               encrypted_file)
    sym.decryption()


def keys_generator(private_key: str, public_key: str, symmetric_key: str, symmetric_key_decrypted: str, size: int) -> None:
    """генерация ключей

    Параметры:
    private_key(str) - путь к закрытому ключу
    public_key(str) - путь к открытому ключу
    symmetric_key(str) - путь симметричному ключу
    symmetric_key_decrypted(str) - путь к симметричному расшифрованному ключу
    size(int) - размер ключа

    Возвращаемое значение:
    None
    """

    assym = assymmetric_encryption(
        public_key, private_key, symmetric_key_decrypted, symmetric_key)
    assym.generate_keys()

    symm = symmetric_encryption(size, symmetric_key_decrypted)
    symm.generate_key()

    assym.encryption()
