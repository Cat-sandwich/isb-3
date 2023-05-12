import argparse
import json
import logging
import os

from encryption_decryption import keys_generator, encrypt_data, decrypt_data


def check_size(size: int):
    """Проверка размерности для ключа

    Параметры:
    size(int) - длина ключа для AES

    Возвращаемые значения:
    size(int) - проверенная длина ключа для AES
    true or false - идентификатор проверки
    """
    if size == 128 or size == 192 or size == 256:
        return int(size/8), True
    return 16, False


def get_argument():
    """Получение аргументов

    Параметры:
    None

    Возвращаемое значение:
    args(Namespase) - считанные аргументы
    """
    parser = argparse.ArgumentParser()

    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        '-gen', '--generation', action='store_true', help='Сгенерировать ключи')
    mode_group.add_argument('-enc', '--encryption', action='store_true',
                            help='Зашифровать данные')
    mode_group.add_argument('-dec', '--decryption', action='store_true',
                            help='Расшифровать данные')
    args = parser.parse_args()
    return args


def set_config_file(name: str) -> str:
    """Читаем пути из json файла

    Параметры:
    name(str) - название конфиг-файла

    Возвращаемое значение:
    settings(str) - считанный файл
    """
    CONFIG = os.path.join(name)
    settings = str()
    try:
        with open(CONFIG) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        logging.error(
            f"Ошибка открытия файла: {CONFIG} \nЗавершение работы")
        exit()
    return settings


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    args = get_argument()
    mode = (args.generation, args.encryption, args.decryption)
    settings = set_config_file("path.json")
    size = int(settings["size"])
    size, correct = check_size(size)

    if not correct:
        logging.info(
            'Размер ключа введен некорректно -> установлен размер по умолчанию = 128.')
    else:
        logging.info(f'Размер ключа: {size * 8}')

    match mode:
        case (True, False, False):
            logging.info('Генерация ключей\n ------->')
            keys_generator(
                settings['private_key'], settings['public_key'], settings['symmetric_key'], settings['symmetric_key_decrypted'], size)
            logging.info('Ключи сгенерированы')
        case (False, True, False):
            logging.info('Шифрование:\n ------->')
            encrypt_data(settings['src_text_file'], settings['private_key'],
                         settings['symmetric_key'], settings['encrypted_file'], settings["symmetric_key_decrypted"], size)
            logging.info('Данные зашифрованы')
        case (False, False, True):
            logging.info('Дешифрование:\n ------->')
            decrypt_data(settings['encrypted_file'], settings['private_key'],
                         settings['symmetric_key'], settings['decrypted_file'], settings["symmetric_key_decrypted"], size)
            logging.info('Данные расшифрованы')
        case _:
            logging.error("Не выбран допустимый режим")
