import argparse
import json
import logging
import os

from encryption_decryption import keys_generator, encrypt_data, decrypt_data


def check_size(size: int):
    """Проверка размерности для ключа"""
    if size == 128 or size == 192 or size == 256:
        return size, True
    return 128, False


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()

    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        '-gen', '--generation', action='store_true', help='Start regeneration of keys mode')
    mode_group.add_argument('-enc', '--encryption', action='store_true',
                            help='Start encryption of data mode')
    mode_group.add_argument('-dec', '--decryption', action='store_true',
                            help='Start decryption of data mode')
    parser.add_argument('config_file', metavar='N',
                        type=str, help='Custom config file')
    #args = parser.parse_args()
    #mode = (args.generation, args.encryption, args.decryption)
    mode = (True, False, False)
    CONFIG = os.path.join('path.json')  # что-то надо поменять
    settings = str()
    try:
        with open(CONFIG) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        logging.error(f"{CONFIG} не найден\nExit")
        exit()
    size = int(settings["size"])
    size, correct = check_size(size)
    if not correct:
        logging.info(
            'Размер ключа введен некорректно -> установлен размер по умолчанию = 128.')
    else:
        logging.info(f'Размер ключа: {size}')

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
