Взаимодействие с пользователем происходит через терминал на этапе вызова программы (main.py)

Для получения справочной информации нужно ввести:
python .\main.py -h  

Тогда вы получите следующую справочную информацию:
usage: main.py [-h] (-gen | -enc | -dec)
options:
  -h, --help          show this help message and exit
  -gen, --generation  Сгенерировать ключи
  -enc, --encryption  Зашифровать данные
  -dec, --decryption  Расшифровать данные

Также размер ключа задается в файле (path.json) в поле size.
Там можно указать любое значение, но если оно не будет равно 128, 192 или 256,
то по умолчанию size установится равным 128.

Исходный текст лежит в файле text.txt, дальше он шифруется в файл encrypted_text.txt
и расшивровывается в файл decrypted_text.txt