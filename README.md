# CryptoCore

CryptoCore – консольный инструмент для шифрования и расшифрования файлов с помощью AES-128-ECB и дополнения PKCS#7.

## Зависимости

- Python 3.9 или новее.
- pip и setuptools для установки проекта.
- pycryptodome версии от 3.20 до 4. Библиотека устанавливается автоматически.
- Git для размещения проекта в репозитории.
- OpenSSL для дополнительной проверки совпадения шифртекста. Для работы инструмента OpenSSL не требуется.

## Установка

На Linux и macOS выполните команды из корня проекта.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
cryptocore --help
```

В PowerShell вместо команды активации используйте `.venv\Scripts\Activate.ps1`. Если в системе команда Python называется `py`, замените `python` на `py`.

Проект написан на Python и не требует отдельной компиляции. Команда `pip install .` устанавливает зависимости и регистрирует исполняемую команду `cryptocore`.

## Использование

Ключ AES-128 передаётся как 32 шестнадцатеричных символа. Пример шифрования файла.

```sh
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Пример расшифрования.

```sh
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Если `--output` опущен, инструмент добавляет к имени входного файла `.enc` при шифровании или `.dec` при расшифровании. Для операции требуется ровно один из флагов `--encrypt` и `--decrypt`.

## Проверка полного цикла

После установки выполните команды из корня проекта на Linux или macOS.

```sh
printf 'CryptoCore test\n' > original_file.txt
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input original_file.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted_file.txt
diff original_file.txt decrypted_file.txt
```

Успешный `diff` не выводит различий. Для бинарного файла можно использовать `cmp original.bin decrypted.bin`.

Запуск автоматических тестов после установки проекта.

```sh
python -m unittest discover -s tests -v
```

## Сравнение с OpenSSL

Следующие команды используют стандартное дополнение OpenSSL, совместимое с PKCS#7. Флаг `-nopad` здесь не нужен.

```sh
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input original_file.txt --output ciphertext.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in original_file.txt -out ciphertext_openssl.bin
cmp ciphertext.bin ciphertext_openssl.bin
```

Если `cmp` не выводит различий, шифртексты совпадают. Автоматический тест с OpenSSL пропускается, если программа не установлена.

## Размещение в Git

Выполните команды из корня проекта после создания файлов.

```sh
git init
git add .
git commit -m "Implement CryptoCore sprint 1"
```

Чтобы разместить репозиторий на GitHub или GitLab, создайте там пустой репозиторий, затем используйте предоставленный сервисом адрес.

```sh
git branch -M main
git remote add origin ВАШ_АДРЕС_РЕПОЗИТОРИЯ
git push -u origin main
```

## Ограничения безопасности

ECB раскрывает совпадения одинаковых блоков и не обеспечивает проверку подлинности данных. Этот режим реализован для выполнения требований спринта и не рекомендуется для защиты реальных файлов. Не передавайте секретные ключи через командную строку в рабочей среде, где аргументы процессов или история команд могут быть доступны другим пользователям.