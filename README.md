# CryptoCore

Консольная программа для шифрования и расшифрования файлов с помощью AES-128.

Поддерживаются режимы ECB, CBC, CFB, OFB и CTR.

## Зависимости

- Python 3.9 или новее
- pycryptodome
- pip
- OpenSSL для проверки совместимости

Программа работает в Windows, Linux и macOS.

## Установка в Windows

Откройте PowerShell в папке проекта:

```powershell
cd D:\CryptoCore
```

Создайте виртуальное окружение:

```powershell
python -m venv .venv
```

Активируйте его:

```powershell
.\.venv\Scripts\Activate.ps1
```

Установите проект:

```powershell
python -m pip install .
```

Если PowerShell запрещает запуск скриптов, выполните:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

После этого снова активируйте окружение:

```powershell
.\.venv\Scripts\Activate.ps1
```

Проверка установки:

```powershell
python -m cryptocore.cli --help
```

## Установка в Linux и macOS

Откройте терминал в папке проекта:

```sh
cd CryptoCore
```

Создайте виртуальное окружение:

```sh
python3 -m venv .venv
```

Активируйте его:

```sh
. .venv/bin/activate
```

Установите проект:

```sh
python -m pip install .
```

Проверка установки:

```sh
python -m cryptocore.cli --help
```

## Формат команды

Для шифрования:

```text
cryptocore --algorithm aes --mode MODE --encrypt --key KEY --input INPUT_FILE --output OUTPUT_FILE
```

Для расшифрования:

```text
cryptocore --algorithm aes --mode MODE --decrypt --key KEY --input INPUT_FILE --output OUTPUT_FILE
```

В одной команде нужно указывать только один параметр операции:

```text
--encrypt
```

или:

```text
--decrypt
```

Ключ AES-128 передаётся как 32 шестнадцатеричных символа:

```text
000102030405060708090a0b0c0d0e0f
```

IV передаётся как 32 шестнадцатеричных символа:

```text
AABBCCDDEEFF00112233445566778899
```

## Режим ECB

Шифрование:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

В режиме ECB используется дополнение PKCS#7. IV не используется.

## Режим CBC

Шифрование:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

При шифровании программа создаёт случайный IV с помощью `os.urandom(16)`.

Формат выходного файла:

```text
16 байт IV + шифртекст
```

Расшифрование с IV из начала файла:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Если входной файл содержит только шифртекст, IV можно передать отдельно:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 --input ciphertext-only.bin --output decrypted.txt
```

Для CBC используется дополнение PKCS#7.

## Режим CFB

Шифрование:

```powershell
cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Первые 16 байт выходного файла содержат IV.

Padding не используется. Размер шифртекста без IV совпадает с размером исходного файла.

## Режим OFB

Шифрование:

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Первые 16 байт выходного файла содержат IV.

Padding не используется. Размер шифртекста без IV совпадает с размером исходного файла.

## Режим CTR

Шифрование:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Первые 16 байт выходного файла содержат IV.

Счётчик инициализируется значением IV и увеличивается для каждого блока. Padding не используется.

## Проверка полного цикла в Windows

Создайте исходный файл:

```powershell
"CryptoCore test" | Set-Content -NoNewline plaintext.txt
```

Зашифруйте файл:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифруйте файл:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plaintext.txt")
$b = [System.IO.File]::ReadAllBytes("decrypted.txt")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

## Проверка полного цикла в Linux и macOS

Создайте исходный файл:

```sh
printf 'CryptoCore test' > plaintext.txt
```

Зашифруйте файл:

```sh
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифруйте файл:

```sh
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Сравните файлы:

```sh
cmp plaintext.txt decrypted.txt
```

Если команда завершилась без сообщения, файлы совпадают.

## Запуск тестов

Windows:

```powershell
python -m unittest .\tests\test_cryptocore.py -v
```

Linux и macOS:

```sh
python -m unittest tests/test_cryptocore.py -v
```

## Проверка ECB через OpenSSL

Создайте файл с тестовыми данными:

```powershell
python -c "from pathlib import Path; Path('plain.bin').write_bytes(bytes(range(32)))"
```

Задайте ключ:

```powershell
$key = "000102030405060708090a0b0c0d0e0f"
```

Зашифруйте файл CryptoCore:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key $key --input plain.bin --output cryptocore-ecb.bin
```

Зашифруйте тот же файл OpenSSL:

```powershell
openssl enc -aes-128-ecb -K $key -in plain.bin -out openssl-ecb.bin
```

Сравните результаты:

```powershell
$a = [System.IO.File]::ReadAllBytes("cryptocore-ecb.bin")
$b = [System.IO.File]::ReadAllBytes("openssl-ecb.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

## Проверка CBC через OpenSSL

Зашифруйте файл CryptoCore:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key $key --input plain.bin --output cryptocore-cbc.bin
```

Отделите IV от шифртекста:

```powershell
$all = [System.IO.File]::ReadAllBytes("cryptocore-cbc.bin")
$ivBytes = $all[0..15]
$cipherBytes = $all[16..($all.Length - 1)]

[System.IO.File]::WriteAllBytes("cbc.ciphertext", $cipherBytes)

$ivHex = ($ivBytes | ForEach-Object { $_.ToString("x2") }) -join ""
```

Расшифруйте шифртекст через OpenSSL:

```powershell
openssl enc -aes-128-cbc -d -K $key -iv $ivHex -in cbc.ciphertext -out openssl-cbc-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("openssl-cbc-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

Зашифруйте файл через OpenSSL:

```powershell
$iv = "aabbccddeeff00112233445566778899"
openssl enc -aes-128-cbc -K $key -iv $iv -in plain.bin -out openssl-cbc.bin
```

Расшифруйте файл через CryptoCore:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key $key --iv $iv --input openssl-cbc.bin --output cryptocore-cbc-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("cryptocore-cbc-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

## Проверка CFB через OpenSSL

Зашифруйте файл CryptoCore:

```powershell
cryptocore --algorithm aes --mode cfb --encrypt --key $key --input plain.bin --output cryptocore-cfb.bin
```

Отделите IV от шифртекста:

```powershell
$all = [System.IO.File]::ReadAllBytes("cryptocore-cfb.bin")
$ivBytes = $all[0..15]
$cipherBytes = $all[16..($all.Length - 1)]

[System.IO.File]::WriteAllBytes("cfb.ciphertext", $cipherBytes)

$ivHex = ($ivBytes | ForEach-Object { $_.ToString("x2") }) -join ""
```

Расшифруйте файл через OpenSSL:

```powershell
openssl enc -aes-128-cfb -d -K $key -iv $ivHex -in cfb.ciphertext -out openssl-cfb-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("openssl-cfb-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

Проверка обратного направления:

```powershell
openssl enc -aes-128-cfb -K $key -iv $iv -in plain.bin -out openssl-cfb.bin
cryptocore --algorithm aes --mode cfb --decrypt --key $key --iv $iv --input openssl-cfb.bin --output cryptocore-cfb-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("cryptocore-cfb-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

## Проверка OFB через OpenSSL

Зашифруйте файл CryptoCore:

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key $key --input plain.bin --output cryptocore-ofb.bin
```

Отделите IV от шифртекста:

```powershell
$all = [System.IO.File]::ReadAllBytes("cryptocore-ofb.bin")
$ivBytes = $all[0..15]
$cipherBytes = $all[16..($all.Length - 1)]

[System.IO.File]::WriteAllBytes("ofb.ciphertext", $cipherBytes)

$ivHex = ($ivBytes | ForEach-Object { $_.ToString("x2") }) -join ""
```

Расшифруйте файл через OpenSSL:

```powershell
openssl enc -aes-128-ofb -d -K $key -iv $ivHex -in ofb.ciphertext -out openssl-ofb-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("openssl-ofb-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

Проверка обратного направления:

```powershell
openssl enc -aes-128-ofb -K $key -iv $iv -in plain.bin -out openssl-ofb.bin
cryptocore --algorithm aes --mode ofb --decrypt --key $key --iv $iv --input openssl-ofb.bin --output cryptocore-ofb-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("cryptocore-ofb-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

## Проверка CTR через OpenSSL

Зашифруйте файл CryptoCore:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key $key --input plain.bin --output cryptocore-ctr.bin
```

Отделите IV от шифртекста:

```powershell
$all = [System.IO.File]::ReadAllBytes("cryptocore-ctr.bin")
$ivBytes = $all[0..15]
$cipherBytes = $all[16..($all.Length - 1)]

[System.IO.File]::WriteAllBytes("ctr.ciphertext", $cipherBytes)

$ivHex = ($ivBytes | ForEach-Object { $_.ToString("x2") }) -join ""
```

Расшифруйте файл через OpenSSL:

```powershell
openssl enc -aes-128-ctr -d -K $key -iv $ivHex -in ctr.ciphertext -out openssl-ctr-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("openssl-ctr-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Ожидаемый результат:

```text
True
```

Проверка обратного направления:

```powershell
openssl enc -aes-128-ctr -K $key -iv $iv -in plain.bin -out openssl-ctr.bin
cryptocore --algorithm aes --mode ctr --decrypt --key $key --iv $iv --input openssl-ctr.bin --output cryptocore-ctr-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("cryptocore-ctr-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```

Если OpenSSL не поддерживает режим `aes-128-ctr`, проверьте полный цикл CryptoCore:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key $key --input plain.bin --output cryptocore-ctr.bin
cryptocore --algorithm aes --mode ctr --decrypt --key $key --input cryptocore-ctr.bin --output cryptocore-ctr-dec.bin
```

Сравните файлы:

```powershell
$a = [System.IO.File]::ReadAllBytes("plain.bin")
$b = [System.IO.File]::ReadAllBytes("cryptocore-ctr-dec.bin")
[System.Linq.Enumerable]::SequenceEqual($a, $b)
```