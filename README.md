# CryptoCore

Консольная программа для шифрования и расшифрования файлов с помощью AES-128.

Поддерживаются режимы ECB, CBC, CFB, OFB и CTR.

## Зависимости

- Python 3.9 или новее
- pycryptodome
- pip
- OpenSSL для проверки совместимости

Программа работает в Windows, Linux и macOS.

## Содержание

- [Установка в Windows](#установка-в-windows)
- [Установка в Linux и macOS](#установка-в-linux-и-macos)
- [Формат команды](#формат-команды)
- [Режим ECB](#режим-ecb)
- [Режим CBC](#режим-cbc)
- [Режим CFB](#режим-cfb)
- [Режим OFB](#режим-ofb)
- [Режим CTR](#режим-ctr)
- [Проверка полного цикла](#проверка-полного-цикла)
- [Запуск тестов](#запуск-тестов)
- [Interoperability Tests](#interoperability-tests)
- [Генерация ключа](#генерация-ключа)
- [Источник случайности](#источник-случайности)
- [NIST STS](#nist-sts)
- [Хеширование](#хеширование)
- [Проверка хеш-функций](#проверка-хеш-функций)
- [HMAC-SHA256](#hmac-sha256)
- [AES-CMAC](#aes-cmac)
- [Проверка MAC](#проверка-mac)
- [Тестирование MAC](#тестирование-mac)
- [Аутентифицированное шифрование](#аутентифицированное-шифрование)
- [Проверка AEAD](#проверка-aead)

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

## Interoperability Tests

Для проверки совместимости с OpenSSL используется скрипт:

```powershell
.\scripts\openssl_tests.ps1
```

## Генерация ключа

При шифровании параметр `--key` можно не указывать.

```sh
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Программа генерирует ключ AES-128 длиной 16 байт, выводит его один раз в stdout и продолжает шифрование.

Формат сообщения приведён ниже. Вместо `<32 hex symbols>` программа выводит сгенерированный ключ.

```text
Generated random key: <32 hex symbols>
```

Ключ нужно сохранить самостоятельно. В файл с шифртекстом он не записывается. Без ключа восстановить исходные данные не получится.

При расшифровании `--key` обязателен.

```sh
cryptocore --algorithm aes --mode ctr --decrypt --key YOUR_SAVED_KEY --input ciphertext.bin --output decrypted.txt
```

Вместо `YOUR_SAVED_KEY` нужно указать сохранённые 32 шестнадцатеричных символа.

Если `--key` передан при шифровании, программа использует именно его. Для ключей из одинаковых или последовательных байтов выводится предупреждение в stderr. Операция при этом не запрещается.

Вывод с ключом нельзя публиковать или добавлять в репозиторий вместе с зашифрованными данными.

## Источник случайности

Модуль `src/cryptocore/csprng.py` содержит функцию:

```python
generate_random_bytes(num_bytes: int) -> bytes
```

Она использует `os.urandom`, который получает криптографически стойкие случайные данные от операционной системы.

Через эту функцию создаются автоматически сгенерированные ключи, IV для CBC, CFB, OFB и CTR, а также nonce для дополнительного режима GCM. Модуль `random` не используется.

При сбое источника случайности операция завершается с ошибкой. Программа не переключается на менее надёжный генератор.

Формат файлов предыдущих режимов не изменён. Для CBC, CFB, OFB и CTR первые 16 байт содержат IV. При передаче `--iv` во время расшифрования входной файл считается шифртекстом без префикса IV.

Статистические проверки не доказывают криптографическую стойкость генератора. Надёжность источника случайности зависит от реализации операционной системы.

## NIST STS

Для проверки используется NIST Statistical Test Suite с официальной страницы:

https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software

Нужно скачать архив Statistical Test Suite и распаковать его. Для классической реализации STS используется программа `assess`.

### Подготовка данных

Из корневой папки CryptoCore выполните:

```sh
python scripts/generate_nist_data.py
```

Будет создан бинарный файл `nist_test_data.bin` размером 12 500 000 байт. Скрипт выводит SHA-256 файла для идентификации проверенной выборки.

Данные рассчитаны на 100 последовательностей по 1 000 000 бит. Файл следует сохранить до завершения проверки и оформления результатов.

### Запуск в Windows

Для сборки STS используется Ubuntu через WSL. Команда установки запускается в PowerShell с правами администратора.

```powershell
wsl --install -d Ubuntu
```

Если система запросит перезагрузку, выполните её. Затем откройте Ubuntu и завершите первоначальную настройку.

В терминале Ubuntu установите инструменты сборки:

```sh
sudo apt update
sudo apt install build-essential unzip
```

Распакуйте скачанный архив STS в домашнюю папку Ubuntu. Перейдите в каталог, содержащий Makefile, папки `src` и `templates`.

Соберите программу:

```sh
make
```

Скопируйте данные CryptoCore в каталог STS:

```sh
cp /mnt/d/CryptoCore/nist_test_data.bin ./nist_test_data.bin
```

Если проект находится не в `D:\CryptoCore`, укажите фактический путь.

### Запуск в Linux и macOS

Распакуйте архив STS и перейдите в каталог с Makefile. Для Linux понадобятся GCC и make, для macOS можно установить Command Line Tools.

Linux Ubuntu:

```sh
sudo apt install build-essential unzip
```

macOS:

```sh
xcode-select --install
```

Соберите STS:

```sh
make
```

Если Makefile использует недоступный компилятор, исправьте значение `CC` на установленный GCC или Clang.

Скопируйте `nist_test_data.bin` из проекта в каталог STS.

### Параметры проверки

Запускайте программу из каталога STS, чтобы ей были доступны шаблоны и каталоги отчётов.

```sh
./assess 1000000
```

В интерактивном меню выберите источник `Input File` и укажите:

```text
nist_test_data.bin
```

Выберите запуск всех 15 тестов. Если меню предлагает пункт `Apply all tests`, выберите его.

Оставьте стандартные параметры тестов. Для числа последовательностей укажите:

```text
100
```

Для формата входного файла выберите `Binary`, а не `ASCII`.

Если STS сообщает об отсутствии каталогов вывода, создайте их из корня STS и повторите запуск:

```sh
for test in Frequency BlockFrequency CumulativeSums Runs LongestRun Rank FFT NonOverlappingTemplate OverlappingTemplate Universal ApproximateEntropy RandomExcursions RandomExcursionsVariant Serial LinearComplexity
do
    mkdir -p "experiments/AlgorithmTesting/$test"
done
```

### Отчёт

Основной отчёт классической реализации STS находится по пути:

```text
experiments/AlgorithmTesting/finalAnalysisReport.txt
```

Для просмотра:

```sh
cat experiments/AlgorithmTesting/finalAnalysisReport.txt
```

Для отдельных последовательностей используется уровень значимости 0.01. Значение p-value меньше 0.01 означает отказ соответствующей проверки на этой последовательности.

В итоговом отчёте отдельно оцениваются доля прошедших последовательностей и равномерность p-value. Для равномерности STS использует другой порог, поэтому нельзя применять 0.01 ко всем числам в отчёте.

Некоторые тесты создают несколько строк результатов. Для Random Excursions число подходящих последовательностей может быть меньше общего числа, поскольку применимость зависит от числа циклов случайного блуждания.

Единичные отказы возможны и на корректных случайных данных. Массовые отказы требуют проверки реализации и параметров запуска. Не следует повторять генерацию только ради получения отчёта без отказов.

### Результаты NIST STS

Проверка выполнена с помощью NIST STS 2.1.2 в Ubuntu через WSL.

Проверен файл размером 12 500 000 байт. Использованы 100 последовательностей по 1 000 000 бит, бинарный формат входных данных и стандартные параметры всех 15 тестов.

SHA-256 выборки:

```text
45073e3103729e78997ecf8d3e4d9d80dfe83857ed01d1f0e427449d8cd31b62
```

Все значения p-value равномерности в итоговом отчёте превышают порог 0.0001.

Одна проверка NonOverlappingTemplate не прошла критерий доли успешных последовательностей. Для одного шаблона результат составил 95/100 при минимальной допустимой доле 96/100. Остальные строки отчёта проходят критерии STS.

Для RandomExcursions и RandomExcursionsVariant подходящими оказались 60 последовательностей. Результаты составили от 58/60 до 60/60 при минимуме 57/60.

Массовых статистических отклонений не обнаружено. Единичный отказ сохранён в отчёте. Результаты статистических тестов не являются доказательством криптографической стойкости генератора.

Полный отчёт находится в `reports/nist/finalAnalysisReport.txt`.

## Хеширование

Команда `dgst` вычисляет хеш файла. Поддерживаются SHA-256 и SHA3-256 с результатом длиной 256 бит.

```sh
cryptocore dgst --algorithm sha256 --input document.pdf
```

```sh
cryptocore dgst --algorithm sha3-256 --input document.pdf
```

Результат выводится в нижнем регистре. Между хешем и путём находятся два пробела.

```text
HASH_VALUE  INPUT_FILE_PATH
```

Для записи результата в файл используется `--output`. В этом случае stdout остаётся пустым.

```sh
cryptocore dgst --algorithm sha256 --input document.pdf --output document.sha256
```

Для чтения из stdin укажите `--input -`.

Linux и macOS:

```sh
printf 'abc' | cryptocore dgst --algorithm sha256 --input -
```

Без флагов `--hmac` и `--cmac` команда `dgst` выполняет обычное хеширование и отклоняет параметр `--key`.

В MAC-режимах параметр `--key` задаёт секретный ключ HMAC или AES-CMAC. Это расширение пятого спринта, а не параметр шифрования.

Команда `dgst` не принимает параметры `--mode`, `--encrypt`, `--decrypt` и `--iv`.

SHA-256 реализован по FIPS 180-4 и обрабатывает блоки по 64 байта. SHA3-256 реализован по FIPS 202 на основе Keccak-f[1600] с размером поглощаемого блока 136 байт.

Файлы читаются в бинарном режиме порциями по 8192 байта. Потребление памяти при чтении не растёт вместе с размером файла.

Оба алгоритма рассчитаны на 128-битную стойкость к поиску коллизий и 256-битную стойкость к поиску прообраза в стандартной модели оценки.

Обычный хеш не подтверждает подлинность файла. Проверка целостности имеет смысл, если эталонный хеш получен из доверенного источника. Если злоумышленник может заменить и файл, и его хеш, такая проверка не защитит от подмены.

## Проверка хеш-функций

### Автоматические тесты

```sh
python -m unittest discover -s tests -v
```

Проверяются известные ответы, пустые файлы и длины около границ блоков. Дополнительно проверяются последовательные вызовы update, однобитовое изменение сообщения и работа CLI.

### Векторы NIST

Скачайте byte-oriented наборы SHA-256 и SHA3-256 с сайта NIST.

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/sha-3

Для SHA-256 нужны файлы `SHA256ShortMsg.rsp` и `SHA256LongMsg.rsp`. Для SHA3-256 нужны `SHA3_256ShortMsg.rsp` и `SHA3_256LongMsg.rsp`.

Распакуйте наборы в `tests/vectors/sha256` и `tests/vectors/sha3`.

```sh
python scripts/check_hash_vectors.py --algorithm sha256 --directory tests/vectors/sha256
python scripts/check_hash_vectors.py --algorithm sha3-256 --directory tests/vectors/sha3
```

Скрипт завершится с ненулевым кодом при несовпадении результата или отсутствии файлов с векторами.

### Совместимость с системными командами

В Linux SHA-256 можно проверить через sha256sum:

```sh
cryptocore dgst --algorithm sha256 --input document.pdf > cryptocore.sha256
sha256sum document.pdf > system.sha256
diff cryptocore.sha256 system.sha256
```

Для SHA3-256 при установленной sha3sum:

```sh
cryptocore dgst --algorithm sha3-256 --input document.pdf
sha3sum -a 256 document.pdf
```

Значения хешей должны совпасть.

Для автоматического сравнения SHA-256 с sha256sum:

```sh
python scripts/check_hash_files.py --algorithm sha256 --reference sha256sum --sizes-mib 1 10
```

Для SHA3-256 с sha3sum:

```sh
python scripts/check_hash_files.py --algorithm sha3-256 --reference sha3sum --sizes-mib 1 10
```

В Windows оба алгоритма можно сравнить с OpenSSL:

```powershell
python scripts/check_hash_files.py --reference openssl --sizes-mib 1 10
```

В столбце `match` ожидается `true`.

### Файлы больше 1 ГБ

Перед запуском обеспечьте свободное место для временного файла размером 1025 МиБ.

```sh
python scripts/check_hash_files.py --sizes-mib 1025
```

Скрипт проверяет оба алгоритма, сравнивает результаты с OpenSSL и удаляет временный файл после завершения.

Чистая реализация на Python значительно медленнее OpenSSL. Проверка большого файла может занять много часов.

Проверен файл размером 1 074 790 400 байт, что составляет 1025 МиБ и превышает 1 ГиБ.

| Алгоритм | CryptoCore, с | OpenSSL, с | Совпадение |
|---|---|---|---|
| SHA-256 | 5613.432461 | 1.546811 | Да |
| SHA3-256 | 6737.290841 | 3.157365 | Да |

Скрипт завершился с кодом 0. Результаты сохранены в `reports/s4-s5/hash-large-file.csv`, лог запуска находится в `reports/s4-s5/hash-large-file.log`.

### Производительность

Для измерения на нескольких размерах выполните:

```sh
python scripts/check_hash_files.py --sizes-mib 1 10 100
```

Скрипт выводит время вычисления хеша собственной реализацией и системной командой. Создание тестового файла в эти измерения не включается.

Это последовательное измерение с одним запуском для каждой комбинации алгоритма и размера. На время влияют загрузка системы и файловый кеш.

### Результаты измерений

Измерения выполнены в Windows. Для сравнения использован OpenSSL 4.0.3. Для каждой комбинации алгоритма и размера выполнен один запуск. Создание тестового файла не включено в измеряемое время.

| Алгоритм | Размер, МиБ | CryptoCore, с | OpenSSL, с | Совпадение |
|---|---|---|---|---|
| SHA-256 | 1 | 4.142442 | 0.044830 | Да |
| SHA3-256 | 1 | 5.007149 | 0.030162 | Да |
| SHA-256 | 10 | 45.583156 | 0.036078 | Да |
| SHA3-256 | 10 | 46.751178 | 0.058966 | Да |
| SHA-256 | 100 | 358.219016 | 0.296070 | Да |
| SHA3-256 | 100 | 504.604033 | 0.390771 | Да |

Собственные реализации на Python работают значительно медленнее OpenSSL. Результаты зависят от загрузки компьютера и файлового кеша.

Исходные измерения сохранены в `reports/s4-s5/hash-performance.csv`. Лог запуска находится в `reports/s4-s5/hash-performance.log`.

## HMAC-SHA256

HMAC позволяет проверить целостность сообщения и владение общим секретным ключом.

Для вычисления используется собственная реализация SHA-256.

```sh
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Результат содержит MAC в нижнем регистре и путь к файлу, разделённые одним пробелом.

```text
HMAC_VALUE INPUT_FILE_PATH
```

Для сохранения результата используйте `--output`.

```sh
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
```

При записи в файл stdout остаётся пустым.

Ключ передаётся в шестнадцатеричном формате. Число символов должно быть чётным. HMAC поддерживает ключи переменной длины. Для использования рекомендуется случайный секретный ключ длиной 32 байта.

Ключи длиннее 64 байт предварительно хешируются. Более короткие дополняются нулями до 64 байт.

Конструкция HMAC соответствует RFC 2104.

```text
HMAC = H[outer_pad || H[inner_pad || message]]
```

`inner_pad` получается XOR подготовленного ключа с повторяющимся байтом `0x36`. Для `outer_pad` используется байт `0x5c`.

HMAC не шифрует данные. Любой владелец общего ключа может создать корректный MAC, поэтому HMAC не заменяет цифровую подпись.

## AES-CMAC

AES-CMAC использует AES-128 и ключ длиной 16 байт.

```sh
cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.cmac
```

Логика CMAC реализована по NIST SP 800-38B. Для шифрования отдельных блоков используется AES из PyCryptodome.

Размер результата составляет 16 байт. В отличие от обычного CBC-MAC, CMAC корректно обрабатывает сообщения переменной длины с помощью подключей и специальной обработки последнего блока.

Для MAC и шифрования следует использовать разные ключи.

## Проверка MAC

Для HMAC:

```sh
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.hmac
```

Для CMAC:

```sh
cryptocore dgst --algorithm aes --cmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.cmac
```

При совпадении программа выводит сообщение об успешной проверке и завершается с кодом 0.

```text
[OK] HMAC verification successful
```

При несовпадении возвращается ненулевой код, а сообщение выводится в stderr.

```text
[ERROR] HMAC verification failed
```

Ожидаемый MAC читается из первого поля единственной непустой строки файла. Пробелы вокруг значения и имя файла игнорируются. Допускаются hex-символы в обоих регистрах.

Проверяется полный MAC. Усечённые значения не принимаются.

Параметры `--verify` и `--output` нельзя использовать вместе. Параметр `--key` обязателен для HMAC и CMAC.

Сравнение MAC выполняется через `compare_digest`. Изменение файла или использование другого ключа приводит к неуспешной проверке.

Входные файлы читаются в бинарном режиме порциями по 8192 байта. Также поддерживается `--input -` для чтения из stdin.

## Тестирование MAC

Все команды выполняются из корневой папки проекта.

```sh
python -m unittest discover -s tests -v
```

Проверки HMAC включают все семь случаев RFC 4231 для SHA-256. Для случая 5 сравниваются первые 128 бит результата согласно вектору.

https://www.rfc-editor.org/rfc/rfc4231.html

Для AES-CMAC используются четыре примера AES-128 из приложения D NIST SP 800-38B.

https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final

Также проверяются разные размеры ключа HMAC, пустые файлы и последовательные обновления состояния. CLI-тесты проверяют создание MAC, успешную проверку, изменение одного байта сообщения и использование другого ключа.

### Файл больше доступной памяти

Проверка запускается в Linux или Ubuntu WSL.

```sh
python scripts/check_large_mac.py
```

Сценарий ограничивает адресное пространство процесса до 128 МиБ и обрабатывает файл 257 МиБ. Результаты HMAC и CMAC сравниваются с библиотечными реализациями. Временный файл удаляется после завершения.

Для отдельной проверки HMAC:

```sh
python scripts/check_large_mac.py --kind hmac
```

Для отдельной проверки CMAC:

```sh
python scripts/check_large_mac.py --kind cmac
```

Проверка считается успешной после завершения сценария с кодом 0 и сообщениями `PASS`. 

Проверка выполнена в Ubuntu через WSL. Размер файла составил 257 МиБ, лимит адресного пространства процесса установлен в 128 МиБ.

| Алгоритм | Время проверки, с | Результат |
|---|---|---|
| HMAC-SHA256 | 599.026 | Совпадение с библиотечной реализацией |
| AES-CMAC | 46.947 | Совпадение с библиотечной реализацией |

Указанное время включает вычисление MAC собственной и библиотечной реализациями. Создание входного файла в него не включено.

Обе проверки завершились успешно, итоговый код завершения 0. Лог находится в `reports/s4-s5/large-mac.txt`.

## Аутентифицированное шифрование

Поддерживаются AES-128-GCM и Encrypt-then-MAC на AES-CTR с HMAC-SHA256.

AEAD обеспечивает конфиденциальность сообщения и проверку подлинности шифртекста вместе с дополнительными данными.

AAD не шифруется и не записывается в выходной файл. Для расшифрования нужно передать те же байты AAD.

Параметр `--aad HEX` принимает шестнадцатеричную строку. Для больших AAD предусмотрен `--aad-file FILE`. Эти параметры нельзя использовать одновременно.

Если AAD не указан, он считается пустым.

### AES-128-GCM

Шифрование:

```sh
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin --aad aabbccddeeff
```

Расшифрование:

```sh
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad aabbccddeeff
```

GCM использует ключ длиной 16 байт. При каждом шифровании автоматически генерируется случайный nonce длиной 12 байт.

Формат файла:

```text
nonce[12] || ciphertext || tag[16]
```

Nonce можно передать отдельно при расшифровании через `--nonce` или совместимый параметр `--iv`. В этом случае входной файл должен содержать только шифртекст и тег, без nonce.

```sh
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --nonce 000102030405060708090a0b --input ciphertext-without-nonce.bin --output decrypted.txt --aad aabbccddeeff
```

Указание nonce при шифровании через CLI запрещено.

В рабочем коде AES используется как блочный примитив ECB. Счётчик GCM, GHASH, табличное умножение в поле GF[2^128] и формирование тега реализованы в проекте.

Программный detached-интерфейс поддерживает nonce нестандартной длины через обработку GHASH. Файловый интерфейс использует 12-байтовые nonce.

### Большие AAD

AAD-файл читается в бинарном режиме порциями по 8192 байта.

```sh
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin --aad-file metadata.bin
```

```sh
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad-file metadata.bin
```

### Encrypt-then-MAC

Для ETM используется master key длиной 32 байта. Из него выводятся отдельные ключи AES-128 и HMAC-SHA256 через HMAC-based KDF в режиме счётчика.

```sh
cryptocore --algorithm aes --mode etm --encrypt --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --input plaintext.txt --output ciphertext.etm --aad aabbcc
```

```sh
cryptocore --algorithm aes --mode etm --decrypt --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --input ciphertext.etm --output decrypted.txt --aad aabbcc
```

Формат файла:

```text
nonce[12] || ciphertext || tag[32]
```

Сначала сообщение шифруется AES-CTR. Затем вычисляется HMAC по разделителю протокола, nonce, шифртексту, AAD и длинам шифртекста и AAD.

При расшифровании HMAC проверяется до восстановления открытого текста.

### Генерация ключа

Если при шифровании `--key` не указан, программа генерирует случайный ключ и один раз выводит его в stdout.

```text
Generated random key: HEX_KEY
```

Ключ нужно сохранить отдельно. В шифртекст он не записывается. Для расшифрования ключ обязателен.

### Отказ аутентификации

Неверный ключ или изменение аутентифицируемых данных приводят к отказу проверки.

Программа возвращает ненулевой код и сообщает об ошибке в stderr. Открытый текст не выводится. Новый выходной файл не создаётся, а существующий файл остаётся без изменений.

Катастрофический отказ в этом контексте означает полный отказ операции без выдачи открытого текста. Он не означает удаление пользовательских файлов или аварийное завершение системы.

Проверка выполняется до расшифрования. Для защиты от изменения исходного файла между проверкой и расшифрованием используется временная копия шифртекста.

При работе с большими файлами нужно место на диске для временного шифртекста и временного выходного файла.

Повторное использование nonce с одним ключом GCM недопустимо. Оно нарушает конфиденциальность и может позволить подделку тегов. Случайные nonce требуют ограничения числа сообщений под одним ключом и своевременной смены ключа.

Программный интерфейс с фиксированным nonce предназначен для тестов. Один nonce нельзя использовать для шифрования разных сообщений под одним ключом.

Реализация Python не заявляется как защищённая от атак по сторонним каналам. Таблицы GHASH и операции Python не обеспечивают постоянное время выполнения.

## Проверка AEAD

Установка тестовой зависимости:

```sh
python -m pip install -e ".[test]"
```

Все автоматические тесты:

```sh
python -m unittest discover -s tests -v
```

Только проверки AEAD:

```sh
python -m unittest discover -s tests -p "test_aead.py" -v
```

Проверяются известные ответы GCM, пустые сообщения и разные длины AAD и nonce. Дополнительно проверяются подмена каждого бита короткого GCM-сообщения, неверный ключ и сохранность выходного файла при отказе.

Для Encrypt-then-MAC проверяются полные циклы обработки, неверный ключ и изменение AAD. Дополнительно проверяется отклонение каждого одиночного битового изменения контейнера, включая nonce, шифртекст и тег. При отказе новый выходной файл не создаётся, а существующий остаётся неизменным.

Отдельный тест проверяет отсутствие повторов nonce при 1000 шифрованиях ETM. Отсутствие повторов в этой выборке не является доказательством случайности.

### Векторы NIST

Наборы GCM CAVP нужно распаковать в `tests/vectors/gcm`.

```sh
python scripts/check_gcm_vectors.py --directory tests/vectors/gcm
```

Проверяются AES-128 и полный тег длиной 128 бит. Векторы других размеров ключей и усечённых тегов пропускаются.

Для проверки отрицательных случаев нужен набор расшифрования с записями FAIL.

### Совместимость с OpenSSL

Команда `openssl enc` не поддерживает AEAD, поэтому пример с `openssl enc -aes-128-gcm` не используется.

Автоматический тест проверяет совместимость AES-128-GCM через AESGCM из библиотеки cryptography, использующей backend OpenSSL. Сравниваются шифртекст и тег. Расшифрование проверяется в обоих направлениях.

Это альтернативная проверка через программный интерфейс OpenSSL, а не через OpenSSL CLI.

### AAD больше доступной памяти

Проверка запускается в Linux или Ubuntu WSL.

```sh
python -u scripts/check_large_aad.py
```

Сценарий ограничивает адресное пространство процесса до 128 МиБ и обрабатывает AAD-файл 129 МиБ.

Проверяются совпадение с библиотечным GCM, полный цикл и отказ при изменении одного байта AAD.

Если окружению недостаточно установленного лимита, можно одновременно увеличить лимит и размер AAD:

```sh
python -u scripts/check_large_aad.py --memory-mib 256 --aad-mib 257
```

Размер AAD должен оставаться больше лимита памяти процесса.

Проверка считается пройденной только после завершения сценария с кодом 0 и сообщениями PASS.

### Результаты проверок

Все 24 автоматических теста AEAD завершились успешно. Полный набор проекта из 92 тестов также завершился с результатом OK и кодом 0.

Проверены 2250 официальных векторов NIST CAVP для AES-128-GCM с тегом 128 бит. В их числе 590 отрицательных случаев, все они корректно отклонены.

В Ubuntu через WSL проверена обработка AAD размером 129 МиБ при лимите адресного пространства процесса 128 МиБ. Результат совпал с библиотечным GCM. Полный цикл шифрования и расшифрования выполнен успешно, изменение AAD вызвало отказ без создания выходного файла.

Логи проверок:

- `reports/s6/aead-tests.txt`
- `reports/s6/all-tests.txt`
- `reports/s6/nist-gcm.txt`
- `reports/s6/large-aad.txt`