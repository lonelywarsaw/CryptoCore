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

Для обычного хеширования ключ не используется. Параметр `--key` доступен только с `--hmac` или `--cmac`.

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

### Производительность

Для измерения на нескольких размерах выполните:

```sh
python scripts/check_hash_files.py --sizes-mib 1 10 100
```

Скрипт выводит время вычисления хеша собственной реализацией и системной командой. Создание тестового файла в эти измерения не включается.

Это последовательное измерение с одним запуском для каждой комбинации алгоритма и размера. На время влияют загрузка системы и файловый кеш.

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