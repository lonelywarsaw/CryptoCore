$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$inputFile = Join-Path $root "openssl-test-plain.bin"
$key = "000102030405060708090a0b0c0d0e0f"
$fixedIv = "aabbccddeeff00112233445566778899"

function Assert-FileEqual {
    param(
        [string]$First,
        [string]$Second,
        [string]$Message
    )

    $firstBytes = [System.IO.File]::ReadAllBytes($First)
    $secondBytes = [System.IO.File]::ReadAllBytes($Second)

    if ($firstBytes.Length -ne $secondBytes.Length) {
        throw "$Message. Размеры файлов различаются."
    }

    for ($index = 0; $index -lt $firstBytes.Length; $index++) {
        if ($firstBytes[$index] -ne $secondBytes[$index]) {
            throw "$Message. Файлы различаются."
        }
    }

    Write-Host "PASS $Message" -ForegroundColor Green
}

function Invoke-CryptoCore {
    param(
        [string[]]$Arguments
    )

    & $python -m cryptocore.cli @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "CryptoCore завершился с кодом $LASTEXITCODE."
    }
}

function Invoke-OpenSSL {
    param(
        [string[]]$Arguments
    )

    & openssl enc @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL завершился с кодом $LASTEXITCODE."
    }
}

function Get-IV-And-Ciphertext {
    param(
        [string]$InputFile,
        [string]$IvFile,
        [string]$CiphertextFile
    )

    $allBytes = [System.IO.File]::ReadAllBytes($InputFile)

    if ($allBytes.Length -lt 16) {
        throw "Файл $InputFile не содержит полный IV."
    }

    [byte[]]$ivBytes = $allBytes[0..15]
    [byte[]]$ciphertextBytes = $allBytes[16..($allBytes.Length - 1)]

    [System.IO.File]::WriteAllBytes($IvFile, $ivBytes)
    [System.IO.File]::WriteAllBytes($CiphertextFile, $ciphertextBytes)

    return (($ivBytes | ForEach-Object {
        $_.ToString("x2")
    }) -join "")
}

if (-not (Test-Path $python)) {
    throw "Не найден Python виртуального окружения: $python"
}

try {
    openssl version | Out-Host
}
catch {
    throw "Команда openssl не найдена."
}

[System.IO.File]::WriteAllBytes(
    $inputFile,
    [byte[]](0..36)
)

$ecbCryptoCore = Join-Path $root "openssl-test-ecb-cryptocore.bin"
$ecbOpenSSL = Join-Path $root "openssl-test-ecb-openssl.bin"

Invoke-CryptoCore @(
    "--algorithm",
    "aes",
    "--mode",
    "ecb",
    "--encrypt",
    "--key",
    $key,
    "--input",
    $inputFile,
    "--output",
    $ecbCryptoCore
)

Invoke-OpenSSL @(
    "-aes-128-ecb",
    "-K",
    $key,
    "-in",
    $inputFile,
    "-out",
    $ecbOpenSSL
)

Assert-FileEqual `
    $ecbCryptoCore `
    $ecbOpenSSL `
    "ECB CryptoCore и OpenSSL"

$modes = @("cbc", "cfb", "ofb", "ctr")

foreach ($mode in $modes) {
    $cryptoCoreOutput = Join-Path $root "openssl-test-$mode-cryptocore.bin"
    $ciphertextOnly = Join-Path $root "openssl-test-$mode-ciphertext.bin"
    $ivFile = Join-Path $root "openssl-test-$mode-iv.bin"
    $opensslDecrypted = Join-Path $root "openssl-test-$mode-openssl-decrypted.bin"

    Invoke-CryptoCore @(
        "--algorithm",
        "aes",
        "--mode",
        $mode,
        "--encrypt",
        "--key",
        $key,
        "--input",
        $inputFile,
        "--output",
        $cryptoCoreOutput
    )

    $ivHex = Get-IV-And-Ciphertext `
        $cryptoCoreOutput `
        $ivFile `
        $ciphertextOnly

    Invoke-OpenSSL @(
        "-aes-128-$mode",
        "-d",
        "-K",
        $key,
        "-iv",
        $ivHex,
        "-in",
        $ciphertextOnly,
        "-out",
        $opensslDecrypted
    )

    Assert-FileEqual `
        $inputFile `
        $opensslDecrypted `
        "$mode CryptoCore -> OpenSSL"

    $opensslCiphertext = Join-Path $root "openssl-test-$mode-openssl.bin"
    $cryptoCoreDecrypted = Join-Path $root "openssl-test-$mode-cryptocore-decrypted.bin"

    $opensslArguments = @(
        "-aes-128-$mode",
        "-K",
        $key,
        "-iv",
        $fixedIv,
        "-in",
        $inputFile,
        "-out",
        $opensslCiphertext
    )

    if ($mode -in @("cfb", "ofb", "ctr")) {
        $opensslArguments += "-nopad"
    }

    Invoke-OpenSSL $opensslArguments

    Invoke-CryptoCore @(
        "--algorithm",
        "aes",
        "--mode",
        $mode,
        "--decrypt",
        "--key",
        $key,
        "--iv",
        $fixedIv,
        "--input",
        $opensslCiphertext,
        "--output",
        $cryptoCoreDecrypted
    )

    Assert-FileEqual `
        $inputFile `
        $cryptoCoreDecrypted `
        "$mode OpenSSL -> CryptoCore"
}

Write-Host ""
Write-Host "Все проверки совместимости завершились успешно." `
    -ForegroundColor Green