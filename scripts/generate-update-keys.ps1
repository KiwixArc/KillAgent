$ErrorActionPreference = "Stop"

$javaExe = "java"
if (-not (Get-Command $javaExe -ErrorAction SilentlyContinue)) {
    $jdkBin = Get-ChildItem "C:\Program Files\Java\jdk-21*\bin\java.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    if (-not $jdkBin) { throw "JDK 21 java.exe not found." }
    $javaExe = $jdkBin
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " KILLAgent Ed25519 Update Signing Key Pair Generator" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

& $javaExe (Join-Path $PSScriptRoot "ManifestSigner.java") keygen
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nInstrucciones de uso:" -ForegroundColor Yellow
Write-Host "1. Copia UPDATE_SIGNING_PRIVATE_KEY en GitHub -> Settings -> Secrets -> Actions (solo CI/CD)."
Write-Host "2. Copia UPDATE_SIGNING_PUBLIC_KEY en tu configuracion de cliente (UPDATE_SIGNING_PUBLIC_KEY en .env / config.properties)."
Write-Host "3. Nunca subas la clave privada al repositorio."
