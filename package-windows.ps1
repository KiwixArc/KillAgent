<#
.SYNOPSIS
    Compiles KILLAgent, strips a minimal custom Java 21 runtime (~35 MB) via jlink
    (explicitly including java.smartcardio & jdk.crypto.cryptoki / SunPKCS11),
    and produces a standalone Windows installer (.msi / .exe / app-image) via jpackage.

.DESCRIPTION
    Requires:
    - JDK 21 LTS with jlink and jpackage in PATH
    - Apache Maven 3.9+ in PATH
    - WiX Toolset 3.x (required only when -PackageType is 'msi' or 'exe')
#>

param(
    [ValidateSet("msi", "exe", "app-image")]
    [string]$PackageType = "msi",
    [string]$AppVersion = "1.0.0"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Building KILLAgent Standalone Windows Package ($PackageType)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Run tests and package shaded Fat JAR
Write-Host "`n[1/4] Running tests and building shaded JAR..." -ForegroundColor Yellow
mvn clean package

$shadedJar = "target\killagent-1.0.0-SNAPSHOT.jar"
if (-not (Test-Path $shadedJar)) {
    throw "Shaded JAR not found at $shadedJar"
}

# 2. Stage clean input directory (prevents copying build intermediates into installer)
$stageDir = "target\jpackage-input"
$runtimeDir = "target\custom-jre"
$outDir = "dist"

foreach ($dir in @($stageDir, $runtimeDir, $outDir)) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
    }
}
New-Item -ItemType Directory -Path $stageDir | Out-Null
New-Item -ItemType Directory -Path $outDir | Out-Null
Copy-Item -Path $shadedJar -Destination "$stageDir\killagent.jar"

# 3. Build stripped custom JRE via jlink (explicitly bundling PC/SC and SunPKCS11 modules)
Write-Host "`n[2/4] Building stripped minimal JRE (~35 MB) via jlink..." -ForegroundColor Yellow
$requiredModules = @(
    "java.base",
    "java.desktop",
    "java.logging",
    "java.naming",
    "java.smartcardio",
    "jdk.crypto.cryptoki",
    "jdk.crypto.ec",
    "jdk.unsupported"
) -join ","

jlink `
    --add-modules $requiredModules `
    --strip-debug `
    --no-man-pages `
    --no-header-files `
    --compress=zip-6 `
    --output $runtimeDir

if ($LASTEXITCODE -ne 0) {
    throw "jlink failed with exit code $LASTEXITCODE"
}

# 4. Run jpackage with memory-tuned JVM flags (< 45 MB RAM footprint target)
Write-Host "`n[3/4] Packaging native Windows distribution ($PackageType) via jpackage..." -ForegroundColor Yellow

$jpackageArgs = @(
    "--type", $PackageType,
    "--dest", $outDir,
    "--name", "KILLAgent",
    "--app-version", $AppVersion,
    "--vendor", "Ch'asca Zero Trust Platform",
    "--copyright", "Copyright (c) 2026 Ch'asca Platform",
    "--description", "Zero Trust Hardware Anchor & PKCS#11 DNIe Desktop Agent",
    "--runtime-image", $runtimeDir,
    "--input", $stageDir,
    "--main-jar", "killagent.jar",
    "--main-class", "pe.ong.chasca.killagent.KillAgentApplication",
    "--java-options", "-Dfile.encoding=UTF-8",
    "--java-options", "-Dsun.java2d.dpiaware=true",
    "--java-options", "-XX:+UseSerialGC",
    "--java-options", "-Xms16m",
    "--java-options", "-Xmx64m"
)

if ($PackageType -ne "app-image") {
    $jpackageArgs += @(
        "--win-dir-chooser",
        "--win-menu",
        "--win-shortcut",
        "--win-per-user-install"
    )
}

jpackage @jpackageArgs

if ($LASTEXITCODE -ne 0) {
    throw "jpackage failed with exit code $LASTEXITCODE"
}

Write-Host "`n[4/4] Package generated successfully in '$outDir\':" -ForegroundColor Green
Get-ChildItem $outDir
