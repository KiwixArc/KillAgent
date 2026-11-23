<#
.SYNOPSIS
    Compiles KILLAgent, creates a stripped minimal Java 21 runtime via jlink
    (including java.smartcardio, java.net.http, and jdk.crypto.cryptoki / SunPKCS11),
    produces Windows distributions (.msi / .exe / app-image / portable .zip),
    optionally signs binaries with Windows Authenticode, computes SHA-256 checksums,
    and generates an update-manifest.json (optionally signed with Ed25519).

.DESCRIPTION
    Requires:
    - JDK 21 LTS (jlink and jpackage)
    - Apache Maven 3.9+
    - WiX Toolset v3.x (required only when -PackageType is 'msi', 'exe', or 'all')
#>

param(
    [ValidateSet("portable", "app-image", "msi", "exe", "all")]
    [string]$PackageType = "portable",
    [string]$AppVersion = "",
    [ValidateSet("stable", "beta")]
    [string]$Channel = "stable",
    [string]$ReleaseBaseUrl = "https://github.com/KiwixArc/KillAgent/releases/download",
    [switch]$Mandatory,
    [string]$MinimumSupportedVersion = "1.0.0",
    [string]$ReleaseNotes = "",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
Push-Location $repoRoot

function Resolve-ToolPath {
    param(
        [string]$ToolName,
        [string[]]$CandidateDirs
    )
    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($dir in $CandidateDirs) {
        if ($dir -and (Test-Path (Join-Path $dir $ToolName))) {
            return (Join-Path $dir $ToolName)
        }
    }
    return $null
}

function Invoke-AuthenticodeSignIfConfigured {
    param([string]$TargetPath)
    $pfxPath = $env:WINDOWS_CERT_PFX_PATH
    $pfxB64 = $env:WINDOWS_CERT_PFX_BASE64
    $pfxPass = $env:WINDOWS_CERT_PASSWORD
    $tempPfx = $null

    if (-not $pfxPath -and $pfxB64) {
        $tempPfx = Join-Path $env:TEMP ("killagent-codesign-" + [guid]::NewGuid().ToString("N") + ".pfx")
        [IO.File]::WriteAllBytes($tempPfx, [Convert]::FromBase64String($pfxB64))
        $pfxPath = $tempPfx
    }
    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
        return
    }

    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $signtool) {
        $signtool = (Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    }
    if (-not $signtool) {
        Write-Warning "WINDOWS_CERT_PFX está definido pero no se encontró signtool.exe (x64). Omitiendo firma Authenticode."
        if ($tempPfx -and (Test-Path $tempPfx)) { Remove-Item -Force $tempPfx }
        return
    }

    try {
        Write-Host "  -> Firmando Authenticode SHA-256: $TargetPath" -ForegroundColor DarkCyan
        $signArgs = @("sign", "/fd", "SHA256", "/f", $pfxPath, "/tr", "http://timestamp.digicert.com", "/td", "SHA256")
        if ($pfxPass) { $signArgs += @("/p", $pfxPass) }
        $signArgs += $TargetPath
        & $signtool @signArgs
        if ($LASTEXITCODE -ne 0) { throw "signtool.exe falló para $TargetPath" }
    } finally {
        if ($tempPfx -and (Test-Path $tempPfx)) { Remove-Item -Force $tempPfx }
    }
}

try {
    [xml]$pomXml = Get-Content (Join-Path $repoRoot "pom.xml")
    $pomVersion = $pomXml.project.version.Trim()
    if (-not $AppVersion) {
        $AppVersion = $pomVersion
    }
    $numericVersion = ($AppVersion -split '-')[0]

    $jdkCandidates = @()
    if ($env:JAVA_HOME) { $jdkCandidates += (Join-Path $env:JAVA_HOME "bin") }
    $jdkCandidates += (Get-ChildItem "C:\Program Files\Java\jdk-21*\bin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $jdkCandidates += (Get-ChildItem "C:\Program Files\Eclipse Adoptium\jdk-21*\bin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

    $javaExe = Resolve-ToolPath -ToolName "java.exe" -CandidateDirs $jdkCandidates
    $jlinkExe = Resolve-ToolPath -ToolName "jlink.exe" -CandidateDirs $jdkCandidates
    $jpackageExe = Resolve-ToolPath -ToolName "jpackage.exe" -CandidateDirs $jdkCandidates
    if (-not $javaExe -or -not $jlinkExe -or -not $jpackageExe) {
        throw "No se encontraron java.exe, jlink.exe o jpackage.exe de JDK 21."
    }

    $wixDirs = @(
        "C:\Program Files (x86)\WiX Toolset v3.14\bin",
        "C:\Program Files (x86)\WiX Toolset v3.11\bin",
        "C:\WiXToolset\bin"
    )
    $candleExe = Resolve-ToolPath -ToolName "candle.exe" -CandidateDirs $wixDirs
    if ($candleExe) {
        $wixBin = Split-Path $candleExe -Parent
        if ($env:Path -notlike "*$wixBin*") {
            $env:Path = "$wixBin;$env:Path"
        }
    }

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " Building KILLAgent Windows Distribution ($PackageType) v$AppVersion" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan

    # 1. Maven build & package
    Write-Host "`n[1/5] Compilando y empaquetando Fat JAR..." -ForegroundColor Yellow
    if ($SkipTests) {
        mvn -B clean package -DskipTests
    } else {
        mvn -B clean package
    }
    if ($LASTEXITCODE -ne 0) { throw "mvn clean package falló." }

    $shadedJar = Get-Item (Join-Path $repoRoot "target\killagent-*.jar") | Where-Object { $_.Name -notlike "original-*" } | Select-Object -First 1
    if (-not $shadedJar) {
        throw "No se encontró el Fat JAR compilado en target\killagent-*.jar"
    }

    # 2. Clean staging directories
    $stageDir = Join-Path $repoRoot "target\jpackage-input"
    $runtimeDir = Join-Path $repoRoot "target\custom-jre"
    $outDir = Join-Path $repoRoot "dist"

    foreach ($dir in @($stageDir, $runtimeDir, $outDir)) {
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    }
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    New-Item -ItemType Directory -Path $outDir | Out-Null
    Copy-Item -Path $shadedJar.FullName -Destination (Join-Path $stageDir "killagent.jar")

    $distJarName = "killagent-$AppVersion.jar"
    $distJarPath = Join-Path $outDir $distJarName
    Copy-Item -Path $shadedJar.FullName -Destination $distJarPath

    # 3. Build stripped custom JRE via jlink
    Write-Host "`n[2/5] Generando runtime Java 21 minimo via jlink..." -ForegroundColor Yellow
    $requiredModules = @(
        "java.base",
        "java.desktop",
        "java.logging",
        "java.management",
        "java.naming",
        "java.net.http",
        "java.prefs",
        "java.smartcardio",
        "java.sql",
        "jdk.crypto.cryptoki",
        "jdk.crypto.ec",
        "jdk.unsupported"
    ) -join ","

    & $jlinkExe `
        --add-modules $requiredModules `
        --strip-debug `
        --no-man-pages `
        --no-header-files `
        --compress=zip-6 `
        --output $runtimeDir
    if ($LASTEXITCODE -ne 0) { throw "jlink falló con código $LASTEXITCODE" }

    $iconPath = Join-Path $repoRoot "src\main\resources\assets\icons\app-icon.ico"
    $baseJpackageArgs = @(
        "--dest", $outDir,
        "--name", "KILLAgent",
        "--app-version", $numericVersion,
        "--vendor", "Ch'aska Zero Trust Platform",
        "--copyright", "Copyright (c) 2026 Ch'aska Platform",
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
    if (Test-Path $iconPath) {
        $baseJpackageArgs += @("--icon", $iconPath)
    }

    # 4. Build requested packages
    Write-Host "`n[3/5] Generando paquetes nativos Windows vía jpackage..." -ForegroundColor Yellow
    $manifestArtifacts = [ordered]@{}

    if ($PackageType -in @("app-image", "portable", "all")) {
        $appImageArgs = @("--type", "app-image") + $baseJpackageArgs
        & $jpackageExe @appImageArgs
        if ($LASTEXITCODE -ne 0) { throw "jpackage app-image falló." }

        $appExe = Join-Path $outDir "KILLAgent\KILLAgent.exe"
        Invoke-AuthenticodeSignIfConfigured -TargetPath $appExe

        if ($PackageType -in @("portable", "all")) {
            $zipName = "KILLAgent-$AppVersion-windows-x64-portable.zip"
            $zipPath = Join-Path $outDir $zipName
            Compress-Archive -Path (Join-Path $outDir "KILLAgent") -DestinationPath $zipPath -Force

            $zipHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $zipSize = (Get-Item $zipPath).Length
            $manifestArtifacts["windows-x64-zip"] = [ordered]@{
                fileName  = $zipName
                url       = "$($ReleaseBaseUrl.TrimEnd('/'))/v$AppVersion/$zipName"
                sha256    = $zipHash
                sizeBytes = $zipSize
            }
        }
    }

    if ($PackageType -in @("msi", "exe", "all")) {
        if (-not $candleExe) {
            throw "WiX Toolset v3 (candle.exe / light.exe) no está instalado. Requerido para generar paquetes '$PackageType'."
        }
        $installerTypes = if ($PackageType -eq "all") { @("msi") } else { @($PackageType) }
        foreach ($instType in $installerTypes) {
            $installerArgs = @("--type", $instType) + $baseJpackageArgs + @(
                "--win-dir-chooser",
                "--win-menu",
                "--win-menu-group", "Ch'aska",
                "--win-shortcut",
                "--win-per-user-install",
                "--win-upgrade-uuid", "8f7e4d21-6c3b-4a92-9b1e-3d5a7c8f1042"
            )
            & $jpackageExe @installerArgs
            if ($LASTEXITCODE -ne 0) { throw "jpackage $instType falló." }

            $producedInstaller = Get-ChildItem (Join-Path $outDir "*.$instType") | Select-Object -First 1
            if ($producedInstaller) {
                $targetInstallerName = "KILLAgent-$AppVersion.$instType"
                $targetInstallerPath = Join-Path $outDir $targetInstallerName
                if ($producedInstaller.FullName -ne $targetInstallerPath) {
                    Move-Item -Force $producedInstaller.FullName $targetInstallerPath
                }
                Invoke-AuthenticodeSignIfConfigured -TargetPath $targetInstallerPath

                $instHash = (Get-FileHash -Path $targetInstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $instSize = (Get-Item $targetInstallerPath).Length
                $artifactKey = if ($instType -eq "msi") { "windows-x64-msi" } else { "windows-x64-exe" }
                $manifestArtifacts[$artifactKey] = [ordered]@{
                    fileName  = $targetInstallerName
                    url       = "$($ReleaseBaseUrl.TrimEnd('/'))/v$AppVersion/$targetInstallerName"
                    sha256    = $instHash
                    sizeBytes = $instSize
                }
            }
        }
    }

    $jarHash = (Get-FileHash -Path $distJarPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $jarSize = (Get-Item $distJarPath).Length
    $manifestArtifacts["universal-jar"] = [ordered]@{
        fileName  = $distJarName
        url       = "$($ReleaseBaseUrl.TrimEnd('/'))/v$AppVersion/$distJarName"
        sha256    = $jarHash
        sizeBytes = $jarSize
    }

    # 5. Generate SHA256SUMS.txt & update-manifest.json
    Write-Host "`n[4/5] Generando SHA256SUMS.txt y update-manifest.json..." -ForegroundColor Yellow
    $checksumLines = @()
    Get-ChildItem $outDir -File | Sort-Object Name | ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $checksumLines += "$hash  $($_.Name)"
    }
    Set-Content -Path (Join-Path $outDir "SHA256SUMS.txt") -Value $checksumLines -Encoding UTF8

    $effectiveNotes = if ($ReleaseNotes -and $ReleaseNotes.Trim()) {
        $ReleaseNotes.Trim()
    } else {
        "KILLAgent v$AppVersion ($Channel) - Ancla de hardware Zero Trust, soporte PKCS#11 DNIe y actualizaciones verificadas."
    }

    $manifestObj = [ordered]@{
        schemaVersion           = 1
        product                 = "KILLAgent"
        channel                 = $Channel
        version                 = $AppVersion
        releaseDate             = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        mandatory               = [bool]$Mandatory
        minimumSupportedVersion = $MinimumSupportedVersion
        releaseNotes            = $effectiveNotes
        releaseNotesUrl         = "https://github.com/KiwixArc/KillAgent/releases/tag/v$AppVersion"
        artifacts               = $manifestArtifacts
        signature               = ""
    }

    $manifestPath = Join-Path $outDir "update-manifest.json"
    $manifestJson = $manifestObj | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($manifestPath, $manifestJson + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    if ($env:UPDATE_SIGNING_PRIVATE_KEY -and $env:UPDATE_SIGNING_PRIVATE_KEY.Trim()) {
        Write-Host "  -> Firmando update-manifest.json con clave Ed25519..." -ForegroundColor Cyan
        & $javaExe (Join-Path $repoRoot "scripts\ManifestSigner.java") sign $manifestPath $env:UPDATE_SIGNING_PRIVATE_KEY.Trim()
        if ($LASTEXITCODE -ne 0) { throw "Firma Ed25519 del manifiesto falló." }
    } else {
        Write-Warning "UPDATE_SIGNING_PRIVATE_KEY no definida: update-manifest.json generado sin firma Ed25519 (solo SHA-256)."
    }

    Write-Host "`n[5/5] Distribución generada exitosamente en '$outDir\':" -ForegroundColor Green
    Get-ChildItem $outDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} finally {
    Pop-Location
}
