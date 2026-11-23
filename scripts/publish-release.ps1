param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [ValidateSet("stable", "beta")]
    [string]$Channel = "stable",
    [switch]$Mandatory,
    [string]$MinimumSupportedVersion = "1.0.0",
    [string]$ReleaseNotes = "",
    [switch]$Push
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
    throw "Formato SemVer invalido '$Version'. Usa por ejemplo '1.0.1' o '1.1.0-beta.1'."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $branch = (git branch --show-current).Trim()
    if ($branch -ne "main") {
        throw "Debes estar en la rama 'main' para publicar un release (actual: '$branch')."
    }

    $dirty = git status --porcelain
    if ($dirty) {
        throw "El arbol Git tiene cambios sin confirmar. Haz commit o limpia tu espacio de trabajo antes de publicar."
    }

    Write-Host "[1/4] Actualizando version en pom.xml a $Version..." -ForegroundColor Yellow
    mvn -B versions:set "-DnewVersion=$Version" -DgenerateBackupPoms=false
    if ($LASTEXITCODE -ne 0) { throw "mvn versions:set fallo." }

    Write-Host "[2/4] Ejecutando suite de pruebas y empaquetado Maven..." -ForegroundColor Yellow
    mvn -B clean test
    if ($LASTEXITCODE -ne 0) { throw "Las pruebas fallaron; release abortado." }

    Write-Host "[3/4] Creando commit y tag anotado v$Version..." -ForegroundColor Yellow
    git add -- pom.xml
    git commit -m "chore(release): prepare KILLAgent v$Version ($Channel)"
    if ($LASTEXITCODE -ne 0) { throw "git commit fallo." }

    $tagMsg = if ($ReleaseNotes) { $ReleaseNotes } else { "KILLAgent v$Version ($Channel) release" }
    if ($Mandatory) { $tagMsg = "[MANDATORY] $tagMsg" }
    git tag -a "v$Version" -m $tagMsg
    if ($LASTEXITCODE -ne 0) { throw "git tag fallo." }

    Write-Host "[4/4] Release preparado localmente (commit + tag v$Version)." -ForegroundColor Green
    if ($Push) {
        Write-Host "Subiendo rama main y tag v$Version a origin..." -ForegroundColor Cyan
        git push origin main --follow-tags
        if ($LASTEXITCODE -ne 0) { throw "git push fallo." }
        Write-Host "Push completado. GitHub Actions compilara y publicara el Release automaticamente." -ForegroundColor Green
    } else {
        Write-Host "`nEjecuta para publicar en GitHub y disparar el workflow Release:" -ForegroundColor Cyan
        Write-Host "  git push origin main --follow-tags"
    }
} finally {
    Pop-Location
}
