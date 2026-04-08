$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$tag = git describe --tags --exact-match HEAD 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tag)) {
  throw "Current commit does not have an exact git tag. Create a tag like v1.0.10 and rerun the build."
}

$version = $tag.Trim()
if ($version.StartsWith("v") -or $version.StartsWith("V")) {
  $version = $version.Substring(1)
}

if ($version -notmatch '^[0-9]+(\.[0-9]+)*([-.][0-9A-Za-z]+)*$') {
  throw "Git tag '$tag' does not map to a valid application version."
}

$versionFilePath = Join-Path $projectRoot "src/client/_build_version.py"
@(
  '"""Generated during build from the current git tag."""',
  '',
  "__version__ = ""$version"""
) | Set-Content -LiteralPath $versionFilePath -Encoding utf8

Write-Host "Building E-IMZO ATB Client version $version from git tag $tag"

$pyInstallerArgs = @(
  "-m", "PyInstaller",
  "--noconfirm",
  "--clean",
  "--workpath", "build/pyinstaller",
  "--distpath", "dist",
  "eimzo-atb-client.spec"
)

python @pyInstallerArgs
