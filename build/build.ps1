$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$pyInstallerArgs = @(
  "-m", "PyInstaller",
  "--noconfirm",
  "--clean",
  "--onefile",
  "--windowed",
  "--name", "eimzo-atb-client",
  "--paths", "src",
  "--collect-all", "aiohttp",
  "--collect-all", "websockets",
  "--collect-all", "cryptography",
  "--collect-all", "winloop",
  "--workpath", "build/pyinstaller",
  "--distpath", "dist"
)

$iconPath = Join-Path $projectRoot "icon.ico"
if (Test-Path $iconPath) {
  $pyInstallerArgs += @("--icon", $iconPath)
}

$pyInstallerArgs += "src/client/__main__.py"

python @pyInstallerArgs
