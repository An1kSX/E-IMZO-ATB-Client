$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name "eimzo-atb-client" `
  --paths "src" `
  --collect-all "aiohttp" `
  --collect-all "websockets" `
  --collect-all "cryptography" `
  --collect-all "winloop" `
  --workpath "build/pyinstaller" `
  --distpath "dist" `
  "src/client/__main__.py"
