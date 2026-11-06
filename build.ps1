# 打包运维换机助手为单文件 exe（自带 UAC 管理员清单）
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

python -m pip install -r requirements.txt
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --uac-admin `
  --name "运维换机助手" `
  app.py

Write-Host ""
Write-Host "完成: $PSScriptRoot\dist\运维换机助手.exe"
