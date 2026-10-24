@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-OnecToolkit.ps1" -Root "%~dp0.." %*
