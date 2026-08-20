@echo off
REM Athena Penetration Testing Framework - Run Script
REM Usage: run.bat <target> [mode]
REM Modes: 1=Full Test, 2=Discovery Only, 3=Vulnerability Scan

echo Starting Athena Penetration Testing Framework...
.venv\Scripts\python.exe athena.py %1 %2
