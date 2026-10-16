@echo off
chcp 65001 >nul 2>&1
rem ScopeWeaver Windows supervisor. Arguments are forwarded unchanged.
rem Exit 0 stops; exit 75 applies an update and restarts immediately.
rem Other exits back off from 1 to 60 seconds.
rem The binary handles downloads, SHA-256 checks and atomic replacement.

setlocal enabledelayedexpansion
set "LANG_SEL=%SCOPEWEAVER_LANGUAGE%"
if not defined LANG_SEL set "LANG_SEL=%ARTEX_LANGUAGE%"
cd /d "%~dp0"

set "BIN=scopeweaver.exe"
if not exist "%BIN%" (
	if /i "!LANG_SEL!"=="ko" (echo [ScopeWeaver] 실행 파일을 찾을 수 없습니다: %BIN%) else (echo [ScopeWeaver] Executable not found: %BIN%) 1>&2
	exit /b 1
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	if /i "!LANG_SEL!"=="ko" (echo [ScopeWeaver] 정상 종료) else (echo [ScopeWeaver] Exited normally)
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	if /i "!LANG_SEL!"=="ko" (echo [ScopeWeaver] 다시 시작 요청; 업데이트 적용 중...) else (echo [ScopeWeaver] Restart requested; applying update...)
	set /a delay=1
	goto loop
)

if /i "!LANG_SEL!"=="ko" (echo [ScopeWeaver] 종료 코드 !code!; !delay!초 후 다시 시작) else (echo [ScopeWeaver] Exited with code !code!; restarting in !delay!s) 1>&2
rem Use ping because timeout fails when console input is redirected.
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
