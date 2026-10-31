@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
title HayyanPatcher

rem ===========================================================================
rem  HayyanPatcher launcher.
rem
rem  Pulls the current HayyanPatcher.exe from GitHub, verifies it against the
rem  published sha256, then runs it. No arguments means auto mode: patch the
rem  ExoPanda install, then keep watching for new modules and updates.
rem
rem  Override endpoints before launch if you host your own build:
rem      set PATCH_EXE=https://.../HayyanPatcher.exe
rem      set PATCH_SHA=https://.../HayyanPatcher.sha256
rem ===========================================================================

set "APP=HayyanPatcher"
set "CACHE=%LOCALAPPDATA%\HayyanPatcher"
set "EXE=%CACHE%\%APP%.exe"
set "STAMP=%CACHE%\current.sha256"
set "TMPFILE=%CACHE%\payload.tmp"
set "MINSIZE=1048576"

if not defined PATCH_EXE set "PATCH_EXE=https://github.com/lolcaken/HayyanPatcher/releases/latest/download/%APP%.exe"
if not defined PATCH_EXE_MIRROR set "PATCH_EXE_MIRROR=https://raw.githubusercontent.com/lolcaken/HayyanPatcher/main/%APP%.exe"
if not defined PATCH_SHA set "PATCH_SHA=https://github.com/lolcaken/HayyanPatcher/releases/latest/download/%APP%.sha256"
if not defined PATCH_SHA_MIRROR set "PATCH_SHA_MIRROR=https://raw.githubusercontent.com/lolcaken/HayyanPatcher/main/%APP%.sha256"

if not exist "%CACHE%" mkdir "%CACHE%" >nul 2>&1

rem -- one instance is enough -------------------------------------------------
tasklist /fi "imagename eq %APP%.exe" 2>nul | find /i "%APP%.exe" >nul
if not errorlevel 1 (
    echo   = %APP%.exe is already running - not starting a second copy.
    echo     Close that console window first if you want to restart it.
    timeout /t 3 >nul
    exit /b 0
)

rem -- seed the cache from next to this script --------------------------------
if not exist "%EXE%" if exist "%~dp0%APP%.exe" copy /y "%~dp0%APP%.exe" "%EXE%" >nul 2>&1

echo.
echo   HayyanPatcher
echo   ------------

rem -- published checksum -----------------------------------------------------
set "REMOTE_SHA="
call :download "%PATCH_SHA%" "%TMPFILE%.sha"
if errorlevel 1 call :download "%PATCH_SHA_MIRROR%" "%TMPFILE%.sha"
if not errorlevel 1 (
    for /f "tokens=1 delims= " %%A in ('type "%TMPFILE%.sha"') do if not defined REMOTE_SHA set "REMOTE_SHA=%%A"
)
del /q "%TMPFILE%.sha" >nul 2>&1

set "LOCAL_SHA="
if exist "%EXE%" call :hash "%EXE%" LOCAL_SHA

if defined REMOTE_SHA (
    echo   local  %LOCAL_SHA%
    echo   remote %REMOTE_SHA%
) else (
    echo   local  %LOCAL_SHA%
    echo   remote unavailable - verifying payload directly
)

if defined REMOTE_SHA if /i "%REMOTE_SHA%"=="%LOCAL_SHA%" (
    echo   = up to date
    goto :run
)

rem -- fetch ------------------------------------------------------------------
echo   * fetching build
call :download "%PATCH_EXE%" "%TMPFILE%"
if errorlevel 1 call :download "%PATCH_EXE_MIRROR%" "%TMPFILE%"
if errorlevel 1 goto :offline

set "PAYLOAD_OK="
for %%F in ("%TMPFILE%") do if %%~zF GEQ %MINSIZE% set "PAYLOAD_OK=1"
if not defined PAYLOAD_OK (
    echo   ! payload too small - keeping the cached build
    del /q "%TMPFILE%" >nul 2>&1
    goto :offline
)

if defined REMOTE_SHA (
    set "NEW_SHA="
    call :hash "%TMPFILE%" NEW_SHA
    if /i not "!NEW_SHA!"=="%REMOTE_SHA%" (
        echo   ! checksum mismatch - keeping the cached build
        del /q "%TMPFILE%" >nul 2>&1
        goto :offline
    )
) else (
    set "MAGIC="
    for /f "delims=" %%M in ('powershell -NoProfile -Command "try{$b=[IO.File]::ReadAllBytes('%TMPFILE%'); if($b[0] -eq 77 -and $b[1] -eq 90){'mz'}else{'no'}}catch{'no'}"') do set "MAGIC=%%M"
    if /i not "!MAGIC!"=="mz" (
        echo   ! payload is not a PE executable - keeping the cached build
        del /q "%TMPFILE%" >nul 2>&1
        goto :offline
    )
)

move /y "%TMPFILE%" "%EXE%" >nul 2>&1
if errorlevel 1 (
    echo   ! cannot replace %APP%.exe - it is locked
    del /q "%TMPFILE%" >nul 2>&1
    goto :offline
)

set "LOCAL_SHA="
call :hash "%EXE%" LOCAL_SHA
> "%STAMP%" echo %LOCAL_SHA%
echo   = updated
goto :run

:offline
if exist "%EXE%" (
    echo   ! update skipped - running the cached build
    goto :run
)
echo   x no cached build and the download failed
echo     put %APP%.exe next to this script, or set PATCH_EXE to a reachable URL.
echo.
pause
exit /b 1

:run
echo.
"%EXE%" %*
exit /b %errorlevel%

rem ===========================================================================
:download
rem %1 = url, %2 = destination. exit 0 when a non-empty file landed.
set "URL=%~1"
set "OUT=%~2"
del /q "%OUT%" >nul 2>&1
curl.exe -fsSL --retry 2 --connect-timeout 10 --max-time 180 -o "%OUT%" "%URL%" >nul 2>&1
call :nonempty "%OUT%" && exit /b 0
del /q "%OUT%" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -OutFile '%OUT%' -TimeoutSec 180 } catch { exit 1 }" >nul 2>&1
call :nonempty "%OUT%" && exit /b 0
del /q "%OUT%" >nul 2>&1
exit /b 1

:nonempty
for %%F in ("%~1") do if %%~zF GTR 0 exit /b 0
exit /b 1

:hash
rem %1 = file, %2 = variable to receive the sha256
setlocal EnableDelayedExpansion
set "LINE="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" SHA256 2^>nul') do (
    if not defined LINE set "LINE=%%H"
)
set "LINE=!LINE: =!"
endlocal & set "%~2=%LINE%"
goto :eof
