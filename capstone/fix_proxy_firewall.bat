@echo off
REM ===================================================================
REM  Fix Windows Firewall so the Kali VM can reach mitmproxy on 8888
REM
REM  Problem this fixes:
REM    Windows auto-creates inbound BLOCK rules for python.exe on the
REM    Public profile when you click "Cancel" on the firewall popup.
REM    The VirtualBox Host-Only adapter is an unidentified network, so
REM    it is treated as Public -> inbound 8888 is dropped silently ->
REM    the VM browser shows "connection timed out" and mitmdump prints
REM    no traffic at all.
REM
REM    Explicit Block rules take precedence over Allow rules in Windows
REM    Firewall, so the Block rules must be deleted. Adding the Allow
REM    rule alone is not enough.
REM
REM  This is idempotent - safe to re-run.
REM  MUST be run from an Administrator command prompt.
REM ===================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click cmd.exe -^> "Run as administrator", then re-run.
    pause
    exit /b 1
)

echo.
echo [1/3] Removing inbound BLOCK rules for python.exe ...
powershell -NoProfile -Command "Get-NetFirewallRule -Direction Inbound | Where-Object { $_.Action -eq 'Block' -and (($_ | Get-NetFirewallApplicationFilter).Program -like '*\python*\python.exe') } | Remove-NetFirewallRule -Confirm:$false"
echo       done.

echo.
echo [2/3] Removing any previous DLP proxy allow rule ...
netsh advfirewall firewall delete rule name="MITM DLP Proxy 8888" >nul 2>&1
echo       done.

echo.
echo [3/3] Allowing inbound TCP 8888 from the host-only subnet only ...
netsh advfirewall firewall add rule name="MITM DLP Proxy 8888" dir=in action=allow protocol=TCP localport=8888 remoteip=192.168.56.0/24 profile=any
echo.

echo ===================================================================
echo  Resulting rule:
echo ===================================================================
netsh advfirewall firewall show rule name="MITM DLP Proxy 8888"

echo.
echo Firewall fix applied.
echo.
echo Next: run start_proxy.bat in this folder, then from Kali verify:
echo     nc -vz 192.168.56.1 8888
echo.
pause
