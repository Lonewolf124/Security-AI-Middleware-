@echo off
REM ===================================================================
REM  Start the Hide-and-Seek DLP proxy on this machine only (no VM).
REM
REM  Listens on loopback, so only a browser on this computer can use it.
REM  Point the browser's HTTP and HTTPS proxy at 127.0.0.1:8888 and trust
REM  the mitmproxy CA (%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer).
REM
REM  Must run with this directory as the working directory: mitm_has.py,
REM  mitm_dlp.py, dlp_engine and hide_seek are imported relative to it.
REM ===================================================================

setlocal

set LISTEN_HOST=127.0.0.1
set LISTEN_PORT=8888

cd /d "%~dp0"

echo ===================================================================
echo  Hide-and-Seek DLP Proxy (local)
echo ===================================================================
echo  Project dir : %CD%
echo  Listening   : %LISTEN_HOST%:%LISTEN_PORT%
echo ===================================================================
echo.

if not exist "mitm_has.py" (
    echo [ERROR] mitm_has.py not found in %CD%
    pause
    exit /b 1
)

if not exist "onnx_quantized_all17\model_quantized.onnx" (
    echo [ERROR] model_quantized.onnx not found.
    echo         Expected: %CD%\onnx_quantized_all17\model_quantized.onnx
    pause
    exit /b 1
)

mitmdump --listen-host %LISTEN_HOST% --listen-port %LISTEN_PORT% --set connection_strategy=lazy -s "%~dp0mitm_has.py"

endlocal
