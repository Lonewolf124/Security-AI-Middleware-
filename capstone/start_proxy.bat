@echo off
REM ===================================================================
REM  Start the AI Prompt DLP proxy
REM
REM  Must run with this directory as the working directory, because
REM  mitm_dlp.py does "from dlp_engine.engine import inspect" and
REM  engine.py does "from onnx_quantized_all17.pii_model import PIIModel".
REM  Both are top-level absolute imports resolved against the CWD.
REM
REM  "%~dp0" is this script's own folder, so the project can be moved
REM  to any drive or path without editing this file.
REM ===================================================================

setlocal

set LISTEN_HOST=192.168.56.1
set LISTEN_PORT=8888

cd /d "%~dp0"

echo ===================================================================
echo  AI Prompt DLP Proxy
echo ===================================================================
echo  Project dir : %CD%
echo  Listening   : %LISTEN_HOST%:%LISTEN_PORT%
echo ===================================================================
echo.

if not exist "mitm_dlp.py" (
    echo [ERROR] mitm_dlp.py not found in %CD%
    pause
    exit /b 1
)

if not exist "onnx_quantized_all17\model_quantized.onnx" (
    echo [ERROR] model_quantized.onnx not found.
    echo         Expected: %CD%\onnx_quantized_all17\model_quantized.onnx
    pause
    exit /b 1
)

mitmdump --listen-host %LISTEN_HOST% --listen-port %LISTEN_PORT% --set connection_strategy=lazy -s "%~dp0mitm_dlp.py"

endlocal
