@echo off
rem Build the FCP Qt client (apps/fcp-client) with MSVC + Ninja + vcpkg Qt.
rem Usage: build_app.bat [Debug|Release]
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release
set "CFG_PRESET=release"
if /I "%CONFIG%"=="Debug" set "CFG_PRESET=debug"

rem --- locate Visual Studio (same logic as build.bat) ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [fcp-app] vswhere.exe not found at "%VSWHERE%"
  exit /b 1
)
set "VSDIR="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [fcp-app] no Visual Studio installation with the MSVC x64 toolset found
  exit /b 1
)
echo [fcp-app] Visual Studio: %VSDIR%
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo [fcp-app] vcvars64.bat failed
  exit /b 1
)
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"

rem --- vcpkg: prefer a vcpkg that actually has Qt installed ---
rem A Visual Studio installation exports its own VCPKG_ROOT, which has no Qt;
rem switch to the local checkout when that one carries qt6. vcpkg's qtbase
rem installs the config tree as share\Qt6 (capital Q), so check that spelling.
if not defined VCPKG_ROOT set "VCPKG_ROOT=D:\work\vcpkg"
if not exist "%VCPKG_ROOT%\installed\x64-windows\share\Qt6" if exist "D:\work\vcpkg\installed\x64-windows\share\Qt6" set "VCPKG_ROOT=D:\work\vcpkg"
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
  echo [fcp-app] vcpkg not found: set VCPKG_ROOT to your vcpkg checkout
  exit /b 1
)
echo [fcp-app] vcpkg: %VCPKG_ROOT%

echo [fcp-app] configure
cmake --preset windows-x64-app || goto :error

echo [fcp-app] build (%CONFIG%)
cmake --build --preset windows-x64-app-%CFG_PRESET% --target fcp_client || goto :error

set "EXEDIR=%CD%\build\windows-x64-app\apps\fcp-client\%CONFIG%"
if not exist "%EXEDIR%\fcp_client.exe" (
  echo [fcp-app] fcp_client.exe not found in "%EXEDIR%"
  exit /b 1
)

echo [fcp-app] deploy Qt runtime
if /I "%CONFIG%"=="Debug" (
  set "DEPLOY=%VCPKG_ROOT%\installed\x64-windows\tools\Qt6\bin\windeployqt.debug.bat"
) else (
  set "DEPLOY=%VCPKG_ROOT%\installed\x64-windows\tools\Qt6\bin\windeployqt.exe"
)
if exist "%DEPLOY%" (
  call "%DEPLOY%" --no-translations "%EXEDIR%\fcp_client.exe" >nul 2>&1
) else (
  echo [fcp-app] windeployqt not found; run with
  echo          set PATH=%%VCPKG_ROOT%%\installed\x64-windows\bin;%%PATH%%
)

echo [fcp-app] OK: %EXEDIR%\fcp_client.exe
exit /b 0

:error
echo [fcp-app] FAILED with error %errorlevel%
exit /b %errorlevel%
