@echo off
rem Build + test FCP on Windows (MSVC + Ninja). Usage: build.bat [Debug|Release]
setlocal
rem cmake --preset only looks for CMakePresets.json in the current directory;
rem a double-click, a scheduled task or a CI step can start anywhere (C-07).
pushd "%~dp0" >nul

rem --- vcpkg (manifest mode) -----------------------------------------------
rem CMakePresets.json resolves the toolchain through $env{VCPKG_ROOT}, so the
rem variable has to exist before `cmake --preset`. One-time setup:
rem   git clone https://github.com/microsoft/vcpkg.git D:\vcpkg
rem   D:\vcpkg\bootstrap-vcpkg.bat
rem   setx VCPKG_ROOT D:\vcpkg        (reopen the terminal afterwards)
if not defined VCPKG_ROOT (
  echo [fcp] VCPKG_ROOT is not set; see the deployment guide, section 1.
  popd
  exit /b 1
)
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
  echo [fcp] VCPKG_ROOT="%VCPKG_ROOT%" is not a vcpkg checkout.
  popd
  exit /b 1
)
if not exist "%VCPKG_ROOT%\vcpkg.exe" (
  echo [fcp] vcpkg is not bootstrapped; run "%VCPKG_ROOT%\bootstrap-vcpkg.bat".
  popd
  exit /b 1
)
rem vcvars64.bat exports VCPKG_ROOT pointing at Visual Studio's bundled vcpkg.
rem Keep the checkout the user (or CI) pinned; restore it after vcvars runs.
set "FCP_VCPKG_ROOT=%VCPKG_ROOT%"

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug
set "CFG_PRESET=debug"
if /I "%CONFIG%"=="Release" set "CFG_PRESET=release"

rem --- locate Visual Studio (vswhere is installed with every VS 2017+ product) ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [fcp] vswhere.exe not found at "%VSWHERE%"
  exit /b 1
)

set "VSDIR="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [fcp] no Visual Studio installation with the MSVC x64 toolset found
  exit /b 1
)

echo [fcp] Visual Studio: %VSDIR%
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo [fcp] vcvars64.bat failed
  exit /b 1
)
set "VCPKG_ROOT=%FCP_VCPKG_ROOT%"

rem Prefer the CMake + Ninja that ship with VS, so the build works without a separate install.
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\VC\Tools\Llvm\x64\bin;%PATH%"

rem --- Windows SDK fallback (same rationale as kcp-cpp: restricted shells break reg.exe lookup) ---
echo "%LIB%" | findstr /i /c:"Windows Kits" >nul
if not errorlevel 1 goto :sdk_ready

set "SDKROOT=%ProgramFiles(x86)%\Windows Kits\10"
set "SDKVER="
for /f "delims=" %%d in ('dir /b /ad /o-n "%SDKROOT%\bin\10.*" 2^>nul') do (
  if not defined SDKVER if exist "%SDKROOT%\Lib\%%d\um\x64\kernel32.lib" set "SDKVER=%%d"
)
if not defined SDKVER (
  echo [fcp] Windows SDK with x64 libs not found under "%SDKROOT%"
  exit /b 1
)
echo [fcp] Windows SDK fallback: %SDKVER%
set "SDKINC=%SDKROOT%\Include\%SDKVER%"
set "SDKLIB=%SDKROOT%\Lib\%SDKVER%"
set "INCLUDE=%SDKINC%\ucrt;%SDKINC%\um;%SDKINC%\shared;%SDKINC%\winrt;%INCLUDE%"
set "LIB=%SDKLIB%\ucrt\x64;%SDKLIB%\um\x64;%LIB%"
set "PATH=%SDKROOT%\bin\%SDKVER%\x64;%PATH%"

:sdk_ready
echo [fcp] configure
cmake --preset windows-x64 || goto :error

echo [fcp] build (%CONFIG%)
cmake --build --preset windows-x64-%CFG_PRESET% || goto :error

echo [fcp] ctest (%CONFIG%)
ctest --preset windows-x64-%CFG_PRESET% || goto :error

echo [fcp] OK
popd
exit /b 0

:error
set "RC=%errorlevel%"
popd
echo [fcp] FAILED with error %RC%
exit /b %RC%
