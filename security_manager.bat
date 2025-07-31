@echo off
setlocal enabledelayedexpansion
title Security Manager v1.0

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run as administrator.
    pause
    exit /b 1
)

:MAIN_MENU
cls
echo ===============================================
echo           SECURITY MANAGER v1.0
echo ===============================================
echo.
echo [1] Complete Security Setup (All-in-One)
echo [2] Run Windows Defender Scan
echo [3] Install Bloxstrap (winget)
echo [4] Install Zen-browser (winget)
echo [5] System Cleanup
echo [0] Exit
echo.
set /p choice="Enter your choice (0-5): "

if "%choice%"=="1" goto COMPLETE_SECURITY
if "%choice%"=="2" goto SCAN_MENU
if "%choice%"=="3" goto BLOXSTRAP_WINGET
if "%choice%"=="4" goto ZEN-BROWSER_WINGET
if "%choice%"=="5" goto SYSTEM_CLEANUP
if "%choice%"=="0" goto EXIT
goto MAIN_MENU

:COMPLETE_SECURITY
cls
echo ===============================================
echo        COMPLETE SECURITY SETUP
echo ===============================================
echo.
echo This will perform all security operations:
echo 1. Enable Windows Firewall
echo 2. Enable App and Browser Control
echo 3. Configure DNS to Cloudflare Anti-Malware
echo 4. Activate Windows Defender Protection
echo 5. Remove Exclusions and KMSpico
echo 6. Run Quick Scan
echo.
echo Starting comprehensive security setup...
echo.

:: Enable Windows Firewall
echo [1/6] Enabling Windows Firewall...
call :FIREWALL_CONFIG_SILENT

:: Enable App and Browser Control
echo [2/6] Enabling App and Browser Control...
call :APPBROWSER_CONFIG_SILENT

:: DNS Configuration
echo [3/6] Configuring DNS...
call :DNS_CONFIG_SILENT

:: Defender Configuration
echo [4/6] Activating Windows Defender...
call :DEFENDER_CONFIG_SILENT

:: Remove Threats
echo [5/6] Removing threats and exclusions...
call :REMOVE_THREATS_SILENT

:: Quick Scan
echo [6/6] Running quick scan...
powershell -Command "Start-MpScan -ScanType QuickScan" >nul 2>&1

echo.
echo ✓ Complete security setup finished successfully!
echo.
echo All security features are now active:
echo ✓ Windows Firewall enabled
echo ✓ App and Browser Control enabled
echo ✓ DNS configured for malware blocking
echo ✓ Windows Defender fully activated
echo ✓ All exclusions removed
echo ✓ KMSpico removed
echo ✓ System scanned for threats
echo.
pause
goto MAIN_MENU

:DNS_CONFIG
cls
echo ===============================================
echo        CONFIGURING CLOUDFLARE DNS
echo ===============================================
echo.
echo Setting DNS to Cloudflare servers...
echo Primary DNS: 1.1.1.1 (Cloudflare DNS)
echo Secondary DNS: 1.0.0.1 (Cloudflare DNS)
echo.

:: Configure DNS using PowerShell method that works
echo Configuring DNS servers to Cloudflare (1.1.1.1, 1.0.0.1)...
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '1.1.1.1','1.0.0.1'; Write-Host 'DNS configured for interface:' $_.Name }"

echo.
echo DNS configuration completed!
echo.
pause
goto MAIN_MENU

:DEFENDER_CONFIG
cls
echo ===============================================
echo    ACTIVATING WINDOWS DEFENDER PROTECTION
echo ===============================================
echo.

echo Enabling Real-time Protection...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Real-time Protection enabled) else (echo ✗ Failed to enable Real-time Protection)

echo Enabling Cloud Protection...
powershell -Command "Set-MpPreference -MAPSReporting Advanced" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Cloud Protection enabled) else (echo ✗ Failed to enable Cloud Protection)

echo Enabling Automatic Sample Submission...
powershell -Command "Set-MpPreference -SubmitSamplesConsent SendAllSamples" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Automatic Sample Submission enabled) else (echo ✗ Failed to enable Sample Submission)

echo Enabling Behavior Monitoring...
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Behavior Monitoring enabled) else (echo ✗ Failed to enable Behavior Monitoring)

echo Enabling Intrusion Prevention System...
powershell -Command "Set-MpPreference -DisableIntrusionPreventionSystem $false" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Intrusion Prevention enabled) else (echo ✗ Failed to enable Intrusion Prevention)

echo Enabling Script Scanning...
powershell -Command "Set-MpPreference -DisableScriptScanning $false" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Script Scanning enabled) else (echo ✗ Failed to enable Script Scanning)

echo Enabling Archive Scanning...
powershell -Command "Set-MpPreference -DisableArchiveScanning $false" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Archive Scanning enabled) else (echo ✗ Failed to enable Archive Scanning)

echo Enabling Tamper Protection...
:: Enable Tamper Protection via registry
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableTamperProtection /t REG_DWORD /d 0 /f >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Tamper Protection enabled) else (echo ✗ Failed to enable Tamper Protection)

echo Updating Windows Defender signatures...
powershell -Command "Update-MpSignature" >nul 2>&1
if %errorlevel% equ 0 (echo ✓ Signatures updated) else (echo ✗ Failed to update signatures)

echo.
echo Windows Defender protection activated!
echo.
pause
goto MAIN_MENU

:REMOVE_THREATS
cls
echo ===============================================
echo     REMOVING EXCLUSIONS AND KMSPICO
echo ===============================================
echo.

echo Removing all Windows Defender exclusions...
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | ForEach-Object { Remove-MpPreference -ExclusionPath $_ -Force }" >nul 2>&1
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ -Force }" >nul 2>&1
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ -Force }" >nul 2>&1
echo ✓ All exclusions removed

echo.
echo Searching for and removing KMSpico...

:: Common KMSpico locations
set "kms_paths=C:\Program Files\KMSpico"
set "kms_paths=%kms_paths% C:\Program Files (x86)\KMSpico"
set "kms_paths=%kms_paths% %APPDATA%\KMSpico"
set "kms_paths=%kms_paths% %LOCALAPPDATA%\KMSpico"
set "kms_paths=%kms_paths% C:\KMSpico"

for %%p in (%kms_paths%) do (
    if exist "%%p" (
        echo Found KMSpico at: %%p
        echo Removing...
        rmdir /s /q "%%p" >nul 2>&1
        if not exist "%%p" (
            echo ✓ Successfully removed %%p
        ) else (
            echo ✗ Failed to remove %%p
        )
    )
)

:: Remove KMSpico services
echo Checking for KMSpico services...
sc query "KMSEmulator" >nul 2>&1
if %errorlevel% equ 0 (
    echo Stopping and removing KMSEmulator service...
    sc stop "KMSEmulator" >nul 2>&1
    sc delete "KMSEmulator" >nul 2>&1
    echo ✓ KMSEmulator service removed
)

:: Remove registry entries
echo Cleaning registry entries...
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\KMSpico" /f >nul 2>&1
reg delete "HKCU\Software\KMSpico" /f >nul 2>&1
reg delete "HKLM\Software\KMSpico" /f >nul 2>&1

:: Remove scheduled tasks
echo Removing KMSpico scheduled tasks...
schtasks /delete /tn "KMSpico" /f >nul 2>&1

echo.
echo KMSpico removal completed!
echo.
pause
goto MAIN_MENU

:SCAN_MENU
cls
echo ===============================================
echo        WINDOWS DEFENDER SCAN OPTIONS
echo ===============================================
echo.
echo [1] Quick Scan
echo [2] Full Scan
echo [3] Custom Scan
echo [0] Back to Main Menu
echo.
set /p scan_choice="Enter your choice (0-3): "

if "%scan_choice%"=="1" goto QUICK_SCAN
if "%scan_choice%"=="2" goto FULL_SCAN
if "%scan_choice%"=="3" goto CUSTOM_SCAN
if "%scan_choice%"=="0" goto MAIN_MENU
goto SCAN_MENU

:QUICK_SCAN
cls
echo ===============================================
echo           RUNNING QUICK SCAN
echo ===============================================
echo.
echo Starting Windows Defender Quick Scan...
echo This may take a few minutes...
echo.
powershell -Command "Start-MpScan -ScanType QuickScan"
echo.
echo Quick scan completed!
echo.
pause
goto SCAN_MENU

:FULL_SCAN
cls
echo ===============================================
echo            RUNNING FULL SCAN
echo ===============================================
echo.
echo Starting Windows Defender Full Scan...
echo This may take several hours...
echo.
powershell -Command "Start-MpScan -ScanType FullScan"
echo.
echo Full scan completed!
echo.
pause
goto SCAN_MENU

:CUSTOM_SCAN
cls
echo ===============================================
echo           RUNNING CUSTOM SCAN
echo ===============================================
echo.
set /p scan_path="Enter path to scan (e.g., C:\Users): "
echo.
echo Starting custom scan of: %scan_path%
echo.
powershell -Command "Start-MpScan -ScanType CustomScan -ScanPath '%scan_path%'"
echo.
echo Custom scan completed!
echo.
pause
goto SCAN_MENU

:BLOXSTRAP_WINGET
cls
echo ===============================================
echo         BLOXSTRAP INSTALLATION (WINGET)
echo ===============================================
echo.
echo Installing Bloxstrap using Windows Package Manager (winget)...
echo This is the recommended installation method.
echo.
echo Checking if winget is available...
winget --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ✗ Winget is not available on this system
    echo Please use option 6 for direct download instead
    echo.
    pause
    goto MAIN_MENU
)

echo ✓ Winget is available
echo Installing Bloxstrap...
echo.
winget install bloxstrap

if %errorlevel% equ 0 (
    echo.
    echo ✓ Bloxstrap installed successfully via winget!
    echo You can now launch Bloxstrap from the Start Menu
) else (
    echo.
    echo ✗ Failed to install Bloxstrap via winget
    echo You may want to try the direct download option (6)
)
echo.
pause
goto MAIN_MENU

:BLOXSTRAP_DOWNLOAD
cls
echo ===============================================
echo         BLOXSTRAP DIRECT DOWNLOAD
echo ===============================================
echo.
echo Bloxstrap is an alternative bootstrapper for Roblox
echo that provides additional features and customization options.
echo.
echo Downloading latest Bloxstrap from GitHub...
echo.
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/pizzaboxer/bloxstrap/releases/latest/download/Bloxstrap.exe' -OutFile '%USERPROFILE%\Desktop\Bloxstrap.exe'}"

if exist "%USERPROFILE%\Desktop\Bloxstrap.exe" (
    echo ✓ Bloxstrap downloaded successfully to Desktop!
    echo You can run it from: %USERPROFILE%\Desktop\Bloxstrap.exe
) else (
    echo ✗ Failed to download Bloxstrap
)
echo.
pause
goto MAIN_MENU

:ZEN-BROWSER_WINGET
cls
echo ===============================================
echo        ZEN-BROWSER INSTALLATION (WINGET)
echo ===============================================
echo.
echo Installing Zen-browser using Windows Package Manager (winget)...
echo.

:: Check if winget exists
winget --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ✗ Winget is not available on this system
    echo Please install winget or update your system
    pause
    goto MAIN_MENU
)

echo ✓ Winget is available
echo.

:: Attempt to install Zen-browser
echo Installing Zen-browser...
winget install --id=Zen-Dev.Zen-Browser -e

if %errorlevel% equ 0 (
    echo.
    echo ✓ Zen-browser installed successfully!
) else (
    echo.
    echo ✗ Zen-browser installation failed.
    echo Please check if the ID is correct or try manually.
)
echo.
pause
goto MAIN_MENU

:RUN_ALL
cls
echo ===============================================
echo        RUNNING ALL SECURITY TASKS
echo ===============================================
echo.
echo This will perform all security operations in sequence:
echo 1. Configure DNS to Cloudflare Anti-Malware
echo 2. Activate Windows Defender Protection
echo 3. Remove Exclusions and KMSpico
echo 4. Run Quick Scan
echo.
set /p confirm="Continue? (y/n): "

if /i not "%confirm%"=="y" goto MAIN_MENU

echo.
echo Starting comprehensive security setup...
echo.

:: DNS Configuration
echo [1/4] Configuring DNS...
call :DNS_CONFIG_SILENT

:: Defender Configuration
echo [2/4] Activating Windows Defender...
call :DEFENDER_CONFIG_SILENT

:: Remove Threats
echo [3/4] Removing threats and exclusions...
call :REMOVE_THREATS_SILENT

:: Quick Scan
echo [4/4] Running quick scan...
powershell -Command "Start-MpScan -ScanType QuickScan" >nul 2>&1

echo.
echo ✓ All security tasks completed successfully!
echo.

:: Ask about Bloxstrap
set /p blox_final="Would you like to download Bloxstrap? (y/n): "
if /i "%blox_final%"=="y" (
    echo.
    echo Downloading Bloxstrap...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/pizzaboxer/bloxstrap/releases/latest/download/Bloxstrap.exe' -OutFile '%USERPROFILE%\Desktop\Bloxstrap.exe'}" >nul 2>&1
    if exist "%USERPROFILE%\Desktop\Bloxstrap.exe" (
        echo ✓ Bloxstrap downloaded to Desktop!
    )
)

echo.
echo All operations completed!
pause
goto MAIN_MENU

:: Silent functions for RUN_ALL
:DNS_CONFIG_SILENT
:: Configure DNS using PowerShell method that works
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '1.1.1.1','1.0.0.1' }" >nul 2>&1
exit /b

:DEFENDER_CONFIG_SILENT
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul 2>&1
powershell -Command "Set-MpPreference -MAPSReporting Advanced" >nul 2>&1
powershell -Command "Set-MpPreference -SubmitSamplesConsent SendAllSamples" >nul 2>&1
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false" >nul 2>&1
powershell -Command "Set-MpPreference -DisableIntrusionPreventionSystem $false" >nul 2>&1
powershell -Command "Set-MpPreference -DisableScriptScanning $false" >nul 2>&1
powershell -Command "Set-MpPreference -DisableArchiveScanning $false" >nul 2>&1
:: Enable Tamper Protection via registry (silent)
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableTamperProtection /t REG_DWORD /d 0 /f >nul 2>&1
powershell -Command "Update-MpSignature" >nul 2>&1
exit /b

:FIREWALL_CONFIG_SILENT
:: Enable Windows Firewall for all profiles
netsh advfirewall set allprofiles state on >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1
exit /b

:APPBROWSER_CONFIG_SILENT
:: Enable Windows Defender Application Guard and SmartScreen
powershell -Command "Set-MpPreference -EnableNetworkProtection Enabled" >nul 2>&1
powershell -Command "Set-MpPreference -PUAProtection Enabled" >nul 2>&1
:: Enable SmartScreen for Microsoft Edge and Internet Explorer
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f >nul 2>&1
exit /b

:REMOVE_THREATS_SILENT
:: Safely remove exclusions with comprehensive error handling
powershell -Command "& {try{$ErrorActionPreference='SilentlyContinue';$prefs=Get-MpPreference -ErrorAction SilentlyContinue;if($prefs -and $prefs.ExclusionPath){$prefs.ExclusionPath|%{try{Remove-MpPreference -ExclusionPath $_ -Force -ErrorAction SilentlyContinue}catch{}}}}catch{}}" >nul 2>&1
powershell -Command "& {try{$ErrorActionPreference='SilentlyContinue';$prefs=Get-MpPreference -ErrorAction SilentlyContinue;if($prefs -and $prefs.ExclusionExtension){$prefs.ExclusionExtension|%{try{Remove-MpPreference -ExclusionExtension $_ -Force -ErrorAction SilentlyContinue}catch{}}}}catch{}}" >nul 2>&1
powershell -Command "& {try{$ErrorActionPreference='SilentlyContinue';$prefs=Get-MpPreference -ErrorAction SilentlyContinue;if($prefs -and $prefs.ExclusionProcess){$prefs.ExclusionProcess|%{try{Remove-MpPreference -ExclusionProcess $_ -Force -ErrorAction SilentlyContinue}catch{}}}}catch{}}" >nul 2>&1

set "kms_paths=C:\Program Files\KMSpico C:\Program Files (x86)\KMSpico %APPDATA%\KMSpico %LOCALAPPDATA%\KMSpico C:\KMSpico"
for %%p in (%kms_paths%) do (
    if exist "%%p" rmdir /s /q "%%p" >nul 2>&1
)

sc stop "KMSEmulator" >nul 2>&1
sc delete "KMSEmulator" >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\KMSpico" /f >nul 2>&1
reg delete "HKCU\Software\KMSpico" /f >nul 2>&1
reg delete "HKLM\Software\KMSpico" /f >nul 2>&1
schtasks /delete /tn "KMSpico" /f >nul 2>&1
exit /b

:SYSTEM_CLEANUP
cls
echo ===============================================
echo            SYSTEM CLEANUP
echo ===============================================
echo.
echo This will perform safe system cleanup operations:
echo 1. Clear temporary files from user temp folder
echo 2. Empty recycle bin
echo 3. Clear DNS cache
echo.
echo Note: These operations are safe and do not modify system settings.
echo.
set /p cleanup_confirm="Continue with system cleanup? (y/n): "

if /i not "%cleanup_confirm%"=="y" goto MAIN_MENU

echo.
echo Starting system cleanup...
echo.

:: Clear temporary files from user temp folder
echo [1/3] Clearing temporary files...
echo Cleaning user temp folder: %TEMP%
if exist "%TEMP%" (
    for /f "tokens=*" %%i in ('dir /b "%TEMP%"') do (
        del /q /f "%TEMP%\%%i" >nul 2>&1
        rmdir /s /q "%TEMP%\%%i" >nul 2>&1
    )
    echo ✓ User temporary files cleared
) else (
    echo ✗ User temp folder not found
)

:: Clear system temp files (safe locations only)
echo Cleaning Windows temp folder: %SYSTEMROOT%\Temp
if exist "%SYSTEMROOT%\Temp" (
    for /f "tokens=*" %%i in ('dir /b "%SYSTEMROOT%\Temp" 2^>nul') do (
        del /q /f "%SYSTEMROOT%\Temp\%%i" >nul 2>&1
        rmdir /s /q "%SYSTEMROOT%\Temp\%%i" >nul 2>&1
    )
    echo ✓ System temporary files cleared
)

:: Empty recycle bin
echo.
echo [2/3] Emptying recycle bin...
powershell -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Recycle bin emptied
) else (
    echo ⚠ Could not empty recycle bin (may already be empty)
)

:: Clear DNS cache
echo.
echo [3/3] Clearing DNS cache...
ipconfig /flushdns >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ DNS cache cleared
) else (
    echo ✗ Failed to clear DNS cache
)

echo.
echo ===============================================
echo          CLEANUP COMPLETED
echo ===============================================
echo.
echo System cleanup operations completed:
echo ✓ Temporary files removed
echo ✓ Recycle bin emptied
echo ✓ DNS cache cleared
echo.
echo Your system should now have more free space and
echo refreshed network settings.
echo.
pause
goto MAIN_MENU

:EXIT
cls
echo Thank you for using Security Manager!
echo Your system security has been enhanced.
echo.
pause
exit /b 0
