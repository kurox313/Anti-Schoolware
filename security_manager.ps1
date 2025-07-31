# SECURITY MANAGER v1.0 (PowerShell version)

# Ensure script is running as administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges."
    Write-Host "Please run as administrator."
    Pause
    Exit 1
}

Function Show-MainMenu {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "          SECURITY MANAGER v1.0"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "[1] Complete Security Setup (All-in-One)"
    Write-Host "[2] Run Windows Defender Scan"
    Write-Host "[3] Install Fishstrap (winget)"
    Write-Host "[4] Install Zen-browser (winget)"
    Write-Host "[5] System Cleanup"
    Write-Host "[0] Exit"
    Write-Host ""
}

Function Complete-Security {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "       COMPLETE SECURITY SETUP"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "This will perform all security operations:"
    Write-Host "1. Enable Windows Firewall"
    Write-Host "2. Enable App and Browser Control"
    Write-Host "3. Configure DNS to Cloudflare Anti-Malware"
    Write-Host "4. Activate Windows Defender Protection"
    Write-Host "5. Remove Exclusions and KMSpico"
    Write-Host "6. Run Quick Scan"
    Write-Host ""
    Write-Host "Starting comprehensive security setup..."
    Write-Host ""

    # Enable Windows Firewall
    Write-Host "[1/6] Enabling Windows Firewall..."
    netsh advfirewall set allprofiles state on | Out-Null
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null

    # Enable App and Browser Control
    Write-Host "[2/6] Enabling App and Browser Control..."
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -PUAProtection Enabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f | Out-Null

    # DNS Configuration
    Write-Host "[3/6] Configuring DNS..."
    Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '1.1.1.1','1.0.0.1'
    }

    # Defender Configuration
    Write-Host "[4/6] Activating Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableArchiveScanning $false
    reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableTamperProtection /t REG_DWORD /d 0 /f | Out-Null
    Update-MpSignature

    # Remove Threats
    Write-Host "[5/6] Removing threats and exclusions..."
    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | ForEach-Object { Remove-MpPreference -ExclusionPath $_ -Force }
    Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ -Force }
    Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ -Force }
    $kmsPaths = @(
        "C:\Program Files\KMSpico",
        "C:\Program Files (x86)\KMSpico",
        "$env:APPDATA\KMSpico",
        "$env:LOCALAPPDATA\KMSpico",
        "C:\KMSpico"
    )
    foreach ($path in $kmsPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Removed $path"
        }
    }
    sc stop "KMSEmulator" | Out-Null
    sc delete "KMSEmulator" | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\KMSpico" /f | Out-Null
    reg delete "HKCU\Software\KMSpico" /f | Out-Null
    reg delete "HKLM\Software\KMSpico" /f | Out-Null
    schtasks /delete /tn "KMSpico" /f | Out-Null

    # Quick Scan
    Write-Host "[6/6] Running quick scan..."
    Start-MpScan -ScanType QuickScan

    Write-Host ""
    Write-Host "✓ Complete security setup finished successfully!"
    Write-Host ""
    Write-Host "All security features are now active:"
    Write-Host "✓ Windows Firewall enabled"
    Write-Host "✓ App and Browser Control enabled"
    Write-Host "✓ DNS configured for malware blocking"
    Write-Host "✓ Windows Defender fully activated"
    Write-Host "✓ All exclusions removed"
    Write-Host "✓ KMSpico removed"
    Write-Host "✓ System scanned for threats"
    Write-Host ""
    Pause
}

Function Install-Fishstrap {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "        FISHSTRAP INSTALLATION (WINGET)"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "Installing Fishstrap using Windows Package Manager (winget)..."
    Write-Host "This is the recommended installation method."
    Write-Host ""
    winget --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ Winget is not available on this system"
        Write-Host "Please use the direct download option instead"
        Pause
        return
    }
    Write-Host "✓ Winget is available"
    Write-Host "Installing Fishstrap..."
    winget install Fishstrap.fishstrap -e --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Fishstrap installed successfully via winget!"
        Write-Host "You can now launch Fishstrap from the Start Menu"
    } else {
        Write-Host ""
        Write-Host "✗ Failed to install Fishstrap via winget"
        Write-Host "You may want to try the direct download option"
    }
    Write-Host ""
    Pause
}

Function Install-ZenBrowser {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "       ZEN-BROWSER INSTALLATION (WINGET)"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "Installing Zen-browser using Windows Package Manager (winget)..."
    Write-Host ""
    winget --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ Winget is not available on this system"
        Write-Host "Please install winget or update your system"
        Pause
        return
    }
    Write-Host "✓ Winget is available"
    Write-Host ""
    Write-Host "Installing Zen-browser..."
    # Try both possible IDs
    $zenInstalled = $false
    winget install Zen-Dev.ZenBrowser -e --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -eq 0) { $zenInstalled = $true }
    if (-not $zenInstalled) {
        winget install ZenBrowser.ZenBrowser -e --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) { $zenInstalled = $true }
    }
    if ($zenInstalled) {
        Write-Host ""
        Write-Host "✓ Zen-browser installed successfully!"
    } else {
        Write-Host ""
        Write-Host "✗ Zen-browser installation failed."
        Write-Host "Please check if the package ID is correct or try manually."
    }
    Write-Host ""
    Pause
}

Function System-Cleanup {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "           SYSTEM CLEANUP"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "This will perform safe system cleanup operations:"
    Write-Host "1. Clear temporary files from user temp folder"
    Write-Host "2. Empty recycle bin"
    Write-Host "3. Clear DNS cache"
    Write-Host ""
    $cleanup_confirm = Read-Host "Continue with system cleanup? (y/n)"
    if ($cleanup_confirm -ne "y") { return }
    Write-Host ""
    Write-Host "Starting system cleanup..."
    Write-Host ""

    # Clear temporary files from user temp folder
    Write-Host "[1/3] Clearing temporary files..."
    $temp = $env:TEMP
    if (Test-Path $temp) {
        Get-ChildItem -Path $temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "✓ User temporary files cleared"
    } else {
        Write-Host "✗ User temp folder not found"
    }

    # Clear system temp files
    $sysTemp = "$env:SystemRoot\Temp"
    if (Test-Path $sysTemp) {
        Get-ChildItem -Path $sysTemp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "✓ System temporary files cleared"
    }

    # Empty recycle bin
    Write-Host ""
    Write-Host "[2/3] Emptying recycle bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Recycle bin emptied"
    } catch {
        Write-Host "⚠ Could not empty recycle bin (may already be empty)"
    }

    # Clear DNS cache
    Write-Host ""
    Write-Host "[3/3] Clearing DNS cache..."
    ipconfig /flushdns | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ DNS cache cleared"
    } else {
        Write-Host "✗ Failed to clear DNS cache"
    }

    Write-Host ""
    Write-Host "==============================================="
    Write-Host "         CLEANUP COMPLETED"
    Write-Host "==============================================="
    Write-Host ""
    Write-Host "System cleanup operations completed:"
    Write-Host "✓ Temporary files removed"
    Write-Host "✓ Recycle bin emptied"
    Write-Host "✓ DNS cache cleared"
    Write-Host ""
    Write-Host "Your system should now have more free space and refreshed network settings."
    Write-Host ""
    Pause
}

# Main loop
do {
    Show-MainMenu
    $choice = Read-Host "Enter your choice (0-5)"
    switch ($choice) {
        "1" { Complete-Security }
        "2" {
            Clear-Host
            Write-Host "==============================================="
            Write-Host "      WINDOWS DEFENDER SCAN OPTIONS"
            Write-Host "==============================================="
            Write-Host ""
            Write-Host "[1] Quick Scan"
            Write-Host "[2] Full Scan"
            Write-Host "[3] Custom Scan"
            Write-Host "[0] Back to Main Menu"
            Write-Host ""
            $scan_choice = Read-Host "Enter your choice (0-3)"
            switch ($scan_choice) {
                "1" {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         RUNNING QUICK SCAN"
                    Write-Host "==============================================="
                    Write-Host ""
                    Write-Host "Starting Windows Defender Quick Scan..."
                    Start-MpScan -ScanType QuickScan
                    Write-Host ""
                    Write-Host "Quick scan completed!"
                    Pause
                }
                "2" {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         RUNNING FULL SCAN"
                    Write-Host "==============================================="
                    Write-Host ""
                    Write-Host "Starting Windows Defender Full Scan..."
                    Start-MpScan -ScanType FullScan
                    Write-Host ""
                    Write-Host "Full scan completed!"
                    Pause
                }
                "3" {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         RUNNING CUSTOM SCAN"
                    Write-Host "==============================================="
                    Write-Host ""
                    $scan_path = Read-Host "Enter path to scan (e.g., C:\Users)"
                    Write-Host ""
                    Write-Host "Starting custom scan of: $scan_path"
                    Start-MpScan -ScanType CustomScan -ScanPath $scan_path
                    Write-Host ""
                    Write-Host "Custom scan completed!"
                    Pause
                }
            }
        }
        "3" { Install-Fishstrap }
        "4" { Install-ZenBrowser }
        "5" { System-Cleanup }
        "0" {
            Clear-Host
            Write-Host "Thank you for using Security Manager!"
            Write-Host "Your system security has been enhanced."
            Pause
            break
        }
        default { }