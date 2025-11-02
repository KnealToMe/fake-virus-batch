@echo off
if "%1"=="child" goto child

title Surveillant
color 0A

echo Lancement de 10 CMD...
for /L %%i in (1,1,10) do (
    start "CMD" cmd /c "%~f0" child
)

:surveillance
for /f %%a in ('tasklist ^| find /c "cmd.exe"') do set /a count=%%a
if %count% LSS 11 (
    start "CMD" cmd /c "%~f0" child
    start "CMD" cmd /c "%~f0" child
)
timeout /t 2 /nobreak >nul
goto surveillance

:child
title CMD
color 0A
setlocal enabledelayedexpansion
cls

echo.
echo  ================================================================
echo  [ALERT] UNAUTHORIZED ACCESS DETECTED - SYSTEM BREACH IN PROGRESS
echo  ================================================================
echo.

echo [%time%] [CRITICAL] Firewall disabled... Backdoor installed
echo [%time%] [WARNING] Remote connection established: 45.!RANDOM!.!RANDOM!.!RANDOM!
echo [%time%] [EXPLOIT] Injecting payload into kernel32.dll...
echo [%time%] [SUCCESS] Administrator privileges escalated - UID: 0
echo.

echo [SYSTEM] Gathering real system information...
for /f "tokens=2 delims=:" %%a in ('systeminfo ^| findstr /C:"OS Name"') do echo [INFO] OS:%%a
for /f "tokens=2 delims=:" %%a in ('systeminfo ^| findstr /C:"System Manufacturer"') do echo [INFO] Manufacturer:%%a
for /f "tokens=2 delims=:" %%a in ('systeminfo ^| findstr /C:"System Model"') do echo [INFO] Model:%%a
echo [INFO] Computer Name: %COMPUTERNAME%
echo [INFO] Username: %USERNAME%
echo [INFO] User Domain: %USERDOMAIN%
echo.

echo [SCAN] Detecting network interfaces...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /C:"IPv4"') do (
    echo [+] IP Address detected:%%a
)
echo.

echo [SCAN] Mapping active processes...
for /f "skip=3 tokens=1" %%a in ('tasklist') do (
    echo [PROCESS] %%a - RUNNING
)
timeout /t 1 >nul

echo.
echo [ATTACK] Launching brute force attack on encrypted files...
for /L %%i in (1,1,20) do (
    set /a prog=%%i*5
    echo [!prog!%%] Trying password: !RANDOM!!RANDOM!!RANDOM! - FAILED
    if %%i==15 (
        echo [SUCCESS] Password cracked: "admin123" - Access granted!
        echo.
    )
)

echo [VULNERABILITY] Exploiting CVE-2024-!RANDOM!...
echo [EXPLOIT] Buffer overflow in system service detected
echo [EXPLOIT] Injecting malicious DLL into process memory...
echo [SUCCESS] Code execution achieved with SYSTEM privileges
echo.

echo [EXFILTRATION] Scanning user directories...
if exist "%USERPROFILE%\Documents" (
    echo [FOUND] Documents folder: %USERPROFILE%\Documents
    for /f "delims=" %%f in ('dir /b "%USERPROFILE%\Documents\*.txt" 2^>nul') do (
        echo [DL] Stealing: %%f - !RANDOM! KB - DOWNLOADING...
    )
)

if exist "%USERPROFILE%\Desktop" (
    echo [FOUND] Desktop folder: %USERPROFILE%\Desktop
    for /f "delims=" %%f in ('dir /b "%USERPROFILE%\Desktop\*.pdf" 2^>nul') do (
        echo [DL] Stealing: %%f - !RANDOM! KB - DOWNLOADING...
    )
)

if exist "%USERPROFILE%\Downloads" (
    echo [FOUND] Downloads folder: %USERPROFILE%\Downloads
    for /f "delims=" %%f in ('dir /b "%USERPROFILE%\Downloads" 2^>nul ^| findstr /i ".exe .zip"') do (
        echo [DL] Stealing: %%f - !RANDOM! MB - DOWNLOADING...
    )
)
echo.

echo [REGISTRY] Accessing Windows Registry...
echo [REG] Reading: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2^>nul') do (
    echo [REG] Windows Version: %%a
)
echo [REG] Extracting installed software list...
for /f "skip=2 tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "DisplayName" 2^>nul ^| findstr "DisplayName"') do (
    echo [SOFTWARE] %%a
)
timeout /t 1 >nul

echo.
echo [DRIVES] Scanning storage devices...
for /f "tokens=1" %%d in ('wmic logicaldisk get caption 2^>nul ^| findstr ":"') do (
    echo [DRIVE] Found: %%d - Scanning for sensitive data...
    if exist "%%d\" (
        for /f "delims=" %%f in ('dir /b "%%d\*.xlsx" "%%d\*.docx" 2^>nul') do (
            echo [TARGET] %%d\%%f - Size: !RANDOM! KB - MARKED FOR EXTRACTION
        )
    )
)
echo.

echo [CRYPTO] Deploying ransomware module...
echo [ENCRYPT] AES-256 encryption initiated on all user files...
for /L %%i in (1,1,30) do (
    set /a files=!RANDOM!
    echo [LOCKED] C:\Users\%USERNAME%\Documents\file_!files!.doc - ENCRYPTED
    echo [LOCKED] C:\Users\%USERNAME%\Pictures\IMG_!files!.jpg - ENCRYPTED
    echo [LOCKED] C:\Users\%USERNAME%\Videos\video_!files!.mp4 - ENCRYPTED
)
echo.
timeout /t 1 >nul
echo [RANSOM] Your files have been encrypted!
echo [RANSOM] UR PC IS GETTING FUCKED
echo [RANSOM] You have 48 hours before files are permanently deleted
echo.

echo [MALWARE] Installing persistent backdoors...
echo [MALWARE] Installing keylogger... SUCCESS
echo [MALWARE] Installing screen recorder... SUCCESS
echo [MALWARE] Installing webcam hijacker... SUCCESS
echo [MALWARE] Installing network sniffer... SUCCESS
echo [BACKDOOR] Opening port 31337 for persistent access... LISTENING
echo [BACKDOOR] Creating scheduled task for auto-start... SUCCESS
echo.

echo [NETWORK] Scanning local network for vulnerable devices...
for /f "skip=3 tokens=1" %%a in ('arp -a 2^>nul ^| findstr "dynamic"') do (
    echo [TARGET] Device found: %%a - Attempting exploitation...
    echo [SUCCESS] %%a compromised - Malware deployed
)
echo.

echo [TRACE] Erasing evidence...
echo [DELETE] C:\Windows\System32\LogFiles\*.log - WIPING...
echo [DELETE] C:\Windows\System32\LogFiles\*.log - WIPED
echo [DELETE] %TEMP%\*.tmp - WIPING...
echo [DELETE] %TEMP%\*.tmp - WIPED
echo [MODIFY] Registry entries altered to hide malware
echo [SPOOF] System timestamps modified
echo [CLEAN] Event logs cleared
echo.
timeout /t 1 >nul

color 0C
cls
echo.
echo  ================================================================
echo                    !!! SYSTEM COMPROMISED !!!
echo  ================================================================
echo.
echo  [ALERT] All your files are now encrypted
timeout /t 1 >nul
echo  [ALERT] Webcam and microphone are being monitored
timeout /t 1 >nul
echo  [ALERT] Banking credentials have been stolen
timeout /t 1 >nul
echo  [ALERT] This device is now part of a botnet
timeout /t 1 >nul
echo  [ALERT] Network devices have been infected
echo.
timeout /t 2 >nul

echo  ================================================================
echo              INITIATING SELF-DESTRUCT SEQUENCE
echo  ================================================================
echo.

for /L %%s in (10,-1,1) do (
    cls
    echo.
    echo  ****************************************************************
    echo  *                                                              *
    echo  *            !!! AUTO-DESTRUCT ACTIVATED !!!                   *
    echo  *                                                              *
    echo  ****************************************************************
    echo.
    echo                    SYSTEM WIPE IN: %%s SECONDS
    echo.
    echo  [WARNING] All data will be permanently erased
    echo  [WARNING] Hardware components will be damaged
    echo  [WARNING] Recovery is IMPOSSIBLE
    echo  [WARNING] Backup systems compromised
    echo.
    echo             Press ANY key to abort... (Too late)
    echo.
    timeout /t 1 >nul
)

cls
color 4F
echo.
echo  ================================================================
echo                         BOOM! DESTROYED
echo  ================================================================
echo.
echo  [FINAL] Master Boot Record overwritten
echo  [FINAL] BIOS corrupted beyond repair
echo  [FINAL] All storage devices wiped
echo  [FINAL] Network cards disabled
echo  [FINAL] System permanently disabled
echo.
echo  Thank you for being an easy target :)
echo  Computer: %COMPUTERNAME% - User: %USERNAME%
echo.
timeout /t 2 >nul

:: Créer le fichier VBS
echo ' Message 1 > "%temp%\final.vbs"
echo MsgBox "jspp", vbInformation, "jspp" >> "%temp%\final.vbs"
echo. >> "%temp%\final.vbs"
echo ' Message 2 >> "%temp%\final.vbs"
echo MsgBox "jspp;((", vbInformation, "jspp" >> "%temp%\final.vbs"
echo. >> "%temp%\final.vbs"
echo ' Message 3 >> "%temp%\final.vbs"
echo MsgBox "jspp", vbInformation, "jspp" >> "%temp%\final.vbs"
echo. >> "%temp%\final.vbs"
echo ' Message 4 -  >> "%temp%\final.vbs"
echo Do >> "%temp%\final.vbs"
echo     reponse = MsgBox("jspp ;'(", vbYesNo + vbQuestion, "Question !!!") >> "%temp%\final.vbs"
echo     If reponse = vbNo Then >> "%temp%\final.vbs"
echo         MsgBox "jspp", vbExclamation, "Nope!!!" >> "%temp%\final.vbs"
echo     End If >> "%temp%\final.vbs"
echo Loop Until reponse = vbYes >> "%temp%\final.vbs"
echo. >> "%temp%\final.vbs"
echo ' Message final >> "%temp%\final.vbs"
echo MsgBox "jspp", vbInformation + vbOKOnly, "jspp" >> "%temp%\final.vbs"

:: Lancer le VBS AVANT de tuer les processus
start "" "%temp%\final.vbs"

:: Attendre 2 secondes pour que le VBS se lance
timeout /t 2 >nul

:: MAINTENANT on tue tous les CMD
taskkill /F /IM cmd.exe >nul 2>&1

exit