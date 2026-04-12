@echo off
setlocal enabledelayedexpansion

set "delay=3"
set "timeout=15"
set "hitch=5"
set "srv="
set "failed="
set "idx=0"
set "connected=none"
set rand=2

echo -- DETECTING CONNECTED VPNGATE SERVER --
rem ping 127.0.0.1 -n !delay! >nul
timeout /t !hitch!
"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountList | findstr /R "Setting Status" > "%temp%\vpn.txt" 2>&1

:: разбираем opengw сервера ::
for /f "usebackq delims=" %%L in ("%temp%\vpn.txt") do (
    set "ln=%%L"
    if "!ln!"=="!ln:opengw=!" (
        :: opengw не найден, проверяем статус ::
        if "!ln:~0,6!"=="Status" if defined srv (
            for /f "tokens=2 delims=|" %%A in ("!ln!") do (
                set "st=%%A"
                for /f "tokens=* delims= " %%B in ("!st!") do set "st=%%B"
                set /a idx+=1
				set "padded=000!idx!"
				if "!st!" == "Connected" set "connected=!srv!"
				if "!st!" == "Connecting" set "failed=!srv!"
                echo [!padded:~-4!] !srv! = !st!
				set "srv!idx!=!srv!"
                set "srv="
            )
        )
    ) else (
        rem opengw найден, сохраняем сервер ::
        for /f "tokens=2 delims=|" %%A in ("!ln!") do set "srv=%%A"
    )
)

del "%temp%\vpn.txt" 2>nul

echo -- Found !idx! VPNGate Settings, Connected: !connected! --

:loop
:: Проверка есть ли подключен ::
if "!connected!" == "none" (    

	:: если идут попытки переподключения ::
	if not "!failed!" == "" (
	
		echo -- Found failed connection: !failed! --
		echo -- Status of failed connection: !failed! --
		"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!failed!" | findstr /R "Setting"	
		
		set "needbreak=0"
		"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!failed!" | findstr "Status" | findstr "Started" >nul
		if errorlevel 0 set "needbreak=1"
		"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!failed!" | findstr "Status" | findstr "Retrying" >nul
		if errorlevel 0 set "needbreak=1"
		"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!failed!" | findstr "not connected" >nul
		if errorlevel 0 set "needbreak=1"

		if !needbreak! == 0 (
		    :: Отключено ::
			echo -- No need to reject server connection: !failed! --
		) else (	
			:: идут попытки переподключения ::
			echo -- Break retries to the server: !failed! --
			"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountDisconnect "!failed!" | findstr /R "Setting"
			rem ping 127.0.0.1 -n !delay! >nul			
			timeout /t !delay!
																				   
		)
		set "failed="
	)

	:: ROTATE VPNGATE SERVER ::
	echo -- ROTATE VPNGATE SERVER --
	
	:: Получаем рандомный сервер из списка ::
	for /F "delims=" %%i IN ('powershell -Command "Get-Random -Minimum 1 -Maximum !idx!"') do set "rnd=%%i"	
	set "current_index=!rnd!"
	for /f "delims=" %%a in ("srv!current_index!") do set "current=!%%a!"
	
	echo -- Selected random server !rnd! : !current! --
	"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!current!" | findstr /R "Setting"
	
	:: Подключаемся ::
	echo -- Connecting to the server !rnd! : !current! --
	"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountConnect "!current!" | findstr /R "Setting"
	rem ping 127.0.0.1 -n !timeout! >nul
	timeout /t !timeout!
	
	:: Проверяем статус ::
	echo -- Status of server !rnd! : !current! --
	"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!current!" | findstr /R "Setting"	
	"%ProgramW6432%\SoftEther VPN Client\vpncmd.exe" localhost /client /cmd:AccountStatusGet "!current!" | findstr "Status" | findstr "Completed" >nul
	if errorlevel 1 (	
	    :: Не удалось подключиться ::
		set "connected=none"
		set "failed=!current!"		
	) else (
		:: Удалось подключиться ::
		set "connected=!current!"
		echo -- CONNECTED TO !current! SERVER --
	)
	
) else (
	:: VPN Подключен ::
	echo -- NO NEED ROTATE VPNGATE SERVER --
)
if "!connected!" == "none" goto loop 