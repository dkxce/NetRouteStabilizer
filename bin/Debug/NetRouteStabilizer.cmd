@echo off
cls
:: CHECK ADMIN RULES
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    echo -- ELEVATE ADMIN PERMISSIONS --
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:admin
:: CHANGE TO WORKING DIR
cd /d "%~dp0"

:: YOUR CODE HERE:
echo -- LAUNCHED BY ADMIN --
echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:variables

	:: TIMEOUTS ::
	SET SKIP=5
	SET SLEEP=20
	
	:: COLORS ::
	SET DEFCOLOR=07
	SET WRNCOLOR=06
	SET DNGCOLOR=04
	SET OKKCOLOR=0A
	SET FLDCOLOR=40
	
	:: FILES ::	
	SET FILE_CHECK=vpnroutes_CHECK.cmd
	SET FILE_NORMAL=vpnroutes_NORMALIZE.cmd
	SET FILE_DEL=vpnroutes_DELETE.cmd
	SET FILE_MAPSUPP=vpnroutes_MAPSUPP.cmd
	SET FILE_CHECK_COPY_TILL=121
	SET FILE_NORMAL_COPY_TILL=83	
	SET FILE_DEL_COPY_TILL=83
	SET FILE_MAPSUPP_COPY_TILL=83
	
	:: PARAMETERS ::
	SET CHECK=ya.ru
	SET PROXY=ENABLED
	SET TRIGGERMETRIC=999	

	:: GATEWAYS ::
	SET NORMAL=192.168.177.254
	SET NORMALMETRIC=35
	SET GATEWAY=10.211.254.254
	SET GATEWAYMETRIC=1111
	SET MAPSUPPGATEWAY=192.168.33.254
	SET MAPSUPPGATEWAYMETRIC=135

	:: PROXIES ::
	SET PROXIES=161.115.230.27,85.195.81.161

	:: TELEGRAM IPs ::
	SET TELEGRAM=149.154.160.0/255.255.240.0,149.154.176.0/255.255.240.0,91.108.4.0/255.255.252.0,91.108.8.0/255.255.252.0,91.108.12.0/255.255.252.0,91.108.16.0/255.255.252.0,91.108.56.0/255.255.252.0,5.28.16.0/255.255.248.0,5.28.24.0/255.255.248.0,109.239.140.0/255.255.255.0

	:: 3PROXY ::
	SET TPRXYPATH=%~dp0\3proxy-0.9.5-x64-dkxce\bin64
	SET TPRXYREWRITE=ENABLED
	SET TPRXYRESTART=ENABLED
	SET TRPXYEXE=%TPRXYPATH%\3proxy.exe
	SET TRPXYCFG=%TPRXYPATH%\3proxy.cfg
	SET TRPXY_ADMIN_PASS=4S9eBHkphYaMFPr38
	SET TRPXY_DKXCE_PASS=zCEuBnhC6Ss83gG0x
	SET DNWLDVPNGATECSV=ENABLED

:begin
color %DEFCOLOR%

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

	:: GET CURRENT ROUTES ::
	SET TTLROUTES=0 && FOR /F "delims=" %%i IN ('route print 0.0.0.0 ^| findstr "0.0.0.0"') DO (SET /A TTLROUTES+=1)
	if %TTLROUTES% GTR 1 (
		color %WRNCOLOR%
		echo -- FOUND DEFAULT ROUTES %TTLROUTES%: --
		route print 0.0.0.0 | findstr "0.0.0.0"
	)
	:: GET SoftEtherVPN ROUTE ::
	SET /A TTLROUTES = 0
	SET TTLROUTES=0 && FOR /F "delims=" %%i IN ('route print 0.0.0.0 ^| findstr "0.0.0.0" ^| findstr "%GATEWAY%"') DO (SET /A TTLROUTES+=1)
	if %TTLROUTES% GEQ 1 (
		color %WRNCOLOR%
		echo -- FOUND SoftEtherVPN ROUTE %TTLROUTES%: --
		route print 0.0.0.0 | findstr "0.0.0.0" | findstr "%GATEWAY%"
		:: GET SoftEtherVPN Metric ::
		for /f "tokens=5" %%a in ('route print 0.0.0.0 ^| findstr "0.0.0.0" ^| findstr "%GATEWAY%"') do (
			echo -- SoftEtherVPN METRIC IS %%a --
			if %%a LEQ %TRIGGERMETRIC% (
				color %DNGCOLOR%
				echo .
				echo -- !!! PLEASE CHANGE SoftEtherVPN METRIC TO MANUAL VALUE %GATEWAYMETRIC% !!!--
				echo .
				goto normilize
			) else (
				color %OKKCOLOR%
				echo -- NO NEED TO CHANGE DEFAULT ROUTE --
				goto proximize
			)
		)
	)
	color %FLDCOLOR%
	echo -- SoftEtherVPN ROUTE NOT FOUND --
	goto ready
	
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:normilize
		
	:: CHECK ROUTES ::
	echo -- CHECK DEFAULT SYSTEM ROUTE --
	route print 0.0.0.0 | findstr "0.0.0.0"	
	
	echo -- CHECK DEFAULT SYSTEM GATEWAY --
	ipconfig | findstr /v "IPv4" | findstr /v "255.255." | findstr "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"
	
	echo -- CHECK IP ADDRESSES --
	ipconfig /all | findstr "IPv4"

	echo .
    echo -- SWITCHING TO CHANGE ROUTES --
	echo .
    ping 127.0.0.1 -n 3 >nul
		
	:: SET ROUTES TO GATEWAY ::
	echo -- SET ROUTES TO %NORMAL% --
	route delete 0.0.0.0 >nul
	route add 0.0.0.0 mask 0.0.0.0 %NORMAL% metric %NORMALMETRIC% >nul
	route print 0.0.0.0 | findstr "0.0.0.0"
	
	echo -- CHECK SYSTEM GATEWAY: --
	ipconfig | findstr /v "IPv4" | findstr /v "255.255." | findstr "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"
	
	echo -- CHECK IP ADDRESSES --
	ipconfig /all | findstr "IPv4"
	
	echo .
    echo -- SWITCHING TO CHECK ROUTES --
	echo .

	:: CHECK INTERNET ::
	echo -- CHECK DIRECT INTERNET --
	ping %CHECK% -n 3 | findstr "TTL"
	rem tracert %CHECK%
	
:proximize
:save_del_routes_file

	:: SAVE DEL ROUTES FILE ::
	if "%~nx0" NEQ "%FILE_DEL%" (
		if exist "%~dp0\%FILE_DEL%" (
			del /q /f "%~dp0\%FILE_DEL%"
		)
		powershell -Command "Get-Content '%0' -TotalCount %FILE_DEL_COPY_TILL% | Set-Content '%~dp0\%FILE_DEL%'"		
	)
	echo echo -- RESET PROXY LISTS --  >> %FILE_DEL%
	if not "%PROXIES%"=="" (
		echo echo --  RESET DIRECT PROXIES ROUTES --  >> %FILE_DEL%
		for %%i in (%PROXIES:,= %) do (
			echo route delete %%i >> %FILE_DEL%			
		)
	)
	if not "%TELEGRAM%"=="" (
		echo echo --  RESET DIRECT TELEGRAM --  >> %FILE_DEL%
		for %%i in (%TELEGRAM:,= %) do (
			for /f "tokens=1,2 delims=/" %%a in ("%%i") do (
				echo route delete %%a >> %FILE_DEL%		
			)
		)
	)
	echo echo !!! READY, SLEEP %SLEEP% SECONDS !!! >> %FILE_DEL%
	echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_DEL%
	echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_DEL%
	echo ping 127.0.0.1 -n %SLEEP% >nul >> %FILE_DEL%

:proximize_proxify

	if "%PROXY%"=="ENABLED" (
		
		:: RE-SET DIRECT PROXIES ROUTES ::
		echo .
		echo -- SWITCHING TO CHANGE DIRECT PROXIES ROUTES --
		echo .
		ping 127.0.0.1 -n 3 >nul

		if not "%PROXIES%"=="" (
		:: RE-SET DIRECT PROXIES ::
			echo -- RE-SET DIRECT PROXIES ROUTES: --
			ping 127.0.0.1 -n 2 >nul
			for %%i in (%PROXIES:,= %) do (
				route delete %%i >nul
				route add %%i mask 255.255.255.255 %GATEWAY% metric 15 >nul
				route print %%i | findstr "%%i"
				rem ping %%i -n 3 | findstr "TTL"
				rem tracert %%i
			)
		)
		
		:: RE-SET DIRECT TELEGRAM ROUTES ::
		echo .
		echo -- SWITCHING TO CHANGE DIRECT TELEGRAM ROUTES --
		echo .
		ping 127.0.0.1 -n 3 >nul

		if not "%TELEGRAM%"=="" (
			:: RE-SET DIRECT TELEGRAM ROUTES:
			echo -- RE-SET DIRECT TELEGRAM ROUTES: --
			ping 127.0.0.1 -n 2 >nul
			for %%i in (%TELEGRAM:,= %) do (
				set /a COUNT+=1
				for /f "tokens=1,2 delims=/" %%a in ("%%i") do (
					route delete %%a >nul
					route add -p %%a mask %%b %GATEWAY% >nul
					route print %%a | findstr "%%a"
				)
			)
		)
		
	) else (
	
		echo .
		echo -- PASSION CHANGE PROXY LISTS ROUTES --
		echo .
		
	)
	
:save_3proxy_congif

	:: SAVE 3PROXY CONFIG ::	
	if "%TPRXYREWRITE%"=="ENABLED" (
	
		echo .
		echo -- SWITCHING TO CHANGE 3PROXY CONFIGURATION --
		echo .
		ping 127.0.0.1 -n 3 >nul
		
		setlocal enabledelayedexpansion
		for /f "tokens=4" %%a in ('route print 0.0.0.0 ^| find "10.211." ^| findstr /r "[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*"') do (
			set "externalip=%%a"
		)
		
		if not defined externalip (
			echo -- CANNOT DETECT EXTERNAL IP !externalip! --
			route print 0.0.0.0 | find "10.211."
			echo -- USING NetRouteStabilizer.exe --
			
			%~dp0\NetRouteStabilizer.exe /detectip > %~dp0\tmp.txt
			if exist "%~dp0\tmp.txt" (
				for /f "usebackq delims=" %%i in ("%~dp0\tmp.txt") do set "externalip=%%i"	
				del /q /f tmp.txt			
			)					
		)		
		
		if not defined externalip (
			echo -- CANNOT DETECT EXTERNAL IP !externalip! WITH NetRouteStabilizer.exe --
		) else (
			if "!externalip!"=="0.0.0.0" (
				echo -- CANNOT DETECT EXTERNAL IP !externalip! WITH NetRouteStabilizer.exe --
			) else (
			
				echo .
				echo -- WRITING 3PROXY CONFIGURATION TO IP !externalip! --
				
				if exist "%TRPXYCFG%" (
					del /q /f "%TRPXYCFG%"
				)		

				echo # >> %TRPXYCFG%
				echo # DNS IP ADDRESSES # >> %TRPXYCFG%
				echo #nserver 127.0.0.1 >> %TRPXYCFG%
				echo #timeouts 1 5 30 60 180 1800 15 60 >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo # USER LISTS # >> %TRPXYCFG%
				echo users dkxce:CL:%TRPXY_DKXCE_PASS% >> %TRPXYCFG%
				echo users Administrator:CL:%TRPXY_ADMIN_PASS% >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo # AUTHORIZATION # >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo auth strong >> %TRPXYCFG%
				echo allow dkxce >> %TRPXYCFG%
				echo allow Administrator 192.168.177.0/24 * 80 * 1-7 00:00:00-23:59:59 >> %TRPXYCFG%
				echo deny * * * >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo # PORTS # >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo internal 0.0.0.0 >> %TRPXYCFG%
				echo external !externalip! >> %TRPXYCFG%
				echo socks -p1088 -i0.0.0.0 -a >> %TRPXYCFG%
				echo admin -p10088 >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo # LOG # >> %TRPXYCFG%
				echo # >> %TRPXYCFG%
				echo log >> %TRPXYCFG%
				echo log %~dp0\3proxy-0.9.5-x64-dkxce\logs\3proxy.log D >> %TRPXYCFG%
				echo rotate 7 >> %TRPXYCFG%
				
				if exist "%TRPXYCFG%" (
					echo -- CONFIGURATION SUCCESSFULLY WRITED --
					echo .
				) else (
					echo -- !!! ERROR WRITING CONFIGURATION !!! --
					echo .
				)
				
				if "%TPRXYRESTART%"=="ENABLED" (
				
					echo .
					echo -- SWITCHING RESTART 3PROXY --
					echo .				
					ping 127.0.0.1 -n 3 >nul
					
					net stop 3proxy | findstr "3proxy"
					net start 3proxy | findstr "3proxy"
					
					echo .
					echo -- TESTING 3PROXY --
					echo .
					echo -- EXTERNAL IP ADDRESS: --
					curl -x socks5://127.0.0.1:1088 -U dkxce:%TRPXY_DKXCE_PASS% --connect-timeout 15 https://api.ipify.org/?format=text
					echo .
					curl -x socks5://127.0.0.1:1088 -U dkxce:%TRPXY_DKXCE_PASS% --connect-timeout 15 https://api.myip.com
					echo .
					
					if "%DNWLDVPNGATECSV%"=="ENABLED" (
						if exist "%~dp0\vpnroutes_vpngate.txt" (
							del /q /f "%~dp0\vpnroutes_vpngate.txt"
						)
						echo .
						echo -- DOWNLOADING OpenVPNGate Servers CSV File --
						echo .
						curl -x socks5://127.0.0.1:1088 -U dkxce:%TRPXY_DKXCE_PASS% --connect-timeout 90 -o %~dp0\vpnroutes_vpngate.txt https://www.vpngate.net/api/iphone/
						echo .
						%~dp0\NetRouteStabilizer.exe /stripcsv
					)
					
				)
			
			)
		)
		
	)
	
:ready
:save_check_routes_file

	:: SAVE CHECK ROUTES FILE ::
	if "%~nx0" NEQ "%FILE_CHECK%" (
		if exist "%~dp0\%FILE_CHECK%" (
			del /q /f "%~dp0\%FILE_CHECK%"
		)
		powershell -Command "Get-Content '%0' -TotalCount %FILE_CHECK_COPY_TILL% | Set-Content '%~dp0\%FILE_CHECK%'"
		echo :normilize >> %FILE_CHECK%
		echo :proximize >> %FILE_CHECK%
		echo :ready >> %FILE_CHECK%
		echo echo !!! READY, SLEEP %SLEEP% SECONDS !!! >> %FILE_CHECK%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_CHECK%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_CHECK%
		echo ping 127.0.0.1 -n %SLEEP% >nul >> %FILE_CHECK%
	)
	
:save_normilize_routes_file

	:: SAVE NORMILIE ROUTES FILE ::
	if "%~nx0" NEQ "%FILE_NORMAL%" (
		if exist "%~dp0\%FILE_NORMAL%" (
			del /q /f "%~dp0\%FILE_NORMAL%"
		)
		powershell -Command "Get-Content '%0' -TotalCount %FILE_NORMAL_COPY_TILL% | Set-Content '%~dp0\%FILE_NORMAL%'"		
		
		echo :: SET ROUTES TO GATEWAY ::  >> %FILE_NORMAL%
		echo echo -- NORMILIZE NETWORK ROUTES --  >> %FILE_NORMAL%
		echo echo -- SET ROUTES TO %NORMAL% --  >> %FILE_NORMAL%
		echo route delete 0.0.0.0 >nul >> %FILE_NORMAL%
		echo route add 0.0.0.0 mask 0.0.0.0 %NORMAL% metric %NORMALMETRIC% >nul >> %FILE_NORMAL%
		echo route print 0.0.0.0 | findstr "0.0.0.0" >> %FILE_NORMAL%
	
		echo echo -- CHECK SYSTEM GATEWAY: -- >> %FILE_NORMAL%
		echo ipconfig | findstr /v "IPv4" | findstr /v "255.255." | findstr "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" >> %FILE_NORMAL%
	
		echo echo -- CHECK IP ADDRESSES -- >> %FILE_NORMAL%
		echo ipconfig /all | findstr "IPv4" >> %FILE_NORMAL%
		
		echo echo !!! READY, SLEEP %SLEEP% SECONDS !!! >> %FILE_NORMAL%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_NORMAL%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_NORMAL%
		echo ping 127.0.0.1 -n %SLEEP% >nul >> %FILE_NORMAL%
	)
	
:save_mapsupp_routes_file
		
	:: SAVE NORMILIE ROUTES FILE ::
	if "%~nx0" NEQ "%FILE_MAPSUPP%" (
		if exist "%~dp0\%FILE_MAPSUPP%" (
			del /q /f "%~dp0\%FILE_MAPSUPP%"
		)
		powershell -Command "Get-Content '%0' -TotalCount %FILE_MAPSUPP_COPY_TILL% | Set-Content '%~dp0\%FILE_MAPSUPP%'"		
		
		echo :: SET ROUTES TO GATEWAY ::  >> %FILE_MAPSUPP%
		echo echo -- NORMILIZE NETWORK ROUTES --  >> %FILE_MAPSUPP%
		echo echo -- SET ROUTES TO %MAPSUPPGATEWAY% --  >> %FILE_MAPSUPP%
		echo route delete 0.0.0.0 >nul >> %FILE_MAPSUPP%
		echo route add 0.0.0.0 mask 0.0.0.0 %MAPSUPPGATEWAY% metric %MAPSUPPGATEWAYMETRIC% >nul >> %FILE_MAPSUPP%
		echo route print 0.0.0.0 | findstr "0.0.0.0" >> %FILE_MAPSUPP%
	
		echo echo -- CHECK SYSTEM GATEWAY: -- >> %FILE_MAPSUPP%
		echo ipconfig | findstr /v "IPv4" | findstr /v "255.255." | findstr "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" >> %FILE_MAPSUPP%
	
		echo echo -- CHECK IP ADDRESSES -- >> %FILE_MAPSUPP%
		echo ipconfig /all | findstr "IPv4" >> %FILE_MAPSUPP%
		
		echo echo !!! READY, SLEEP %SLEEP% SECONDS !!! >> %FILE_MAPSUPP%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_MAPSUPP%
		echo echo ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> %FILE_MAPSUPP%
		echo ping 127.0.0.1 -n %SLEEP% >nul >> %FILE_MAPSUPP%
	)
	
:final
	
	echo.
	echo !!! READY, SLEEP %SLEEP% SECONDS !!!
	echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
	ping 127.0.0.1 -n %SLEEP% >nul

:end