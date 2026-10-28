# NetRouteStabilizer

#### SoftetherVPN VPNGate Server Template

```
Format:
  (подключения) > vpncmd localhost /client /cmd:AccountList
  (создание)> vpncmd localhost /client /cmd:AccountCreate "%AccountName%" /SERVER:"%IP%/tcp:%TcpPort%" /HUB:"VPNGate" /USERNAME:"vpn" /NICNAME:"%Adapter%"
  (обновить, не надо)> vpncmd localhost /client /cmd:AccountSet "%AccountName%" /SERVER:"%IP%/tcp:%TcpPort%" /HUB:"VPNGate" /USERNAME:"vpn" /NICNAME:"%Adapter%"  
  (пароль, не надо)> vpncmd localhost /client /CMD:AccountPasswordSet "%AccountName%" /PASSWORD:"%Password%" /TYPE:%standard|radius|ntdomain%
  (no gui)> vpncmd localhost /client /cmd:AccountStatusHide "%AccountName%"
  (подключение)> vpncmd localhost /client /cmd:AccountConnect "%AccountName%"
  (статус)> vpncmd localhost /client /cmd:AccountStatusGet "%AccountName%"
  (переименование, не надо)> vpncmd localhost /client /cmd:AccountRename "%AccountName%" /NEW:"%NewAccountName%"
  (gui, не надо)> vpncmd localhost /client /cmd:AccountStatusShow "%AccountName%"  
  (удаление, не надо)> vpncmd localhost /client /cmd:AccountDelete "%AccountName%"  
	
 
Sample:
  > vpncmd localhost /client /cmd:AccountCreate "AccountName" /SERVER:"127.0.0.1:64443" /HUB:"VPNGate" /USERNAME:"vpn" /NICNAME:"VPN2"
  
Remoting:
  > vpncmd localhost /client /CMD:RemoteEnable
  > vpncmd localhost /client /CMD:RemoteDisable
```

#### VPNGate Template

- **Setting Name**: vpn284820218.opengw.net
- **Host Name**: 126.89.248.12/tcp
- **Port Number**: 1429
- **Virtual Hub Name**: VPNGate
- **Auth Type**: Anonymous Authentication
- **User Name**: vpn
- **Virtual Networ Adapter**: *~any~*
- [X] **No Adjustments of Routing Table (Advanced)** - (optional)


#### VPNGate Custom Settings
- **Interface Metrics**: 1111
- **Default Gateway**: 10.211.254.254
- **Local IP Address**: any of 10.211.*.*
- **IPv6**: disabled

```
route print 0.0.0.0 | findstr "0.0.0.0" | findstr "10.211."
route print | findstr "10.211."
route add 0.0.0.0 mask 0.0.0.0 10.211.1.4 metric 1111
curl https://api.myip.com
curl https://ipinfo.io/ip
curl https://api.ipify.org/?format=text
```

#### 3proxy

```
# USERS
users direct:CL:123456
users vpn:CL:123456
users Administrator:CL:passw4
auth strong 
allow Administrator 127.0.0.1,192.168.0.0/24 * 80 * 1-7 00:00:00-23:59:59 

# DIRECT user (No-Parent)
allow direct 

# VPNGate user (With-Parent)
allow vpn
parent 1000 socks5 0.0.0.0 443 proxy_user proxy_pass

deny * * * 

# Defaults
internal 0.0.0.0 
external 10.211.1.4 

# Direct Proxy throught 1087 port
socks -p1087 -i0.0.0.0 -e192.168.0.1 -a

# VPNGate  Proxy throught 1088 port
socks -p1088 -i0.0.0.0 -e10.211.1.4 -a

admin -p10088 
```
