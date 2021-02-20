#### Client Isolation in Wireless Networks  
Setup Device Wifi proxy to 127.0.0.1:8080
`adb reverse tcp:8080 tcp:8080`

<br>

#### Non-Proxy Aware Apps
Redirect all outgoing port 80 traffic to proxy
`iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP\>:8080`
Confirm rule has been set in IP Tables
`iptables -t nat -L`
Reset IP tables and flush rules
`iptables -t nat -F`

<br>

#### Proxy Detection
- Use IP tables instead of system proxy