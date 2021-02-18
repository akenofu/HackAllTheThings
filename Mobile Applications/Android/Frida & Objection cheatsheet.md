### Frida Over ssh
Setup frida over ssh
`ssh -L 27042:127.0.0.1:27042 root@192.168.1.17 -i C:\temp\op6`
Use -R flag on commands
`frida-ps -R`

### Frida with mobile plugged via USB
List all currently installed apps 
`frida-ps -Uai`

Check App Data Directories
`objection -g com.spotify.music explore`