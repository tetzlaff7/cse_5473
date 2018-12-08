Readme:

Linux Installation:

install python 3.7+ packages
install scapy (follow instructions in scapys docs) (https://scapy.net/download/) (https://scapy.readthedocs.io/en/latest/installation.html#windows)
download and install netifaces (https://pypi.org/project/netifaces/)

Windows Installation:

download and install latest ncpap (needed by scapy) (https://nmap.org/npcap/) 
download and install python 3.7+ (https://www.python.org/downloads/)
add \python and \python\scripts folders to Windows PATH variable
download and install scapy for windows (follow instructions in scapys docs) (https://scapy.net/download/) (https://scapy.readthedocs.io/en/latest/installation.html#windows)
download and install pywin32 (https://github.com/mhammond/pywin32/releases)
download and install Microsoft Visual C++ Build Tools (check Windows 10 SDK. needed by netifaces) (https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017)
download and install netifaces (https://pypi.org/project/netifaces/)

Operation:

When run without any arguments the progam will enable packet routing and then print out a list of all the network adapters it finds on the system. Once you choose an adapter, it will probe that adapters subnet for connected devices as well as get the default gateway for that network. Next, it will allow the user to select a victim to attack. Once selected the ARP poisoning attack begins. The application will keep sending ARP packets (every 2 seconds or so) until the user hits [ctrl-c]. At this point the application disables or enables IP routing (depending on whether it was running before the application started) and unpoison's the vicitm and gateway.

Command line arguments:
-h Prints help 
-g [gateway_ip] Specifies the gateway IP to attack
-v [victim_ip] Specifies the victim IP to attack
-if  [interface_name] Specifies which interface to spoof from. If not specified it uses the default network interface
-dos Doesn't enable IP routing causing a denial of service attack on the victim
-t  Sets the packet timeout in seconds for the network probe (default is 2)

Notes:
-Currently this application only works with IPv4 addresses
-On windows, Ncpcap is the recommended packet capture driver, but WinPCap can also be used if you have issues with ncpcap
-on linux currently the application does not check the IP Routing status when it starts or quits. So IP routing will always be disabled after running.
