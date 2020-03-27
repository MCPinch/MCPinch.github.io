Working on a network recon tool that works with the BBB... This is a group project and I will outline how I managed to do my part.
The goal is to have a device you can plug into a network via Ethernet and it will map out devices on there and other useful enumeration things.

# Setting up the BeagleBone Black:
Out the box, the BBB is pretty useless... :(
I would recommend getting a 16gb microSD card online, this is used for updating the beaglebone.

Once you have one, you also need an adapter so you can load the latest beaglebone image onto the SD card then flash it to the on-board memory.

I just used the latest debian image on their website. https://beaglebone.org

After it's been downloaded, I put the micro SD in it's slot on the beaglebone and held down the small black button on the OTHER SIDE of the board from the sd slot. Keep holding it down and apply power (I plugged it in via USB)... keep it held until all the blue lights turn on next to the ethernet port. You may now release the button, leave it a few mins and you should see the lights going back and forth. This means that it is flashing to on-board memory. There are flasher images on the website, but those didn't work and the non-flasher one did... hmmmm... anyway.

After all the lights go off, it should be safe to unplug it, take out the microSD card and plug it back it or apply power again. 
Now you have one that you can SSH into!

The default ip is _192.168.7.2_ and this will always be the same out of the box.
Log in as user _debian_ with the password _temppwd_.

Ethernet over USB is such a pain to get working, all the documentation is horribly out of date and none of it actually works. So, I just plugged it in via Ethernet cable.

Do le updates and should be ready to go... oh and one more thing!
I use a few libraries in my code that I include at the start:
```python
import os
from getmac import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
from ftplib import FTP
from scapy.all import *
from scapy.layers.http import HTTPRequest
import random
import platform
import re
import struct
import sys
import socket
import fcntl
import subprocess
import nmap
from pprint import pprint
```

So you need to pip install some of these libraries that aren't already built in. (if pip is being annoying and giving you errors after you have updated, use `uninstall distributions` and it should work)

# The CODE:
Now onto the meaty part, the code!

I wrote code for the scanner that:

- Pings hosts and returns a list of the live ones.
- TCP scans the hosts by probing a common tcp port.
- Calculates the range of scannable ip's on the network depending on ip and netmask of eth0 interface...
- SNMP enumeration (limited functionality) 
- Some extra little bits...

## Range Calculator:
This has taken the most time and brainpower so far. What this part of the script does is automatically calculate the range of ip's it can scan and it does this by looking at the ethernet interface of the beaglebone, looking at the ip and subnet mask, then doing calculations on them.

First, I get the ip and netmask from eth0 with the following functions:
*I DO NOT KNOW HOW THESE WORK AND I DIDN'T WRITE THEM*

```python
def get_ip_address(ifname):
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

def get_netmask(ifname):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x891b,struct.pack('256s',ifname))[20:24])
```
Then, I assign them a varibale and pass them to the range calc function.

```python
ip = get_ip_address('eth0')
netmask = get_netmask('eth0')
```

```python
def range_calculator(ip,netmask,choice):
        

        #bitwise can only be done on int
        #bitwise can only be done on single numbers
        #split them up at each dot
        #then do calculations on each one
        print("IP is : " + ip)
        print("Netmask is : " + netmask)
        ip_list=ip.split('.')
        netmask_list=netmask.split('.')
        network=[None,None,None,None]
        first_address=[None,None,None,None]
        for i in range(0,4):
                network[i]= int(ip_list[i]) & int(netmask_list[i])
                first_address[i]=int(ip_list[i])& int(netmask_list[i])


        print("Network address is : " + str(network[0]) + '.' + str(network[1])+'.'+str(network[2])+'.'+str(network[3]))


        mask = 255
        hosts = 1
        for index, val in enumerate(netmask_list):
                netmask_list[index] = int(netmask_list[index])^mask #xor with 255 to get inverse of netmask
                if netmask_list[index] !=0:
                        hosts *= netmask_list[index] + 1 #use wildcard mask to calculate num of hosts
        hosts-=2
        host_amount=[]
        index_list=[]
        ranges=[]
        indx=[]
        #print("Wildcard netmask is : " + '.'.join(str(x) for x in netmask_list)) #inverse of netmask is wildcard mask
        print("Number of hosts is: " + str(hosts))
        for i in range(0,4):
                if netmask_list[i]!=0:
                        index_list.append(i)
                        host_amount.append(netmask_list[i])
        for i in index_list:

                network[i]=(int(network[i])+int(netmask_list[i]))

        print("Final address is : " +'.'.join(str(x) for x in network))
        #print(first_address)
        #print(network)

        for i in range(0,4):
                if network[i] != first_address[i]:
                        indx.append(i)
                        ranges.append(network[i]-first_address[i])


        #print(indx)
        #print(ranges)
        if choice==1:
                Pingscan(indx,ranges,first_address)
        if choice==2:
               n=input("Enter 1 for windows scan or 2 for linux: ")
               brute=input("Enter 1 for brute force and 2 for scan till discovery: ")
               runTCPScanner(indx,ranges,first_address,n,brute,0)
```

Ok, lets break this down.
- First, I split the ip and netmask into a list of bits without the dots.
- Then I loop through each bit and bitwise AND  the netmask and the ip to get the first address of the network.
- I XOR each bit of the netmask with 255 to get the inverse of the netmask. This is known as the wildcard mask. With this, I can calculate a lot of useful things...
- I get the amount of hosts per subnet and also the final address of the network.
- I also loop through each bit of the wildcard mask and add the index where it isn't 0 and the difference between the first address at that point and the wildcard at that point. This tells us how many times we need to loop through the address and what bit of the ip changes.
- Then, I pass all these values to my functions, the choice depends on what you select in a menu i implemented later. In both cases, I pass the first address, the amount of change at a bit of the address and what index that change occurs.

Phew, that wasn't too bad. Right?! :/

### But why?
With this, the beaglebone can be plugged into any network and it will automatically find the right range.  This takes  a lot of strain off of other functions that may be added later and makes enumeration much easier if we know the scope to scan beforehand. 

## Ping Scan:
Now that we have done all the fancy calculations, we need to figure out a way to process this information into something useful. In other words, how can i loop through each address for a given address range? 
I came up with the following solution:

 ```python
 def Pingscan(indx,ranges,ip): 
       
        if len(indx) == 1:
                for i in range(0,(ranges[0]+1),1):
                        address=str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(i)
                        print("Trying "+ address)
                        res=subprocess.call(['ping','-c','1',address])
                        if res==0:
                                print("Ping to " + address + " ok") 
                                success.append(address)

        if len(indx)==2:
                for i in range(0,(ranges[0]+1),1):
                        for x in range(0,(ranges[1]+1),1):
                                address=str(ip[0])+'.'+str(ip[1])+'.'+str(i)+'.'+str(x)
                                res=subprocess.call(['ping','-c','1',address])
                                if res==0:
                                        print("Ping to " + address + " ok")
                                        success.append(address)

        if len(indx)==3:
                for i in range(0,(ranges[0]+1),1):
                        for x in range(0,(ranges[1]+1),1):
                                for y in range(0,(ranges[2]+1),1):
                                        address=str(ip[0])+'.'+str(i)+'.'+str(x)+'.'+str(y)
                                        res=subprocess.call(['ping','-c','1',address])
                                        if res==0:
                                                print("Ping to " + address + " ok")
                                                success.append(address)

        return success # returns array of succesful pings
```

Simply, it goes through a loop depending on how many changes occur at each bit and calls 'ping' on that ip.
- If the length of the index list is 1 then we know that only the outer bit has changed, etc.
- Loop through depending on the amount of change at that index.
- Append the live addresses to a list called 'success'. This will be used later.

### But why?
It is a simple and easy way to map devices on a network. However, generates a lot of noise. In the future I may want to look into scanning a network silently. 

## TCP Scan:
Now onto the TCP scan, this is another option in the scanning menu as it's a different way hosts can be detected, if pinging isn't viable for some reason.

My script probes common ports (which change depending on the operating system you are scanning) and if the connection comes back ok then the machine is live.

```python
def TCPScan(address,n,port): #function to set up tcp syn-ack handshake

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        if n==1:
                print("Windows discovery.")
                print("Trying connections on port " + str(port) +"...\n")
                result = s.connect_ex((address,port)) #connect to a common open port... should iterate through some so have more chance of finding an open port.
                if result ==0:
                        return 1
                else:
                        return 0
        else:
                print("Linux discovery.")
                print("Trying connections on port " +str(port)+"...\n")
                result=s.connect_ex((address,port))
                if result==0:
                        return 1
                else:
                        return 0

def runTCPScanner(indx,ranges,ip,n,port): #calls tcp scan depending on range and returns live hosts.
                windows=[135,137,138,139,445]
                linux=[20,21,22,23,25,80,111,443,445,631,993,995]
                #port is index and starts at 0
                if len(indx)==1:
                       for i in range(0,(ranges[0]+1),1):
                             address=str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(i)
                             print(address)
                             if n ==1:
                                  for x in windows:
                                        if (TCPScan(address,n,x)):
                                                print(str(address) + " is live.")
                                                if address not in success:
                                                        success.append(address)
                             else:
                                  for x in linux:
                                        if (TCPScan(address,n,x)):
                                                print(str(address) + "is Live.")
                                                if address not in success:
                                                        success.append(address)

                if len(indx)==2:
                       for i in range(0,(ranges[0]+1),1):
                             for x in range(0,(ranges[1]+1),1):
                                  address=str(ip[0])+'.'+str(ip[1])+'.'+str(i)+'.'+str(x)
                                  if n==1:
                                      for x in windows:
                                              if (TCPScan(address,n,x)):
                                                      print(str(address) + " is live.")
                                                      if address not in success:
                                                               success.append(address)
                                  else:
                                      for x in linux:
                                              if (TCPScan(address,n,x)):
                                                      print(str(address)+" is live.")
                                                      if address not in success:
                                                              success.append(address)


                if len(indx)==3:
                       for i in range(0,(ranges[0]+1),1):
                             for x in range(0,(ranges[1]+1),1):
                                  for y in range(0,(ranges[2]+1),1):
                                       address=str(ip[0])+'.'+str(i)+'.'+str(x)+'.'+str(y)
                                       if n==1:
                                               for x in windows:
                                                        if (TCPScan(address,n,x)):
                                                                  print(str(address) + " is live.")
                                                                  if address not in success:
                                                                          success.append(address)

                                       else:
                                              for x in linux:
                                                      if (TCPScan(address,n,x)):
                                                               print(str(address)+" is live.")
                                                               if address not in success:
                                                                       success.append(address)

                       return success

```

First, the TCPScan function takes in 3 arguments, the address to scan, the mystery variable?! 'n' and the port to probe.
The argument 'n' is just when the user chooses what OS to scan, it's 1 for windows and 2 for linux in this case.
This can be seen at the end of my rangecalc function earlier...

- The rest of this function should be pretty self explanatory, I use sockets to connect to the port and if a connection is successful it returns  1, else it returns 0. 

The next function runTCPScanner takes the variables from  the range calculation. This is the function that is called at the end of rangecalc depending on what option you choose. 

- I have 2 lists of ports, one for windows and one for linux. I iterate through the addresses in the same way that I did in the pingScan function. 

- The difference here is that I also iterate through the ports in the list PER address... this can be rather time consuming in some cases but it is thorough. 

- If the address is live and not already in the list of live addresses, add it to the list.

### But why?
Some firewall rules may prevent you from pinging machines properly, this gets around **SOME** firewall restrictions. So when pingscan can't be used, this can be used instead. Adds more options to the users for enumeration.

## SNMP Enumeration: 
This is an interesting one. SNMP stands for "Simple Network Management Protocol" and is used in large networks with many users by administrators to do network monitoring. This protocol can contain some very interesting and useful information... 

A successfully decoded SNMP request is then authenticated using the community string. Therefore, for the project example I already know the community string. Think of this as a password. In the future, I would try to implement a feature to try and brute force the community string. 

My function uses OIDs (Object Identifier) to get the information we need. This changes per OS so I have the option for linux and windows OIDs. An OID looks like some numbers separated by dots. 

For example, the start of an OID may look something like `1.3.6.1.4.1...`


| Number | Label | Explanation | 
| -------- | :-------: | -----------: |
| 1 | iso | establishes that this is an OID. All OIDs start with 1 |
| 3 | org | Used to specify the organization that built the device. |
| 6 | dod | Department of Defense which is the organization that established the Internet first. |
| 1 | internet | To denote that all communications will happen through the Internet. |
| 4 | private | Determines that this device is made by a private organization and not a government one. |
| 1 | enterprise |  This value denotes that the device is made by an enterprise or a business entity. |

You may be able to make your own OIDs but I stuck with some OS specific ones that I can just chuck in and use. 

```python
def snmpEnum(ip,n):
        systemInfo="iso.3.6.1.2.1.1"
        RunningProcesses="1.3.6.1.2.1.25.4.2.1.2"
        InstalledSoftware="1.3.6.1.2.1.25.6.3.1.2"
        Hostname="1.3.6.1.2.1.1.5"
        Users="1.3.6.1.4.1.77.1.4.1"
        LinuxProcesses="1.3.6.1.2.1.25.4.2.1.2"
        LinuxsysInfo="1.3.6.1.2.1.1"
        LinuxHostname="1.3.6.1.2.1.1.5"

        cmd_gen=cmdgen.CommandGenerator()
        comm_data=cmdgen.CommunityData('public','public',1)
        transport=cmdgen.UdpTransportTarget((ip,161))

        startWalk=getattr(cmd_gen,'nextCmd')

        res = (errorIndication, errorStatus, errorIndex, varBinds) = startWalk(comm_data,transport,systemInfo)


        if not errorIndication is None or errorStatus is True:
        #if i!=len(snmp_communities):
        #i=i+1

            print("No SNMP found!")
        else:
            os.system('clear')

            #print("COMMUNITY STRING " + str(comm_data) + " FOUND\n")
               #print("USING OID "+OID+"\n")
            if n==1:
                    print("------------------ SYSTEM INFO ------------------\n")
                    pprint(varBinds)
                    res=(errorIndication,errorStatus,errorIndex,varBinds)=startWalk(comm_data,transport,RunningProcesses)
                    print("\n------------------ RUNNING PROCESSES -------------\n")
                    pprint(varBinds)
                    res=(errorIndication,errorStatus,errorIndex,varBinds)=startWalk(comm_data,transport,InstalledSoftware)
                    print("\n----------------- INSTALLED SOFTWARE ---------------\n")
                    pprint(varBinds)
            if n==2:
                    print("----------------- SYSTEM INFO ---------------------\n")
                    res=(errorIndication,errorStatus,errorIndex,varBinds)=startWalk(comm_data,transport,LinuxsysInfo)
                    pprint(varBinds)
                    print("------------------- RUNNING PROCESSES ----------------\n")
                    res=(errorIndication,errorStatus,errorIndex,varBinds)=startWalk(comm_data,transport,LinuxProcesses)
                    pprint(varBinds)

```

Ok so I have the different OIDs set at the top as strings. 
I use `from pysnmp.entity.rfc3413.oneliner import cmdgen` to do the SNMP walk.
- set the community data string
- set the target ip and snmp port
- Start SNMP walk
- Print info depending on operating system and OIDs used. 

You may  be wondering what is an "snmp walk" ? 

SNMPWALK is an SNMP application that uses SNMP GETNEXT requests to query a network device for information. 

### But why?
It allows us to see some useful info.

When enumerating a target, you may not know what information you need until you give it a context where it becomes useful. So it is good to collect all the info you can, even if it may not be obviously useful at first :)

Gives yet another way to get info from a network or devices on that network.

## MAC address changer:
I also added some functions that allow you to change your MAC address.

```python 
def changeMACrand(interface):
# changing mac helps our device remain anonymous
        getCurrentMAC('eth0')
        random_mac="02:00:00:%02x:%02x:%02x" % (random.randint(0,255),random.randint(0,255),random.randint(0,255))
        subprocess.call(["sudo","ifconfig", interface, "down"])
        subprocess.call(["sudo","ifconfig", interface, "hw", "ether", random_mac])
        subprocess.call(["sudo","ifconfig", interface, "up"])
        global RANDOM_MAC
        RANDOM_MAC= random_mac
def changeMACinput(interface):
        getCurrentMAC('eth0')
        print("CAUTION... MAKE SURE YOU KNOW WHAT TO CHANGE IT TO, COULD BREAK THINGS!")
        input_mac=raw_input("Enter MAC: ")
        subprocess.call(["sudo","ifconfig", interface, "down"])
        subprocess.call(["sudo","ifconfig",interface,"hw","ether",str(input_mac)])
        subprocess.call(["sudo","ifconfig",interface,"up"])
        print("Changed MAC to: " + str(input_mac))
        return
def getCurrentMAC(interface):
        current_mac=get_mac_address(interface=interface)
        print("Current MAC is: " + str(current_mac))
        with open("backup_mac.txt","a") as myfile: #in case things go wrong...
                myfile.write(str(current_mac+"\n"))
```

- First of all, the _changeMACrand_ function changes the devices MAC address to a random one. 
- For the changeMAC functions, I use subprocesses to do commands on the local machine. It simply takes the interface we want down, changes the mac address and brings it back up again.
- The _changeMACinput_ function changes the mac address based on user input.
- The _getCurrentMAC_ function gets the MAC address that is currently set and saves it to a backup file. This is used in case anything goes wrong and we need to change a MAC address back to a previous one.

### But why?
This allows us to stay anonymous on the network and may have other uses depending on the type of network used. 
Being able to enter a known mac may allow you to spoof a mac address of another host on a network which can lead to more enumeration opportunities. In the future we may be able to implement a MiTM (man in the middle) attack with this functionality.

I also made this function that gets the MAC addresses of active hosts on the network and puts them in a list. In the future, we could use this to have an option where a user can enter the MAC address they want to change to by selecting it from the list instead of entering it manually...

```python 
def getMAC(ip_list):
        mac_list=[]
        for i in range(0,len(ip_list)):
                ip_mac=get_mac_address(ip=str(ip_list[i]))
                mac_list.append(ip_mac)
        print(mac_list)
        return mac_list
        
 ```
## Network Sniffer:
I implemented a little network sniffing function that sniffs for IP packets in the network and shows us the source and destination IPs of those packets.
 
 ```python
 def sniff_packets():
         sniff(filter="ip",prn=ip_packets)

def ip_packets(packet):
        if IP in packet:
                ip_src=packet[IP].src
                ip_dst=packet[IP].dst

        print(str(ip_src) +" -> " + str(ip_dst))
```

- The sniff packets function is called from one of my menus. This uses the sniff function from the scapy library.
- It needs a filter for the type of packet and a function, I pass it the IP packet type and the ip_packets function.
- The ip_packets function takes the souce and destination IPs from the packets and prints them.

At the moment the sniffer is quite basic but could still yield some useful info. In the future I may implement an option to sniff for different types of packets and perhaps I can find a way to print more useful info... I may also make it so that it saves the output to a file for later examination. We could store these files on an FTP server if we get that working. 

### But why?
Seeing how often devices communicate and who talks to who on a network could provide us with some good information on mapping the network out. We may be able to tell which devices are the most active etc. 

## ARP Spoofer:
This ARP spoofer redirects the network traffic to the us by faking the IP address.
So we can impersonate someone on the network and listen in perhaps...
Once this works, the router will send the data to the beaglebone instead of the system, and the system will send the data to the beaglebone instead of the router.

```python
def enable_linux_iproute():
        print("Enabling ip routing...")
        file_path="/proc/sys/net/ipv4/ip_forward"
        with open(file_path) as f:
                if f.read()==1:
                         return
        with open(file_path,'w') as f:
                f.write('1')

def spoof(target_ip,host_ip,target_mac):
        arp_response = ARP(pdst=target_ip, hwdst=target_mac,psrc=host_ip, op='is-at')
        send(arp_response)
        print("Sent to " + str(target_ip) +" -> " + str(host_ip))

def restore(target_ip,host_ip,target_mac,host_mac):
        arp_response= ARP(pdst=target_ip,hwdst=target_mac,psrc=host_ip,hwsrc=host_mac)
        send(arp_response,count=7)
        print("Sent to : " + str(target_ip) + " -> " + str(host_ip))
        
```

- First we enable iproute on our beaglebone, IP forwarding is the ability for an operating system to accept incoming network packets on one interface, recognize that it is not meant for the system itself, but that it should be passed on to another network, and then forwards it accordingly.

- The spoof function is where the actual arp spoofing takes place. It gets the MAC address of the target, crafts the ARP response packet and then sends it.

- Once we want to stop the attack, we need to re-assign the real addresses to target device. In order to ensure it isn't obvious that something bad has happened, we send seven legitimate ARP reply packets so no one is disconnected from the network. 

### But why?
This arp spoofer allows us to listen to what is being sent on the network, we may be able to sniff some info such as usernames/passwords or websites visited etc. 
I am currently making a http packet sniffer to use once an arp spoof has taken place but it needs testing... I am unable to test if this works since we need a network connected to the internet. :( 

However, the code is here:

```python
def http_header(packet):
        if packet.haslayer(HTTPRequest):
                url=packet[HTTPRequest].Host.decode()+packet[HTTPRequest].Path.decode()
                ip = packet[IP].src
                method = packet[HTTPRequest].Method.decode()
                print(str(ip) + " requested " + str(url) + " with " + str(method))
```
It may be useful to see how I call these functions since some of them require some arguments from earlier in the program. 

```python
 if n==7:
                        os.system('clear')
                        i=0
                        print("IP's : " + str(success))
                        ip_choice=input("Enter index of target ip: ")
                        arp_target=str(success[ip_choice])
                        arp_host = get_ip_address('eth0')
                        target_mac= get_mac_address(ip=arp_target)
                        print("MAC of target is: " + str(target_mac))
                        host_mac= get_mac_address(interface='eth0')
                        enable_linux_iproute()

                        while(i!=1):
                                try:

                                        spoof(arp_target,arp_host,target_mac)
                                        spoof(arp_host,arp_target,host_mac)
                                        time.sleep(1)
                                except KeyboardInterrupt:
                                        arp_done=1
                                        i=1
                if n==8 and arp_done ==1 :
                        print("Restoring Network...")
                        restore(arp_target,arp_host,target_mac,host_mac)
                        restore(arp_host,arp_target,host_mac,target_mac)
                if n==9:
                        os.system('clear')
                        sniffer_menu()
                elif n==8 and arp_done ==0:
                        print("ARP spoof hasn't been done yet...")
```

- For the arp spoofing, I call spoof twice but switch host and target around. 
- If there is a keyboard interrupt then break out and return to the menu
- You can only restore addresses from arp spoof if you have done it first. It checks if the arp spoof is done and if it is, it lets you restore.
- Other option calls the menu for network sniffing...



## Banner Grabber:
Added a banner grabber, grabs banners for services running on open ports on a target machine and prints them. 
```python
def bannergrabbing(address,portlist):
        print("\n-------------------------------\n")
        for i in range(0,len(portlist)):
                port=portlist[i]
                print("Getting service info for: " + str(port))
                socket.setdefaulttimeout(2)
                bannergrab=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                try:
                        bannergrab.connect((address,port))
                        bannergrab.send('WhoAreYou\r\n')
                        banner=bannergrab.recv(100)
                        bannergrab.close()
                        print(str(banner) + "\n")
                except:
                        print("Can't connect to port: " + str(port))
```
- Gets open ports by port scanning the target ip with the brute force function, that tries all possible ports.
- Takes in the ip of the machine and a list of open ports.
- Loops through each open port and tries to retrieve the banner
- Does this by sending any data e.g. whoareyou, and recieving whatever comes back.

### But why?
This will allow us to see what services are running on what ports. However, it can be easily disabled. This is an easy way to do it without packet crafting, in some cases it could also expose some vulnerable versions of services running that could be exploited.

The way I call it in the menu can be a bit confusing, so I will show it here:
```python
 print("Detected IP addresses are: " + str(success))
 ip_choice=input("Enter the index of target ip: ")
 bannertarget=str(success[ip_choice])
 bannergrabbing(bannertarget,Portscan(success[ip_choice],2))
```

- Gets user input for the target ip for the banner grabbing.
- Gets openports by calling the portscan function with the target ip and the second choice which is the brute force option.


## The Menus:
I also wrote the code for the menus that allow the program to function smoothly.
I will put them here so you have a more complete idea of the program.

```python
def scanMenu(ip,netmask): #can choose what type of scan you want to do for host discovery.
        n=0
        while(n!=5):
               print("1) Ping Scanner \n" + "2) TCP Scan \n" + "3) Change MAC address \n" + "4) Packet sniffer? \n" + "5) Quit \n" )
               n=input("choice--> ")
               if n==1:
                     range_calculator(ip,netmask,n)
                     menu(success)
               if n==2:
                     range_calculator(ip,netmask,n)
                     menu(success)
               if n==3:
                     changeMACmenu()
                     #scanMenu(ip,netmask)
               if n==4:
                     sniffer_menu()
                     
```
                       
The scan menu is the first menu that is called after the range calculation function is done. This presents the option that the user can take to further enumerate the network.

```python
def menu(success): #once the pings are done, a menu opens with different options...
        #range_calculator(ip,netmask)
        '''given a choice, can perform different recon tasks.'''
        arp_done = 0
        n=0
        while n!=11:
                print("The following ip's have been detected: " + str(success) + "\n")
                print("---------------------------------------------------------")
                print("What would you like to do next? ")
                print("1) Port Scan \n")
                print("2) Probe for anon FTP \n")
                print("3) SNMP Enumeration\n")
                print("4) OS Detection\n")
                print("5) MAC  address discovery\n")
                print("6) Change MAC address \n")
                print("7) ARP Spoofer \n")
                print("8) Re-assign addresses after ARP spoof \n")
                print("9) Network Sniffer \n")
                print("10) Banner Grabbing \n")
                print("11) Quit \n")
                n = input("Choice --> ")

                if n==1: #should be able to choose an ip from the list of successful pings and scan it specifically...
                        os.system('clear') #clears screen so doesnt get crowded...
                        print("Which IP you want to run a port scan on?\n")
                        print(success)
                        choice=input("Input ip list index: ") #choose index of  list of ip's.
                        ip_menu=success[int(choice)]
                        print("Choose what port scan you want to do: \n")
                        print("1) Top 20 scan\n")
                        print("2) Brute force (scan all ports\n")

                        n=input("choose --> ")
                        Portscan(ip_menu,n)

                if n==2:
                        os.system('clear') #clears screen so doesnt get crowded...
                        print("FTP stuffs...\n")
                        print(success)
                        choice=input("Input ip list index: ")
                        ip_menu=success[int(choice)]
                        checkFTP(str(ip_menu),21)

                if n==3:
                        os.system('clear') #clears screen so doesnt get crowded...
                        print(success)
                        choice=input("Input ip list index: ")
                        ip_menu=success[int(choice)]
                        n=input("Enter 1 for windows enum and 2 for linux: ")
                        snmpEnum(str(ip_menu),n)
                if n==4:
                        os.system('clear')
                        print(success)
                        choice=input("Input ip list index: ")
                        ip_menu=success[int(choice)]
                        #AD OPEN PORT ARRAY, DECLARE AS GLOBAL VAR AND PASS TO FUNCTION. LOOP THRU.
                        os_detection(ip_menu)
                if n==5:
                        os.system('clear')
                        #getMAC(success)
                        print("IP addresses: " + str(success))
                        print("MAC addresses: " + str(getMAC(success)))
                if n==6:
                        os.system('clear')
                        print("MAC addresses: " + str(getMAC(success)))
                        changeMACmenu()
                if n==7:
                        os.system('clear')
                        i=0
                        print("IP's : " + str(success))
                        ip_choice=input("Enter index of target ip: ")
                        arp_target=str(success[ip_choice])
                        arp_host = get_ip_address('eth0')
                        target_mac= get_mac_address(ip=arp_target)
                        print("MAC of target is: " + str(target_mac))
                        host_mac= get_mac_address(interface='eth0')
                        enable_linux_iproute()

                        while(i!=1):
                                try:

                                        spoof(arp_target,arp_host,target_mac)
                                        spoof(arp_host,arp_target,host_mac)
                                        time.sleep(1)
                                except KeyboardInterrupt:
                                        arp_done=1
                                        i=1
                if n==8 and arp_done ==1 :
                        print("Restoring Network...")
                        restore(arp_target,arp_host,target_mac,host_mac)
                        restore(arp_host,arp_target,host_mac,target_mac)
                if n==9:
                        os.system('clear')
                        sniffer_menu()
                elif n==8 and arp_done ==0:
                        print("ARP spoof hasn't been done yet...")
                if n==10:
                         os.system('clear')
                         print("Detected IP addresses are: " + str(success))
                         ip_choice=input("Enter the index of target ip: ")
                         bannertarget=str(success[ip_choice])
                         bannergrabbing(bannertarget,Portscan(success[ip_choice],2))
                         
```

This is the main menu function that is called after any of the host scanning options are selected in the scan menu before.
This is where most of the additional enumeration takes place. 
It takes in the list  of active hosts on the network (success) that was appended to from one of the scanning functions on the scan menu.

```python
def changeMACmenu():
        n=0
        while n!=3:
                n=input("1) Change to Random MAC address\n2) Input your own MAC address\n3) Quit \n")

                if n==1:
                        changeMACrand('eth0')
                if n==2:
                        changeMACinput('eth0')
                        
```

This is the MAC address functions menu that is called once you select it from the main menu. You can choose to either change your MAC address to a random value or to one based on user input. 

```python 
def sniffer_menu():
        n=0
        while n!=3:
               n=input("1) Sniff source and dest IPs\n2) Sniff HTTP-GET requests\n3) Quit \n")
               if n==1:
                       sniff_packets()
               if n==2:
                       sniff_http()
                       
                       
```

The sniffer menu is called from the main menu once you select the network sniffer option. It then calls the relevant functions. You can go back between the menus easily due to the way I coded it but if you back out to the scan menu, you will have to scan the network again before you get back to the main menu function. Perhaps in the future we could have added an option where if the success list is already populated and you're in the scan menu function, it will ask if you want to scan again or if you want to skip to the menu function...


