Working on a network recon tool that works with the BBB... This is a group project and I will outline how I managed to do my part.
The goal is to have a device you can plug into a network via Ethernet and it will map out devices on there and other useful enumeration things.

## Setting up the BeagleBone Black:
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

I use the pysnmp library for my script, so you need to pip install it (if pip is being annoying and giving you errors after you have updated, use `uninstall distributions` and it should work)

## The CODE:
Now onto the meaty part, the code!

I wrote code for the scanner that:

- Pings hosts and returns a list of the live ones.
- TCP scans the hosts by probing a common tcp port.
- Calculates the range of scannable ip's on the network depending on ip and netmask of eth0 interface...
- SNMP enumeration (limited functionality) 

### Range Calculator:
This has taken the most time and brainpower so far. What this part of the script does is automatically calculate the range of ip's it can scan and it does this by looking at the ethernet interface of the beaglebone, looking at the ip and subnet mask, then doing calculations on them.

First, I get the ip and netmask from eth0 with the following functions:
*I DO NOT KNOW HOW THESE WORK AND I DIDN'T WRITE THEM*

``` def get_ip_address(ifname):
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

def get_netmask(ifname):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x891b,struct.pack('256s',ifname))[20:24])
```
Then, I assign them a varibale and pass them to the range calc function.

```ip = get_ip_address('eth0')
netmask = get_netmask('eth0')
```

```def range_calculator(ip,netmask,choice):
        '''calculate range of ip addresses to scan'''

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

## Ping Scan:
Now that we have done all the fancy calculations, we need to figure out a way to process this information into something useful. In other words, how can i loop through each address for a given address range? 
I came up with the following solution:

```def Pingscan(indx,ranges,ip): #scans  a range of ip's that we can change... prints if the ping is successful or not.
        '''Pings the range of ip's depending on what range was calculated in the range calculation function. Returns a list of ip addresses of active machines.'''
        if len(indx) == 1:
                for i in range(0,(ranges[0]+1),1):
                        address=str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(i)
                        print("Trying "+ address)
                        res=subprocess.call(['ping','-c','1',address])
                        if res==0:
                                print("Ping to " + address + " ok") #maybe find a way to stop so much printing and also disclude our BBB's ip address from the list.
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
