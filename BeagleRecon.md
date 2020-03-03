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

>Pings hosts and returns a list of the live ones.
>TCP scans the hosts by probing a common tcp port.
>Calculates the range of scannable ip's on the network depending on ip and netmask of eth0 interface...
>SNMP enumeration (limited functionality) 

### Range Calculator:
This has taken the most time and brainpower so far. What this part of the script does is automatically calculate the range of ip's it can scan and it does this by looking at the ethernet interface of the beaglebone, looking at the ip and subnet mask, then doing calculations on them.
