Over xmas 2019, I took part in a CTF made by my university. The following are the challeneges I overcame and the things I learned whilst doing so.

*This is a Red Dward themed CTF, if you don't know what that is, I highly suggest you watch it*

## Science Room 1:
The first was a login screen that I had to find a way to get around...
[ScinceLabLogin](/SiteImages/CTFpics/Sciencelab1Login.png)
Turns out that this login form is vulnerable to a simple SQL injection attack.

Putting `admin' or '1'='1` in both boxes logged us in and gave us the flag!
This worked since 1=1 is always true so then the verification is never made, this should work if sql injection is possible.

## Science Room 2:
I am greeted with the same login screen as before, but something has changed...
[ScienceLab2Login](/SiteImages/CTFpics/Sciencelab2login.png)
Logging in the same way  as before gave me a clue for the user creds.
>Username is 'MrFlibble'
But what if I need the password?
Taking a look at the http-post form properties in source code, can see the data that is submitted with the form.
[ScienceLab2Form](/SiteImages/CTFpics/Sciencelab2postform.png)
The failure condition (text that appears when login fails) is "Login Fails" and we know the password is in the top 10k list.

With this information, we can craft a hydra query to brute force the password.
[Sciencelab2hydra](/SiteImages/CTFpics/Sciencelab2Hydra.png)
And woo hoo! We got the password 'midnight'

Now we can SSH into the machine with username mrflibble and password midnight.

[Rarityhappy](/SiteImages/tumblr_m4aapqcT8O1r3k1m8o6_500.png)

To get root, I used the `sudo -l` command to see what things I can run with elevated privileges...
[Sciencelab2Sudo](/SiteImages/CTFpics/Sciencelab2Sudo.png)
We are in luck! It seems we can run netcat with root privileges! 

Now all I needed to do was run the following command on the target machine and set up a listener on my own machine to get a reverse shell...

[ScienceLab2REV](/SiteImages/CTFpics/Sciencelab2RevShell.png)

And we got root! :) 

[Science2Root](/SiteImages/CTFpics/Sciencelab2Root.png)
