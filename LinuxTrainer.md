The Linux Trainer was used as an introduction to linux during the first few weeks at Uni. These are the tasks we had to complete and how I did them. These tasks gave me a broader understanding on how to use Linux and what can be possible. 

> Level 0 
* :q to get out of vi file, level 1 pass is c341b271f5dba18dd4099435670a2c74
> Level 1
* man level 1 , level2 pass is 5c2c8ec6462a8ffb80d30bf8e5d56a29
> Level 2
* use /{word} to search through a man page, level 3 pass is 2166a44ff9d66344b371656ad62ed570
> Level 3
* Same as level 2, pass for level 4 is c0c421b993859d9697e058a9ebc3a01c
> Level 4 
* Search for man page containing "Adderbury"
* apropos command searches manpages for keywords. Use apropos "Adderbury"
* Level 5 password is cab0801f1e662b9f382ecf78cdd1609b
> Level 5
* Use cat command on password file, pass for level 6 is e3f20995ffa525dd9f85966813bf1ef7
> Level 6
* The Password for Level7 is in the Spaces Have No Place in FileNames.txt file in the home directory
* use / to escape spaces --> cat Spaces\ Have\ No\ Place\ In\ Filenames.txt
* Password for level 7 is a5c2b44a9f8c21d2e1bc8ef449ff49ad
> Level 7 
*  The Password for Level 9 is in the -Another Silly -Name.txt
* Put '--' before name to escape hyphens.
* cat -- -Another\ Silly\ -Name.txt
* Pass for level 8 is 78b6c29509af1e86b1abecf9f0ef126c
> Level 8 
* At start of big text file, use head command and control amount of lines with -n
* head textfile.txt -n 50
* Level 9 pass is fa0d9a03c23ceeedc7ced507d5c37d9f
> Level 9 
* pwd, cd .. to prev directory
* level 10 pass is f3a643dd575af9baeb1ba1d032959358
> Level 10
* cd to different directory and cat file
* level 11 pass is a6e10027186a4a360c3ca27e58d75968
> Level 11
*  The password for the next level is split over 3 files, which need to be combined in the following order

       o file11_1.txt Which lives in the root of the filesystem

       o file11_2.txt Which lives in level11's home directory

       o file11_3.txt Which lives in /opt/Level11Stuff/Foo/

* Output of files can be combined with 'cat file1.txt file2.txt file3.txt'
*  cat /file11_1.txt file11_2.txt /opt/level11Stuff/Foo/file11_3.txt
* Pass for level 12 is e3cb9dac40a829e5d0194b8fadc5ea0b
> Level 12
* use history command
* cat /var/local/L12Pw.txt
* level 13 pass is 0fc1d6918da0bacc7d8b3dcbf25853ad
> Level 13
* Search history for an echo command
* Use grep with history command
* history | grep echo
* level 14 pass is bf07d664ee94c602474868869e31e5a4
> Level 14
* use ls
* level 15 pass is 697508bad63a602679c9425778ac0faf
> Level 15
* use ls -la , a for hidden files and l to show more info about them
* lvl 16 pass is 468c7152da29221bcac4a40df02ef387
> Level 16
*  The password for the next level is:

       o A configuration file (IE has the conf extension)

       o Owned by the Levels User

       o Readable by the Owner and Group

       o Writable by the Owner

       o Executable by all users
*  [Permissions] [Size] [Owner] [Group] [Date] [Filename]
* cat file3.conf, has rw for owner and group, x means executable by all users, .conf file etc..
* level 17 pass is 4112b747ff854154ff38e271ee6ecdcb
> Level 17
* ---s--x--x 1 elev17  level17 16624 Apr 23  2019 runme4
* run runme4 script
* Has SUID and exec perms
* level 18 pass is 0ad360e45e0ab518ed1c01dc5bfdde20
> Level 18
       o The file calls the command cat to access a file

       o The file we are accessing is hard coded

       o The location of the cat command is not hard coded
* runme has SUID perms
* make cat file in current dir
* echo $PATH --> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* export PATH=./:$PATH
* echo $PATH --> ./:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* Linux will now check the current directory first for locations of programs (e.g. cat)
* Set cat to have exec permissions --> chmod +x cat
* ./runme
* use vim on password file because we are using cat command
* Level 19 pass is 84d284bda556887dfe827bb9ddba6cc1
> Level 19 
* Somewhere in the users home directory is a file called good.txt that contains the password for the next level.
* use find command
* find /home/level19 -name good.txt
* level 20 pass is 7c872534e89c245af242ee706c1980b6
> Level 20
 * The File with the password for level21 matches the following criteria:

       o Owned by Level 20

       o In the Root Group

       o Read and Executable Permissions for Owner and Group (IE 550)

       o File-size of 16568 bytes
* find / -group root -user level20 -perm 550 -size 16568c
* c means bytes 
* /home/level20/Dir14/Subdir4/file.dat
* meant to use file command to find out what type it was, file didnt exist
* use xxd to read hex 
* Password for Level21 is 04f534086cbedba7d729c796b686fcf2
> Level 21
*  So  far  we have been specifying the home directory (or .) as the path.  This time the program is hidden some-
       where in the file system

       o Owner: Level20

       o Group: Level21

       o Permissions:

         o Owner: Read, Execute

         o Group: Read

         o World: Read, Execute
* find / -group level21 -user level20   2> /dev/null
* 2>/dev/null used to redirect errors so we dont see the invalid ones.
* Level 22 pass is 1cf1aecffeae74b0ca176a741c9ef091
> Level 22
* Dont have permission to look at password file
* find / -perm /4000 2> /dev/null search for SUID files
* find / -perm /2000 2> /dev/null search for SGID files
* File belongs to elev22 user and group
* find / -group elev22 2> /dev/null search for files belonging to elev22 group
* Run finder script with the password file as argument
* Password for level 23 is 2bd1dadd7c844b746187d94b65d5f93c
> Level 23
* This time the password for the next level is hidden in data.txt
* Search inside the file for the string PW24: The password is the 32 character code between the : symbols
* grep PW24: data.txt -- > grep (word) (file)
* pass lvl 24 is 3dcae8f4fb8c2b8adfeabb8e6b61b668
> Level 24
*  Again the password is in data.txt this time it has the following format

       o 5 Lower case letters

       o 2 Numbers

       o 5 Upper case Letters

       o 2 symbols (or punctuation characters).

       o 2 numbers.

       IE aaaaa11AAAA$$11 would be a valid password.

* 
