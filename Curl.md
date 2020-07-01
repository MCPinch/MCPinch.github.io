This was a series of tasks used as an introduction to Curl at Uni. Curl is a network tool used to transfer data to and from a server and can be valuable during the recon stage of an attack.

* Ran server in terminal
* Used 'curl 127.0.0.1:8090'
* Requested instructions page with 'curl 127.0.0.1:8090/instructions'
>  Need to make a simple request for the page called 'begin.xml' in the server root
* 'curl 127.0.0.1:8090/begin.xml'

>  Make POST request for /a.a 
* 'curl -X POST 127.0.0.1:8090/a.a' (-X request method to use)

> Request the page /data.php using the GET method passing in the parameter 'age' with a value of 45. 
* curl -X GET 127.0.0.1:8090/data.php?age=45
*  GET request doesn't use --data parameter 

> Make me an old fashioned request
* 'curl --http1.0 127.0.0.1:8090'

> This stage best viewed with 'zombobrowser'
* curl -A "zombobrowser" 127.0.0.1:8090
* -A changes user agent 

> Request the page /zip, sending the cookie called 'sugar' with the value 'AucVIAdE'
* curl --cookie 'sugar=AucVIAdE' 127.0.0.1:8090/zip

> Request the page /zip. It will send you a coookie. Send it back. Do it again.  And again. Keep going until I say otherwise.
* curl -c cookie.txt -b cookie.txt  127.0.0.1:8090/zip

* -c to get cookies from cookie jar, -b to send contents of file back to server
* Run command multiple times until cookies match
> Requ8est /whoami.php with user joe and password bloggs
* curl 127.0.0.1:8090/whoami.php -u joe:bloggs
* Should write like **user:pass**, -u command for authentication on a web page.
> Request the page /whoami.php again.  You need to log in using captured credentials, though.  I nabbed a header for you and it had the base64 encoded username/password: c2Nhcnk6YnVubnk=
* Base64 is scary:bunny
* curl 127.0.0.1:8090/whoami.php -u scary:bunny
> Sometimes, you want to minimise traffic using compression.  Make your next request for the page /gzipme to be returned with compression.
* curl --compressed 127.0.0.1:8090/gzipme
> OK, so you can get curl to send you gzipped data and you can have it decompress automatically.  Now ask for the page /zipgme, with compression.  Don't let curl automatically decompress the data.  Strip the first 32 bytes off it, then uncompress it (zlib/gzip) to find the URL of the page you need to request to move on.
* curl 127.0.0.1:8090/zipgme |python -c "import zlib, sys; print zlib.decompress(sys.stdin.read()[32:])"
* Got /sacrosanct
* curl 127.0.0.1:8090/sacrosanct

* pipe request output to python command
> For security purposes, please request the next page (/shizzle.pl) using SSL.  The server accepts secure connections on port 8091
* 
