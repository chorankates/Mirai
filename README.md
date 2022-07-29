# [09 - Mirai](https://app.hackthebox.com/machines/Mirai)

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


## flag
```
user:
root:
```
