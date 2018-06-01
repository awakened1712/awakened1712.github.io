---
title:  "Install a trusted CA in Android N"
date:   2018-06-01 12:24:15 +0800
categories: Hacking
classes:
  - landing
header:
  teaser: /assets/img/android.png
---

It’s very trivial to install a user-trusted certificate on Android. Under Settings -> Security you can install new trusted certificates. However, this creates a permanent "Your network could be monitored" warning in your task tray and forces you to have a lock-screen. In addition to this, [apps that target API Level 24 and above no longer trust user or admin-added CAs for secure connections, by default](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html).

This guide shows how to install a system-trusted CA certificate. Most of the steps are referenced from [Installing a new trusted SSL root certificate on Android](https://jamie.holdings/2016/09/04/Installing-a-new-trusted-SSL-root-certificate-on-Android.html), excep that this guide is adapted to generate only 730-day certificates to deal with error `NET::ERR_CERT_VALIDITY_TOO_LONG` in Chrome

### Generate
```bash
openssl req -x509 -days 730 -nodes -newkey rsa:2048 -outform der -keyout server.key -out ca.der -extensions v3_ca
```
### Convert the private key
```bash
openssl rsa -in server.key -inform pem -out server.key.der -outform der
openssl pkcs8 -topk8 -in server.key.der -inform der -out server.key.pkcs8.der -outform der -nocrypt
```
### Convert the public key
```bash
openssl x509 -inform der -in ca.der -out ca.pem
openssl x509 -inform PEM -subject_hash_old -in ca.pem | head -1
cp ca.pem a58355c2.0
openssl x509 -inform PEM -text -in ca.pem -out /dev/null>> a58355c2.0
```

### Copy the cert to the phone
```bash
adb push a58355c2.0 /data/local/tmp
adb shell
```
In the adb shell
```bash
su
mount -o rw,remount /system
mv /data/local/tmp/a58355c2.0 /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/a58355c2.0
chmod 644 /system/etc/security/cacerts/a58355c2.0
reboot
```

### Import the cert into BurpSuite
Go to the proxy settings page and choose "Import / Export CA Certificate" -> "Import" -> "Certificate and priate key in DER format"

![Import the cert into BurpSuite BurpSuite](https://raw.githubusercontent.com/awakened1712/awakened1712.github.io/master/assets/img/burp.png)
