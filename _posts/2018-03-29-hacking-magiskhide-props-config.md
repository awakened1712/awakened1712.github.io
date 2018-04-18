---
title:  "MagiskHide Props Config"
date:   2018-04-18 12:44:33 +0800
categories: Hacking
classes:
  - landing
header:
  teaser: /assets/img/magisk.png
---

Even on a rooted Android phones, you won't be able to debug your apps if they are built as non-debuggable. In order to work around that, you need to somehow change the `ro.debuggable` attribute to 1. However, if you do that, an app can read `/default.prop` to detect that and stop operating. The solution is to use Magisk and its module called `MagiskHide Props Config`. More info on `MagiskHide Props Config` can be found at https://forum.xda-developers.com/apps/magisk/module-magiskhide-props-config-simple-t3765199

### Installation
Install through the Magisk Manager Downloads section.

### Usage
After installing and rebooting:
```
su
props
```
Then, choose `MagiskHide props` to change `ro.debuggable` to 1
