---
title:  "Frida cheat sheet"
date:   2018-03-29 19:00:33 +0800
categories: Hacking
classes:
  - landing
header:
  teaser: /assets/img/frida.png
---

Frida is particularly useful for dynamic analysis on Android/iOS/Windows applications. It allows us to set up hooks on the target functions so that we can inspect/modify the parameters and return value. We can also alter the entire logic of the hooked function. This article shows the most useful code snippets for copy&paste to save time reading the lengthy documentation page.

## Frida python binding
Python binding to attach to an app:
```python
import frida, sys
 
ss = """
Java.perform(function () {
    // declare classes that are going to be used
    var System = Java.use('java.lang.System');
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");
     
    System.exit.implementation = function() {
        // console.log(Log.getStackTraceString(Exception.$new()));
    };
});
"""
device = frida.get_device_manager().enumerate_devices()[-1]
session = device.attach("com.gemalto.gmst.sample")
script = session.create_script(ss)
script.load()
sys.stdin.read()
```
Python binding to spawn an app:
```python
import frida, sys
 
ss = """
Java.perform(function () {
    // declare classes that are going to be used
    var System = Java.use('java.lang.System');
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");
     
    System.exit.implementation = function() {
        // console.log(Log.getStackTraceString(Exception.$new()));
    };
});
"""
device = frida.get_usb_device()
pid = device.spawn(["com.gemalto.gmst.sample"])
session = device.attach(pid)
script = session.create_script(ss)
script.load()
device.resume(pid)
sys.stdin.read()
```
Note that we need to load the script first before resuming if we need to perform early interception.

## frida-trace
Attach to Chrome app on an Android phone and trace two native functions open and strcmp
```
$ frida-trace -U -i open -i strcmp com.android.chrome
```
Launch SnapChat app on an iPhone and trace CommonCrypto API calls
```
$ frida-trace -U -f com.toyopagroup.picaboo -I "libcommonCrypto*"
```
Trace an Obj-C method of Safari app
```
$ frida-trace -U -m "-[NSView drawRect:]" Safari
```

## Common scripts
Hook HMAC function and print out the params
```javascript
Interceptor.attach(Module.findExportByName("liba.so", "HMAC"), {
    onEnter: function (args) {
        var keySize = args[2].toInt32();
        var keyDump = Memory.readByteArray(args[1], keySize);
        console.log('HMAC Key found at ' + args[1]);
        console.log('HMAC Key size = ' + keySize);
        console.log(hexdump(keyDump, { offset: 0, length: keySize, header: false, ansi: false }));  
    },
    onLeave: function (retval) {
    }
});
```
Hook a static function by resolving its address
```javascript
var fstatat = resolveAddress('liba.so', '0x0', '0x69E238');
Interceptor.attach(fstatat, {
    onEnter: function (args) {
        console.log('[+] fstatat: ' + Memory.readUtf8String(args[1]));
        Memory.writeUtf8String(args[1], "/empty");
    },
    onLeave: function (retval) {
    }
});
 
function resolveAddress(name, idaBase, idaAddr) {
    var baseAddr = Module.findBaseAddress(name);
    console.log('[+] BaseAddr of ' + name + ': ' + baseAddr);
      
    // Calculate offset in memory from base address in IDA database
    var offset = ptr(idaAddr).sub(idaBase);
      
    // Add current memory base address to offset of function to monitor
    var result = baseAddr.add(offset);
      
    // Write location of function in memory to console
    console.log('[+] Address in memory: ' + result);
    return result;
}
```
Android: Hook Java File.delete() method to save a files that is going to be deleted
```javascript
Java.perform(function () {
    var File = Java.use("java.io.File");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var AndroidAppHelper = Java.use('android.app.AndroidAppHelper');
    
    var name = 0;
    File.delete.implementation = function() {
        // create the input channel
        var fis = FileInputStream.$new(this);
        var inChannel = fis.getChannel();
        // create the output channet
        var context = AndroidAppHelper.currentApplication();
        var fos = context.openFileOutput('deleted_' + name, 0);
        name = name + 1;
        var outChannel = fos.getChannel();
        // transfer the file from the input channel to the output channel
        inChannel.transferTo(0, inChannel.size(), outChannel);
        fis.close();
        fos.close();
        return this.delete();
    }
});
```
iOS: Hook an Obj-C method
```javascript
var sendMessage = ObjC.classes.SecureStorage["- readFile:"];
Interceptor.attach(sendMessage.implementation, {
    onEnter: function(args) {
    },
    onLeave: function (retval) {
        var message = ObjC.Object(retval);
        console.log("- [SecureStorage readFile:] -->\n\"" + message.toString() + "\"");
    }
});
```
Android: Hook SecretKeySpec to print out the key byte array
```javascript
Java.perform(function () {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(p0, p1) {
        console.log('SecretKeySpec.$init("' + bytes2hex(p0) + '", "' + p1 + '")');
        return this.$init(p0, p1);
    };
});
function bytes2hex(array) {
    var result = '';
    console.log('len = ' + array.length);
    for(var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
}
```





