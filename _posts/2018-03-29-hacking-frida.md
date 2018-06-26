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
    const System = Java.use('java.lang.System');
    const Log = Java.use("android.util.Log");
    const Exception = Java.use("java.lang.Exception");
    
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
    const System = Java.use('java.lang.System');
    const Log = Java.use("android.util.Log");
    const Exception = Java.use("java.lang.Exception");
    
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
### Convert IDA address to memory address and vice versa
```javascript
function memAddress(memBase, idaBase, idaAddr) {
    var offset = ptr(idaAddr).sub(idaBase);
    var result = ptr(memBase).add(offset);
    return result;
}

function idaAddress(memBase, idaBase, memAddr) {
    var offset = ptr(memAddr).sub(memBase);
    var result = ptr(idaBase).add(offset);
    return result;
}
```
### C: Hook HMAC function and print out the params
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
### C: Hook a static function by resolving its address
```javascript
const membase = Module.findBaseAddress('libtest.so');
const fstatat = memAddress(membase, '0x0', '0x69E238');
Interceptor.attach(fstatat, {
    onEnter: function (args) {
        console.log('[+] fstatat: ' + Memory.readUtf8String(args[1]));
        Memory.writeUtf8String(args[1], "/empty");
    },
    onLeave: function (retval) {
    }
});
```
### C: Print the backtraces of a list of functions
```javascript
const membase = Module.findBaseAddress('libtest.so');
const funcs = [ '0x21B248', '0x21D0C8', '0x234730', '0x23F718', '0x259E68' ];
for (var i in funcs) {
    var funcPtr = memAddress(membase, '0x0', funcs[i]);
    var handler = (function() {
        var name = funcs[i];
        return function(args) {
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            console.log(name + ': ');
            for (var j in trace)
                console.log(trace[j]);
        };
    })();
    Interceptor.attach(funcPtr, {onEnter: handler});
}
```
### C: Print the execution traces of a list of functions with Stalker
```javascript
const funcs = [ '0x870FF0', '0x871BA0' ];
const STALKED = 12345;
const STARTING_ADDRESS = "0x102FE0";
const ENDING_ADDRESS = "0x89BE04";
const base = Module.findBaseAddress('libtest.so');
var threads = [];
for (var i in funcs) {
    console.log('Hooking funcs[' + i + '] ' + funcs[i]);
    Interceptor.attach(memAddress(base, '0x0', funcs[i]), {
        onEnter: function (args) {
            var tid = Process.getCurrentThreadId();
            if (threads[tid] == STALKED)
                return;
            Stalker.follow(tid, {
                events: {
                    call: true, // CALL instructions: yes please
                    ret: false, // RET instructions: no thanks
                    exec: false // all instructions: no thanks
                },
                onCallSummary: function (summary) {
                    var log = []
                    for (i in summary) {
                        var addr = idaAddress(base, '0x0', i);
                        if (addr.compare(ptr(STARTING_ADDRESS)) >= 0 && addr.compare(ptr(ENDING_ADDRESS)) <= 0)
                            log.push(addr);
                    }
                    console.log(JSON.stringify(log));
                }
            });
            threads[tid] = STALKED;
        },
        onLeave: function (retval) {
            var tid = Process.getCurrentThreadId();
            if (threads[tid] == STALKED)
                return;
            Stalker.unfollow(tid);
            Stalker.garbageCollect();
        }
    });
}
```
### C: Invoke a libc function
```javascript
var openPtr = Module.findExportByName("libc.so", "open");
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
var fd = open('/tmp/test.txt', 0);
```
### Android: Hook C remove() function to save a files that is going to be deleted
```javascript
const File = Java.use("java.io.File");
const FileInputStream = Java.use("java.io.FileInputStream");
const FileOutputStream = Java.use("java.io.FileOutputStream");
const ActivityThread = Java.use("android.app.ActivityThread");
var name = 0;
Interceptor.attach(Module.findExportByName(null, "remove"), {
    onEnter: function (args) {
        path = Memory.readUtf8String(args[0]);
        Java.perform(function () {
            // create the input channel
            var f = File.$new(path);
            var fis = FileInputStream.$new(f);
            var inChannel = fis.getChannel();
            // create the output channet
            var application = ActivityThread.currentApplication();
            if (application == null)
                return;
            var context = application.getApplicationContext();
            var fos = context.openFileOutput('deleted_' + name, 0);
            name = name + 1;
            var outChannel = fos.getChannel();
            // transfer the file from the input channel to the output channel
            inChannel.transferTo(0, inChannel.size(), outChannel);
            fis.close();
            fos.close();
        });
    },
    onLeave: function (retval) {
    }
});
```
### iOS: Hook an Obj-C method
```javascript
const sendMessage = ObjC.classes.SecureStorage["- readFile:"];
Interceptor.attach(sendMessage.implementation, {
    onEnter: function(args) {
    },
    onLeave: function (retval) {
        var message = ObjC.Object(retval);
        console.log("- [SecureStorage readFile:] -->\n\"" + message.toString() + "\"");
    }
});
```
### Android: Hook constructor method of SecretKeySpec to print out the key byte array
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
### Android: Hook the library loading
```javascript
Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');

    System.loadLibrary.implementation = function(library) {
        try {
            console.log('System.loadLibrary("' + library + '")');
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };
    
    System.load.implementation = function(library) {
        try {
            console.log('System.load("' + library + '")');
            const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };
});
```

