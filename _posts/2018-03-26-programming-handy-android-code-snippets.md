---
title:  "Handy Android code snippets"
date:   2018-05-18 17:22:33 +0800
categories: Programming
classes:
  - landing
header:
  teaser: /assets/img/android.png
---

This blog post is a memo of handy Android code snippets that I found particularly useful in programming and hacking.

### Execute a shell command as root
```java
public static String execRootCmd(String cmd) {
    String result = "";
    DataOutputStream dos = null;
    DataInputStream dis = null;
    try {
        Process p = Runtime.getRuntime().exec("su");
        dos = new DataOutputStream(p.getOutputStream());
        dis = new DataInputStream(p.getInputStream());
        dos.writeBytes(cmd + "\n");
        dos.flush();
        dos.writeBytes("exit\n");
        dos.flush();
        String line = null;
        while ((line = dis.readLine()) != null) {
            result += line;
        }
        p.waitFor();
    }
    catch (Exception e) {
    }
    finally {
        if (dos != null) {
            try { dos.close(); }
            catch (IOException e) { }
        }
        if (dis != null) {
            try { dis.close(); }
            catch (IOException e) { 
        }
    }
    return result;
}
```
