In addition to the doc files in Files.app : On My iPhone/iPad  
and/or (/var/jb)/var/mobile/Documents  
(SSHswitch.txt, SSHswitch.pdf, SSHswitch.html)  
there are also standard CLI documentation files for 'man' and 'info'.

# MAN
- If you have man-db installed (some jbs / bootstrap repos have it), just type:
man SSHswitch
- Even if you install man-db later (after SSHswitch), it should start working automatically.


# INFO
- If you had texinfo installed (some jbs / bootstrap repos have it) when you installed SSHswitch, just type:
info SSHswitch

- Else if you install texinfo later (after SSHswitch), you should then manually register the SSHswitch documentation, the command would probably be (as root):  
install-info --dir-file=/usr/share/info/dir --info-file=/usr/share/info/SSHswitch.info  
    - in a rootless jb environment this would be:  
    install-info --dir-file=/var/jb/usr/share/info/dir --info-file=/var/jb/usr/share/info/SSHswitch.info
    - or else without registering it with the Info system, it just has to be manually fed to the info command each time, eg.:  
    info -f /var/jb/usr/share/info/SSHswitch.info
