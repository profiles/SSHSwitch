# SSHswitch
An iOS (jailbroken) command line tool for configuring the OpenSSH server, and starting/stopping it.

This is the heart of the [OpenSSH Settings](https://gitlab.com/blanxd/OpenSshPort) and [OpenSSH CC Toggle](https://gitlab.com/blanxd/OpenSshCC) tweaks, and it all started bundled as SSHonCC ("SSH Toggle and Port") in 2018, since there wasn't anything similar for iOS11 long after it got publicly jailbroken, like there used to be on earlier jailbreaks. And the 1st public jb for iOS11 had OpenSSH server forcibly installed without an option to turn it off so to me it actually felt like a security issue, because not everyone knows what it is in the 1st place so most were probably walking around listening for anyone to log in on the default port with the default password.

Documentation can be found in [doc/SSHswitch.md](doc/SSHswitch.md), this file is formatted for `pandoc` so some things might not look universally well in all circumstances, if processed by your generic MarkDown parsers/converters. Nicer files in many formats come with the actual package (in the Files.app : On My Iphone, and in (/var/jb)/var/mobile/Documents).

## Building
- By default this Makefile makes packages for rootless jbs (since SSHswitch ver.1.1.0). To package it for rootful environments, append RF=1 to the make commandline, eg. `make package FINALPACKAGE=1 RF=1`. The binary program itself works in both environments so it's the same in all cases.  
- The version number/string is always read from version.txt (written into the binary itself while compiling, and into the control file when packaging), the Makefile handles all that.  
- See comments in the c file about some bsd headers, which aren't being distributed with this project (**this could be called a requirement**).  
- Consult [doc/README.md](doc/README.md) about dependencies for generating the documentation files (only relevant for `make package`).  
- A recent [Theos](https://theos.dev/) is recommended (post 2023-03-26), but it also does the rootless job with older Theos versions.  

## Changelog
The [Changelog.md](Changelog.md) shows how it has evolved.  
Code wise, it started as a six function C++ tool (including main, and 2 copied straight from the author of the jb for patching setuid), it  started/stopped the sshd daemon and changed the port, as this was something I had earlier always done manually on my iOS devices. I hadn't written anything from scratch in neither C++ or C before this project (aside from some C snippets in some objC projects), so it has been learning more than anything, admittedly with a very specific goal.  
So I know that I know nothing about C yet, but I'm not too ashamed of it any more so let's go fully open source with ver.1.1.0 (doing that of course resulted in a massive cleanup and optimizations/fixes/etc, and I can still see a whole bunch of stuff that would need rewriting/improvements).

