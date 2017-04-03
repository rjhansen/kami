# Kami 0.3

## What's a _kami_?
_Kami_ (Japanese, 神) roughly translates as spirit, ghost, or specter.

## So what's Kami?
I needed a name for a certificate inspector.  Certificate inspector, key 
spector... specter... _kami_.

Kami is a tool for analyzing your GnuPG keyring.  It provides vastly
more information about your certificates than many other tools do, going
so far as to allow you to easily discover not just what signatures are
on a certificate but even what algorithms were used in the signing.

## What are the system requirements?
* Windows Vista or later (both x86 and x64 supported)
* [.NET 4.5.2](https://www.microsoft.com/en-us/download/details.aspx?id=42642)
  or later
* [GnuPG 2.1.18](https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.1.19_20170328.exe)
  or later
* At least one certificate on your public keyring

## Do you have an installer for it?
Not yet.

## How can I check my download?
The executable code has a proper Authenticode signature on it.  The zipfile
also contains a detached GnuPG signature made by certificate 
```0x1DCBDC01B44427C7```, which is in the strong set.  Finding a trust path
to my cert is up to you, of course.

## How do I report bugs or request new features?
**Don't email these to me.**  GitHub has pretty nice bug and enhancement trackers.
Use those facilities instead.

## Is this Free Software?  Is this open-source?
It's free as in beer and free as in price.  It's released under the 2-clause BSD
license.  Share and enjoy.
