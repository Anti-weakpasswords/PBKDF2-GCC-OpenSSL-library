PBKDF2-GCC-OpenSSL_Linux_Windows
================================

GCC and OpenSSL library based PBKDF2 implementation.  Works in Linux, as well as 32-bit and 64-bit Windows with MinGW.

You will need to have the OpenSSL libraries first - for Windows, see the link at https://www.openssl.org/related/binaries.html for the correct place to get them from.  For Linux, OpenSSL is almost always already installed, but if need be, something like "sudo apt-get install openssl" should work on Debian. 

To compile on Windows, the easiest way is to install MinGW via the MinGW Builds installer, which can be found at http://sourceforge.net/projects/mingwbuilds/    (or, apparently, at links off of there since they've joined the overall MinGW-w64 project for both 32-bit and 64-bit Windows MinGW).
