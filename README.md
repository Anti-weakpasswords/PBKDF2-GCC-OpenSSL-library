PBKDF2-GCC-OpenSSL_Linux_Windows
================================

GCC and OpenSSL library based PBKDF2 implementation.  Works in Linux, as well as 32-bit and 64-bit Windows with MinGW.

You will need to have the OpenSSL libraries first - for Windows, see the link at https://www.openssl.org/related/binaries.html for the correct place to get them from.

For Linux, OpenSSL is almost always already installed, but if need be, something like "sudo apt-get install openssl" followed by "sudo apt-get install libssl-dev" should work on Debian.  Make sure to execute "sudo apt-get update" first, or if libssl-dev is not found (Debian 8 had this issue)

To compile on Windows, the easiest way is to install MinGW via the MinGW Builds installer, which can be found at http://sourceforge.net/projects/mingwbuilds/    (or, apparently, at links off of there since they've joined the overall MinGW-w64 project for both 32-bit and 64-bit Windows MinGW).

Windows was compiling working in 2017 with
  MinGW x64   x86_64-7.2.0-release-posix-seh-rt_v5-rev1
  Put the x86_64-7.2.0-release-posix-seh-rt_v5-rev1\mingw64\bin in the path
  OpenSSL 1.1.0g from https://slproweb.com/products/Win32OpenSSL.html - also in the path



Usage:
Example: pbkdf2 -a SHA-512 -p password -s salt -i 131072 -o 64

Options:
  -h                 help
  -v                 Verbose
  -a algo            algorithm, valid values SHA-512|SHA-384|SHA-256|SHA-224|SHA-1|SHA-1nat|MD5|NONE   Note that in particular, SHA-384 and SHA-512 use 64-bit operations which as of 2014 penalize GPU's (attackers) much, much more than CPU's (you).  Use one of these two if at all possible.  NONE is for testing the format options
  -p password        Password to hash
  -P passwordfmt     Password format, valid values hex|str|base64     default is str, i.e. string
  -s salt            Salt for the hash.  Should be long and cryptographically random.
  -S saltfmt         Salt format, valid values hex|str|base64     default is str, i.e. string
  -i iterations      Number of iterations, as high as you can handle the delay for, at least 16384 recommended.
  -o bytes           Number of bytes of output; for password hashing, keep less than or equal to native hash size (MD5 <=16, SHA-1 <=20, SHA-256 <=32, SHA-512 <=64)
  -O outputfmt       Output format, valid values hex|Hex|hexc|Hexc|base64|bin
                            - hex:            Lowercase Hex (default)
                            - HEX:            Uppercase Hex
                            - hexc:           Lowercase Hex, colon deliminated
                            - HEXC:           Uppercase Hex, colon deliminated
                            - base64:         Base64 single line RFC1521 MIME, PEM - extra chars + and /, padding =
                            - base64url:      Base64 single line URLsafe - extra chars - and _, padding =
                            - base64ML:       Base64 multi line RFC1521 MIME, PEM - extra chars + and /, padding =
                            - base64MLurl:    Base64 multi line URLsafe - extra chars - and _, padding =
                            - bin:            Binary (actual binary output)
  -e hash            Expected hash (in the same format as outputfmt) results in output of 0 <actual> <expected> = different, 1 = same NOT tested with outputfmt
  -n                 Interactive mode; NOT YET IMPLEMENTED
You must select a known algorithm identifier.
