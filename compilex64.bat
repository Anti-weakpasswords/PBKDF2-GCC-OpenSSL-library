rem this is the path to your OpenSSL binary installation
rem you can find binary distributions for Windows at: https://www.openssl.org/related/binaries.html
rem MinGW x86 (32-bit) or x64 (64-bit) is required to compile
rem libeay32.dll from OpenSSL is required to run.
gcc -O3 -I "c:\OpenSSL-Win64\include" -L "C:\OpenSSL-Win64" -leay32 pbkdf2_openssl.c -o pbkdf2
