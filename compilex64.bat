rem this is the path to your OpenSSL binary installation
rem you can find binary distributions for Windows at: https://www.openssl.org/related/binaries.html
rem MinGW x86 (32-bit) or x64 (64-bit) is required to compile
rem this example is for MinGW x64   x86_64-7.2.0-release-posix-seh-rt_v5-rev1
rem    Put the x86_64-7.2.0-release-posix-seh-rt_v5-rev1\mingw64\bin in the path
rem and OpenSSL 1.1.0g from https://slproweb.com/products/Win32OpenSSL.html
rem  And C:\OpenSSL-Win64\bin in the path
rem    OLD OLD OLD gcc -O3 -I "c:\OpenSSL-Win64\include" -L "C:\OpenSSL-Win64" -leay32 pbkdf2_openssl.c -o pbkdf2
"C:\x86_64-7.2.0-release-posix-seh-rt_v5-rev1\mingw64\bin\gcc" -O3 -I "c:\OpenSSL-Win64\include" -L "C:\OpenSSL-Win64\bin" -I "C:\x86_64-7.2.0-release-posix-seh-rt_v5-rev1\mingw64\bin" -llibssl-1_1-x64 -llibcrypto-1_1-x64  pbkdf2_openssl.c -o pbkdf2
