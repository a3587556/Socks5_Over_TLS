# Socks5_Over_TLS
Socks5 Over TLS with Python

Mac OS:

pip install gevent

client.py -l:port -c:host:port

Windows:

Libsodium can be downloaded from https://download.libsodium.org/libsodium/releases/

For eg. https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-msvc.zip
Extract the files from the zip file

There are two extracted directories: x64 and Win32. Select x64 for 64-bit or Win32 for 32-bit versions of Windows, and search for libsodium.dll. You can find one inside Release/v141/dynamic/libsodium.dll

Copy this libsodium.dll file and paste it in C:\Windows\system32


Usage: client.exe -l:port -c:host:port
