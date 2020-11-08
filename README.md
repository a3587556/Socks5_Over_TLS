# Socks5_Over_TLS_And_chacha20-ietf-poly1305
Socks5 over TLS and chacha20-ietf-poly1305 With Python 

Dependencies

python 2.6 - 2.x

pip >= 20.x

gevent

libsodium

========================================================================

Installation

Mac OS:

pip install gevent

brew install libsodium

========================================================================

Debian/Ubuntu:

pip install gevent

apt-get install libsodium-dev -y

========================================================================

CentOS:

pip install gevent

yum install epel-release -y

yum install libsodium -y

========================================================================

Windows:

install vc runtime library 2013 x86 or x64(libsodium version: x86->Win32, x64->x64)
https://support.microsoft.com/en-us/help/4032938/update-for-visual-c-2013-redistributable-package or
https://www.itechtics.com/microsoft-visual-c-redistributable-versions-direct-download-links/#Visual_C_Redistributables_Direct_Download_Links


if you use python client script:

unzip libsodium-1.0.13-msvc.zip  and put libsodium-1.0.13-msvc/Win32/Release/v120/dynamic/* copy to C:\Windows\SysWOW64 or C:\Windows\System32

  if it not work, you can try this:
    unzip libsodium-1.0.13-msvc.zip and put libsodium-1.0.13-msvc/x64/Release/v120/dynamic/* copy to C:\Windows\System32 

if you use exe program:

unzip libsodium-1.0.13-msvc.zip  and put libsodium-1.0.13-msvc/x64/Release/v120/dynamic/* copy to C:\Windows\System32 or C:\Windows\SysWOW64



========================================================================

Usage

server:

modify the path of certfile and keyfile in server.py

server.py l:0.0.0.0:443

------------------------------------------------------------------------

linux:

client.py -l:port -c:host:port

------------------------------------------------------------------------

Windows:

client.exe -l:port -c:host:port
