# Socks5_Over_TLS_And_chacha20-ietf-poly1305
Socks5 over TLS and chacha20-ietf-poly1305 With Python 

Dependencies

python 2.6 - 2.x

gevent

libsodium

Installation

Mac OS:

pip install gevent

brew install libsodium

Debian/Ubuntu:

pip install gevent

apt-get install libsodium-dev -y

CentOS:

pip install gevent

yum install epel-release -y

yum install libsodium -y

Windows

unzip libsodium-1.0.13-msvc.zip  and put libsodium-1.0.13-msvc/Win32/Release/v120/dynamic/* copy to C:\Windows\System32 or C:\Windows\SysWOW64

install vc runtime library

Usage

linux:

client.py -l:port -c:host:port

Windows:

client.exe -l:port -c:host:port
