CPUMiner-Multi optimized for Argon2
===================================

This is a multi-threaded CPU miner,
based on [Encel-US](//github.com/Encel-US/cpuminer-multi) fork of cpuminer, with [tpruvot](//github.com/tpruvot)'s enhancements (see AUTHORS for list of contributors), focused on Argon2.

Others algorithms based on scrypt WILL fail.

#### Table of contents

* [Algorithms](#algorithms)
* [Dependencies](#dependencies)
* [Download](#download)
* [Build](#build)
* [Usage instructions](#usage-instructions)
* [Donations](#donations)
* [Credits](#credits)
* [License](#license)

Algorithms
==========
#### Currently supported
 * ✓ __argon2__ (Argon2 [AR2])
 
Dependencies
============
 * libcurl http://curl.haxx.se/libcurl/
 * jansson http://www.digip.org/jansson/ (jansson source is included in-tree)
 * openssl libcrypto https://www.openssl.org/
 * pthreads
 * zlib (for curl/ssl)

Download
========
 * Windows releases: https://github.com/tpruvot/cpuminer-multi/releases
 * Git tree:   https://github.com/Miouyouyou/cpuminer-argon2
   * Clone with `git clone https://github.com/Miouyouyou/cpuminer-argon2`

Build
=====

#### Basic *nix build instructions:
 * just use ./build.sh
_OR_
 * ./autogen.sh	# only needed if building from git repo
 * ./nomacro.pl	# only needed if building on Mac OS X or with Clang
 * ./configure CFLAGS="*-march=native*" --with-crypto --with-curl
   * # Use -march=native if building for a single machine
 * make

#### PGO build with GCC
 * ./autogen.sh
 * ./configure CFLAGS="-O3 -march=native -fprofile-generate" LDFLAGS="-fprofile-generate"
 * make
 * ./cpuminer (With your usual arguments)
 * Let it run for a few minutes, then stop it
 * make distclean
 * ./configure CFLAGS="-O3 -march=native -fprofile-correction -fprofile-use" LDFLAGS="-fprofile-correction -fprofile-use"
 * make

This should generate a profiled version of cpuminer. You might squeeze 10% more performance with that kind of build.

#### Notes for AIX users:
 * To build a 64-bit binary, export OBJECT_MODE=64
 * GNU-style long options are not supported, but are accessible via configuration file

#### Basic Windows build with Visual Studio 2013
 * All the required .lib files are now included in tree (windows only)
 * AVX enabled by default for x64 platform (AVX2 and XOP could also be used)

#### Basic Windows build instructions, using MinGW64:
 * Install MinGW64 and the MSYS Developer Tool Kit (http://www.mingw.org/)
   * Make sure you have mstcpip.h in MinGW\include
 * install pthreads-w64
 * Install libcurl devel (http://curl.haxx.se/download.html)
   * Make sure you have libcurl.m4 in MinGW\share\aclocal
   * Make sure you have curl-config in MinGW\bin
 * Install openssl devel (https://www.openssl.org/related/binaries.html)
 * In the MSYS shell, run:
   * for 64bit, you can use ./mingw64.sh else :
     ./autogen.sh	# only needed if building from git repo
   * LIBCURL="-lcurldll" ./configure CFLAGS="*-march=native*"
     * # Use -march=native if building for a single machine
   * make

#### Architecture-specific notes:
 * ARM:
   * No runtime CPU detection. The miner can take advantage of some instructions specific to ARMv5E and later processors, but the decision whether to use them is made at compile time, based on compiler-defined macros.
   * To use NEON instructions, add "-mfpu=neon" to CFLAGS.
 * x86:
   * The miner checks for SSE2 instructions support at runtime, and uses them if they are available.
 * x86-64:	
   * The miner can take advantage of AVX, AVX2 and XOP instructions, but only if both the CPU and the operating system support them.
     * Linux supports AVX starting from kernel version 2.6.30.
     * FreeBSD supports AVX starting with 9.1-RELEASE.
     * Mac OS X added AVX support in the 10.6.8 update.
     * Windows supports AVX starting from Windows 7 SP1 and Windows Server 2008 R2 SP1.
   * The configure script outputs a warning if the assembler doesn't support some instruction sets. In that case, the miner can still be built, but unavailable optimizations are left off.

Usage instructions
==================
Run "cpuminer --help" to see options.

### Connecting through a proxy

Use the --proxy option.

To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host  
Protocols socks4a and socks5h, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the --proxy option is not used, the program honors the http_proxy and all_proxy environment variables.

Donations
=========
Donations for the work done in this fork are accepted :

Miouyouyou :
* BTC: `1LhaUEtzhNexchon1iY2oGQxJMajFLX2iQ`
* OPES: `oYhXjGUiKBVQ3Wqp6mhhPn9kHNEWszGF5v`
* AR2: `4hZJtUcZFofb9ipyafAqFNxvotFE2dns8e`

Tanguy Pruvot :
* BTC: `1FhDPLPpw18X4srecguG3MxJYe4a1JsZnd`
* ZRC: `ZX6LmrCwphNgitxvDnf8TX6Tsegfxpeozx`

Lucas Jones :
* MRO: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

Credits
=======
CPUMiner-multi was forked from pooler's CPUMiner, and has been started by Lucas Jones.
* [Encel-US](https://github.com/Encel-US) added the Argon2 algorithm
* [tpruvot](https://github.com/tpruvot) added all the recent features and newer algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight

License
=======
GPLv2.  See COPYING for details.
