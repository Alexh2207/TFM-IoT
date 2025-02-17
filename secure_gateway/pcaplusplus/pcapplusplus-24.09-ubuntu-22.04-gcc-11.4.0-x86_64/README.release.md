September 2024 release of PcapPlusPlus (v24.09)
===============================================

PcapPlusPlus web-site:  https://pcapplusplus.github.io/

GitHub page:            https://github.com/seladb/PcapPlusPlus


This package contains:
----------------------

 - PcapPlusPlus compiled libraries (under `lib/`)
    - libCommon++.a
    - libPacket++.a
    - libPcap++.a
 - PcapPlusPlus header files (under `include/pcapplusplus/`)
 - Compiled examples (under `bin/`)
 - Code example with a simple CMake file showing how to build applications with PcapPlusPlus (under `example-app/`)
 - CMake files required to build your application with PcapPlusPlus (under `lib/cmake/pcapplusplus`)
 - pkg-config information you can use to build your application with PcapPlusPlus (under `lib/pkgconfig`)


Using PcapPlusPlus in your project:
-----------------------------------

 - If your application uses CMake, you can add `PcapPlusPlus_ROOT=<PACKAGE_DIR>` when running CMake, for example:
   `cmake -S . -B build -DPcapPlusPlus_ROOT=<PACKAGE_DIR>`
 - If your application uses Makefiles, you can use pkg-config with `PcapPlusPlus.pc`:
   1. Edit `PcapPlusPlus.pc` and replace `prefix` with the package path, for example:
      `prefix="<PACKAGE_DIR>"`
   2. Use pkg-config in your Makefile, for example:
      ```
      all:
         g++ `pkg-config --cflags PcapPlusPlus` -c -o main.o main.cpp
         g++ -o MyApp main.o `pkg-config --libs PcapPlusPlus`
      ```
   3. When running `make` remember to set pkg-config path so it can find `PcapPlusPlus.pc`, for example:
      `PKG_CONFIG_PATH=<PACKAGE_DIR>/lib/pkgconfig make`


Running the examples:
---------------------

 - Make sure you have libpcap installed (it should come built-in with most Linux distributions)
 - You may need to run the executables as sudo

Release notes (changes from v23.09)
-----------------------------------

- Added support for eBPF AF_XDP
- New protocols:
  - SMTP (thanks @egecetin !)
  - ASN.1 encoding and decoding
  - Enabled ASN.1 root record parsing in x509 certificates
  - LDAP
  - S7COMM (thanks @wivien19 !)
- DPDK improvements:
  - DPDK 22.11 support (thanks @clementperon !)
  - Jumbo frames support (thanks @gyl30 !)
  - Added an option to disable hugepages and driver verification on initialization (thanks @MatteO-Matic !)
  - NUMA awareness (thanks @SesomB !)
- Examples and utils:
  - Added `XdpExample-FilterTraffic` to demonstrate `XdpDevice` usage
  - `PcapSplitter`: updated output filenames with 5-tuple information (thanks @hidd3ncod3s !)
- Added support for nanosecond precision in reading and writing pcap files (thanks @egecetin !)
- Blocking mode packet capture now uses `poll()` (thanks @tigercosmos !)
- Added millisecond precision timeout in `RawSocketDevice` (thanks @tigercosmos !)
- Extended `IPFilter` to support IPv6 where possible (thanks @Dimi1010 !)
- Boosted build time with Ccache (thanks @clementperon !)
- Fixed precision issue in pcapng file reader (thanks @mserdarsanli !)
- Improved method for retrieving the default gateway on macOS (thanks @zhengfeihe !)
- Added security and code of conduct guidelines (thanks @egecetin !)
- Refactoring and modernization of the code base:
  - Refactored and cleaned up live devices (thanks @Dimi1010 !)
    - Added a getter for fetching all IP addresses as `IPAddress` objects.
  - Refactored IP address classes `IPv4Address`, `IPv6Address`, `IPAddress` (thanks @tigercosmos , @Dimi1010 !)
    - Added equality operators between `IPAddress` and `in_addr` types
  - Refactored the MAC address class `MacAddress` (thanks @tigercosmos !)
  - Ported PcapPlusPlus libraries to C++11 (thanks @Dimi1010 , @tigercosmos , @egecetin , @WojtekMs , @rtmeng, @DeepakReddy1999 !)
  - Ported most of the examples and tutorials to C++11 (thanks @jpcofr , @merttozer !)
  - Refactored and cleaned up PF_RING devices (thanks @Dimi1010 !)
  - Refactored and cleaned up the `PointerVector` class (thanks @Dimi1010 !)
  - Converted Macro Guard to `pragma once` (thanks @clementperon !)
  - Replaced `std::map` with `std::unordered_map` (thanks @tigercosmos !)
  - Refactored large parts of the packet filtering code (thanks @Dimi1010 !)
- Supported platforms update:
  - Ubuntu: added 24.04 LTS and dropped 18.04 LTS (thanks @tigercosmos !)
  - Added support for RHEL 9.4 (thanks @clementperon !)
  - Fedora: added support for 39 and removed 37 (thanks @clementperon !)
  - Removed support for CentOS 7
  - FreeBSD: added support for 14.0 and dropped 12 (thanks @clementperon !)
- Internal tools: 
  - Reformatted the entire code base using `clang-format` (thanks @tigercosmos , @Dimi1010 !)
  - Added `dependabot` to keep GitHub Actions and Python packages up-to-date (thanks @egecetin !)
  - Added OpenSSF Scorecard automation to monitor and enhance security (thanks @egecetin !)
  - Transitioned from CirrusCI to GitHub Actions for all workflows (thanks @tigercosmos !)
  - Scheduled regular CI builds (thanks @tigercosmos !)
  - Replaced deprecated `netifaces` by `scapy` (thanks @zhengfeihe !)
  - Improved fuzzing coverage and added Fuzz CI (thanks @sashashura !)
  - Added a template for opening GitHub issues (thanks @tigercosmos !)
  - Upgraded `LightPcapNg` to the latest from `master` (thanks @tigercosmos !)
  - Fixed unhandled exceptions crashing the entire test suite (thanks @Dimi1010 !)
- Tons of bug fixes, security fixes and small improvements (thanks @sashashura , @tigercosmos , @clementperon , @egecetin , @kraj , @liu0hy , @lucashc , @axmahr, @Double0101, @prudens , @MCredbear, @rahagal, @nadongjun !)


Breaking changes
----------------

This version includes a small number of breaking changes:
- Removed `isValid()` from `MacAddress,` `IPAddress`, `IPv4Address`, `IPv6Address`, instead they throw an exception if the input argument is invalid
- Introduced a new `TcpOptionEnumType`
- Removed the `dummy` argument in `PayloadLayer`'s constructor


Deprecation list
----------------

The following methods that were marked as deprecated in previous versions were removed:
- `IPv4Address::matchSubnet()`

The following methods are now marked as deprecated and will be removed in future versions:
- `PointerVector::getAndRemoveFromVector()` -> replaced by `PointerVector::getAndDetach()`
- `HttpResponseLayer::HttpResponseLayer(version, statusCode, statusCodeString)` -> use other constructors
- `HttpResponseLayer::setStatusCode(newStatusCode, statusCodeString)` -> use the other overload
- `TcpOptionType` enum -> replaced by `TcpOptionEnumType`
- `TcpOption::getTcpOptionType()` -> replaced by `TcpOption::getTcpOptionEnumType()`
- `TcpOptionBuilder::TcpOptionBuilder()` -> use other constructors
- `TcpLayer::getTcpOption(TcpOptionType option)` -> use the other overload
- `TcpLayer::addTcpOptionAfter()` -> replaced by `TcpLayer::insertTcpOptionAfter()`
- `TcpLayer::removeTcpOption()` -> use the other overload
- `PcapLiveDevice::getAddresses()` -> replaced by `PcapLiveDevice::getIPAddresses()`
- `PcapRemoteDeviceList::getRemoteDeviceList()` -> replaced by `PcapRemoteDeviceList::createRemoteDeviceList()`


Collaborators
-------------

 - @tigercosmos
 - @Dimi1010
 - @egecetin
 - @clementperon
 - @seladb


Contributors
------------

- @sashashura
- @zhengfeihe
- @wivien19
- @gyl30
- @MatteO-Matic
- @SesomB
- @jpcofr
- @liu0hy
- @merttozer
- @lucashc
- @axmahr
- @Double0101
- @prudens
- @rtmeng 
- @hidd3ncod3s 
- @WojtekMs
- @mserdarsanli
- @MCredbear 
- @rahagal
- @DeepakReddy1999
- @kraj
- @nadongjun


**Full Changelog**: https://github.com/seladb/PcapPlusPlus/compare/v23.09...v24.09
