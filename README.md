# PHP Filesystem Quota Library

`Php-Quota` is a library that allows filesystem quotas on UNIX systems.
The underlying implementation is derived from [`Perl-Quota`](https://github.com/tomzox/Perl-Quota).

## Setup

This library requires the `ffi` and (optionally) the `posix` extensions from php.

Run `make` and copy `libquota.so` to some directory.

To use this library, you simply need `def.php` and `quota.php`.

```
# By default, libquota.so is assumed to be in the same directory as quota.php
$php_quota = new PHPQuota("PATH_TO_LIBQUOTA");
```

## Usage

See examples folder and Perl Quota Documentation

# Original README:

---

This repository contains the sources of the Perl "Quota" module, which has its
official home at [https://metacpan.org/pod/Quota](https://metacpan.org/pod/Quota).
Please use the ticket interfaces at CPAN for reporting issues.

The Perl Quota module provides access to file system quotas on UNIX platforms.
This works both for locally mounted file systems and network file systems (via
RPC, i.e. Remote Procedure Call). The interface is designed to be independent
of UNIX flavours as well as file system types.

I started developing this module 1995 while working as a UNIX system
administrator at university; I'm no longer working in this capacity, but still
updating the module on request. Since its beginnings, it was continuously
extended by porting to more UNIX platforms and filesystems. Numerous people
have contributed to this process; for a complete list of names please see the
CHANGES document in the repository.

The quota module was in the public domain 1995 to 2001. Since 2001 it is
licensed under the same terms as Perl itself, which is (at your choice) either
the Perl Artistic License, or version 1 or later of the GNU General Public
License.  For a copy of these licenses see
<http://www.opensource.org/licenses/>.  The respective authors of the source
code are its owner in regard to copyright.

Since April 2020 there's also a [Python port](https://github.com/tomzox/Python-Quota)
of this module, with its official home at [PyPi](https://pypi.org/project/FsQuota/).

## Module information

Perl DLSIP-Code: Rcdfg

* stable release
* C compiler required for installation
* support by developer
* plain functions, no references used
* licensed under the Perl Artistic License or (at your option)
  version 1 or later of the GNU General Public License

List of supported operating systems:

* SunOS 4.1.3
* Solaris 2.4 - 2.10
* HP-UX 9.0x & 10.10 & 10.20 & 11.00
* IRIX 5.2 & 5.3 & 6.2 - 6.5
* OSF/1 & Digital Unix 4
* FreeBSD 3 - 12.1, OpenBSD 2.2 - 6.6 & NetBSD 5 - 9,
* Linux - kernel 2.0.30 - 4.15
* AIX 4.1, 4.2 and 5.3

List of supported file systems:

* Standard file systems of the platforms listed above
* NFS (Network file system) on all of the above
* XFS on Linux and IRIX 6
* AFS (Andrew File System) on many of the above (see INSTALL)
* VxFS (Veritas File System) on Solaris 2

All of these operating systems and file systems are supported
transparently through a common API.

## Documentation

For further information please refer to the following files:

* <A HREF="Quota/Quota.pm">Quota.pm</A>: API documentation (at the end of the file)
* <A HREF="Quota/INSTALL">INSTALL</A>: Installation description
* <A HREF="Quota/CHANGES">CHANGES</A>: Change log &amp; acknowledgements
* <A HREF="Quota/LICENSE">LICENSE</A>: Perl License

