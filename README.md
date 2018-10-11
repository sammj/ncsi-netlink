A simple command line utility to interact with NCSI over Netlink.

This uses the [libnl](https://www.infradead.org/~tgr/libnl/) library to talk Netlink.
The Makefile assumes cross-compiling against a shared libnl library specified
via `LIBNL_INCDIR` and `LIBNL_LIBDIR`, eg:

	`make CC=/path/to/cross/compiler LIBNL_INCDIR=path/to/headers LIBNL_LIBDIR=/path/to/library`

Hint: You can most likely find these installed on your BMC.

---
```
usage:
ncsi-netlink: Send messages to the NCSI driver via Netlink
ncsi-netlink [-h] operation [-p PACKAGE] [-c CHANNEL] [-l IFINDEX]
	--ifindex index      Specify the interface index
	--package package    Package number
	--channel channel    Channel number (aka. port number)
	--info               Display info for packages and channels
	--set                Force the usage of a certain package/channel combination
	--clear              Clear the above setting
	--help               Print this help text
```
---

There is also a python version used for early prototyping and not as up to date.
This uses the [libnl](https://github.com/Robpol86/libnl) python library to talk Netlink.
