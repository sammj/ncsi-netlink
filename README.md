A simple python script to interact with NCSI over Netlink.

This uses the [libnl](https://github.com/Robpol86/libnl) python library to talk Netlink.

---

usage: ncsi-netlink.py [-h] [-i] [-s] [-p PACKAGE] [-c CHANNEL] [-x INDEX]

optional arguments:

  -h, --help            show this help message and exit

  -i, --info            retrieve info about NCSI topology

  -s, --set             set a specific package / channel

  -p PACKAGE, --package PACKAGE

			specify a package


  -c CHANNEL, --channel CHANNEL

			specify a channel


  -x INDEX, --index INDEX

			specify device ifindex
