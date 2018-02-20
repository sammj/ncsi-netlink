#!/usr/bin/python2

import ctypes
import socket
import argparse


from libnl.attr import nla_data, nla_parse, nla_for_each_nested, nla_get_string, nla_get_u16, nla_get_u32, NLA_NESTED, nla_parse_nested, nla_policy, nla_put_string, NLA_STRING, NLA_U16, NLA_U32, NLA_FLAG, nla_for_each_attr, nla_type, nla_is_nested, nla_get_flag, nla_put_u32
from libnl.error import errmsg
from libnl.genl.genl import genl_connect, genlmsg_attrdata, genlmsg_attrlen, genlmsg_put, genlmsg_parse
from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.linux_private.netlink import NLM_F_DUMP
from libnl.linux_private.genetlink import genlmsghdr
from libnl.handlers import NL_CB_CUSTOM, NL_CB_VALID, NL_SKIP
from libnl.msg import nlmsg_alloc, nlmsg_data, nlmsg_hdr
from libnl.nl import nl_recvmsgs_default, nl_send_auto
from libnl.socket_ import nl_socket_alloc, nl_socket_modify_cb
from libnl.misc import c_int

# NCSI Netlink commands and attributes - see include/uapi/linux/ncsi.h
NCSI_CMD_UNSPEC = 0
NCSI_CMD_SET_INTERFACE = 1
NCSI_CMD_PKG_INFO = 2

NCSI_ATTR_UNSPEC = 0
NCSI_ATTR_IFINDEX = 1
NCSI_ATTR_PACKAGE_LIST = 2
NCSI_ATTR_PACKAGE_ID = 3
NCSI_ATTR_CHANNEL_ID = 4
NCSI_ATTR_MAX = 5

NCSI_PKG_UNSPEC = 0
NCSI_PKG_ATTR = 1
NCSI_PKG_ATTR_ID = 2
NCSI_PKG_ATTR_CHANNEL_LIST = 3
NCSI_PKG_ATTR_MAX = 4

NCSI_CHANNEL_ATTR_UNSPEC = 0
NCSI_CHANNEL_ATTR = 1
NCSI_CHANNEL_ATTR_ID = 2
NCSI_CHANNEL_ATTR_VERSION_MAJOR = 3
NCSI_CHANNEL_ATTR_VERSION_MINOR = 4
NCSI_CHANNEL_ATTR_VERSION_STR = 5
NCSI_CHANNEL_ATTR_LINK_STATE = 6
NCSI_CHANNEL_ATTR_ACTIVE = 7
NCSI_CHANNEL_ATTR_VLAN_LIST = 8
NCSI_CHANNEL_ATTR_MAX = 9

NCSI_VLAN_UNSPEC = 0
NCSI_VLAN_INFO = 1
NCSI_VLAN_INFO_ID = 2
NCSI_VLAN_INFO_PROTO = 3
NCSI_VLAN_INFO_MAX = 4

# NCSI Netlink attribte policies
ncsi_policy = dict((i, None) for i in range(NCSI_ATTR_MAX))
ncsi_policy.update({
    NCSI_ATTR_IFINDEX: nla_policy(type_=NLA_U32),
    NCSI_ATTR_PACKAGE_LIST: nla_policy(type_=NLA_NESTED),
    NCSI_ATTR_PACKAGE_ID: nla_policy(type_=NLA_U32),
    NCSI_ATTR_CHANNEL_ID: nla_policy(type_=NLA_U32),
})

ncsi_package_policy = dict((i, None) for i in range(NCSI_PKG_ATTR_MAX))
ncsi_package_policy.update({
    NCSI_PKG_ATTR: nla_policy(type_=NLA_NESTED),
    NCSI_PKG_ATTR_ID: nla_policy(type_=NLA_U32),
    NCSI_PKG_ATTR_CHANNEL_LIST: nla_policy(type_=NLA_NESTED),
})

ncsi_channel_policy = dict((i, None) for i in range(NCSI_CHANNEL_ATTR_MAX))
ncsi_channel_policy.update({
    NCSI_CHANNEL_ATTR: nla_policy(type_=NLA_NESTED),
    NCSI_CHANNEL_ATTR_ID: nla_policy(type_=NLA_U32),
    NCSI_CHANNEL_ATTR_VERSION_MAJOR: nla_policy(type_=NLA_U32),
    NCSI_CHANNEL_ATTR_VERSION_MINOR: nla_policy(type_=NLA_U32),
    NCSI_CHANNEL_ATTR_VERSION_STR: nla_policy(type_=NLA_STRING),
    NCSI_CHANNEL_ATTR_LINK_STATE: nla_policy(type_=NLA_U32),
    NCSI_CHANNEL_ATTR_ACTIVE: nla_policy(type_=NLA_FLAG),
    NCSI_CHANNEL_ATTR_VLAN_LIST: nla_policy(type_=NLA_NESTED),
})

ncsi_vlan_policy = dict((i, None) for i in range(NCSI_VLAN_INFO_MAX))
ncsi_vlan_policy.update({
    NCSI_VLAN_INFO: nla_policy(type_=NLA_NESTED),
    NCSI_VLAN_INFO_ID: nla_policy(type_=NLA_U16),
    NCSI_VLAN_INFO_PROTO: nla_policy(type_=NLA_U16),
})

# Dummy callback
def dump_callback(msg, _):

    gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
    tb = dict((i, None) for i in range(NCSI_ATTR_MAX + 1))
    nla_parse(tb, NCSI_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)

    print(tb)
    return NL_SKIP

# Callback to parse NCSI_CMD_PKG_INFO reply
def info_callback(msg, _):

    nlh = nlmsg_hdr(msg)
    gnlh = genlmsghdr(nlmsg_data(nlh))
    tb = dict((i, None) for i in range(NCSI_ATTR_MAX + 1))

    ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsi_policy)
    if ret != 0:
        reason = errmsg[abs(ret)]
        print("genlmsg_parse returned {}, {}".format(ret, reason))
        return ret

    if not NCSI_ATTR_PACKAGE_LIST in tb:
        print('No packages!')
        return -1

    rem = c_int()
    for nla in nla_for_each_nested(tb[NCSI_ATTR_PACKAGE_LIST], rem):
        ptb = dict()
        ret = nla_parse_nested(ptb, NCSI_PKG_ATTR_MAX, nla, ncsi_package_policy)
        if ret < 0:
            print('Failed to parse package nest')
            return ret
        if NCSI_PKG_ATTR_ID in ptb:
            print('package {}'.format(nla_get_u32(ptb[NCSI_PKG_ATTR_ID])))
            print('----------')
        else:
            print('package (with no id?)')

        crem = c_int()
        for cnla in nla_for_each_nested(ptb[NCSI_PKG_ATTR_CHANNEL_LIST], crem):
            ctb = dict()
            ret = nla_parse_nested(ctb, NCSI_CHANNEL_ATTR_MAX, cnla, ncsi_channel_policy)
            if ret < 0:
                print('Failed to parse channel nest')
                return ret
            if NCSI_CHANNEL_ATTR_ID in ctb:
                channel = nla_get_u32(ctb[NCSI_CHANNEL_ATTR_ID])
                if NCSI_CHANNEL_ATTR_ACTIVE in ctb:
                    print('channel {} - active!'.format(channel))
                else:
                    print('channel {}'.format(channel))
            else:
                print('channel (with no id?)')
            if NCSI_CHANNEL_ATTR_VERSION_MAJOR in ctb:
                print('\tmajor version {}'.format(nla_get_u32(ctb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])))
            if NCSI_CHANNEL_ATTR_VERSION_MINOR in ctb:
                print('\tminor version {}'.format(nla_get_u32(ctb[NCSI_CHANNEL_ATTR_VERSION_MINOR])))
            if NCSI_CHANNEL_ATTR_VERSION_STR in ctb:
                print('\tversion string {}'.format(nla_get_string(ctb[NCSI_CHANNEL_ATTR_VERSION_STR])))
            if NCSI_CHANNEL_ATTR_LINK_STATE in ctb:
                print('\tlink state {}'.format(nla_get_u32(ctb[NCSI_CHANNEL_ATTR_LINK_STATE])))
            if NCSI_CHANNEL_ATTR_VLAN_LIST in ctb:
                print('\tactive vlan ids:')
                rrem = c_int()
                for vnla in nla_for_each_nested(ctb[NCSI_CHANNEL_ATTR_VLAN_LIST], rrem):
                    vtb = dict()
                    vret = nla_parse_nested(vtb, NCSI_VLAN_INFO_MAX, vnla, ncsi_vlan_policy)
                    if vret < 0:
                        print('\t\tfailed to parse vlan ids')
                    else:
                        if NCSI_VLAN_INFO_ID in vtb:
                            print('\t\t{}'.format(nla_get_u16(vtb[NCSI_VLAN_INFO_ID])))
                        else:
                            print('\t\tno id?')

    return NL_SKIP

'''
Send an NCSI_CMD_SET_INTERFACE command. We can set either;
    - A single package
    - A single package and a single channel on that package (ie. a
      particular port)
If neither package or channel ID are specified any previously set interface
is cleared.
'''
def ncsi_set_interface(ifindex, package, channel):

    sk = nl_socket_alloc()
    ret = genl_connect(sk)
    if ret < 0:
        return ret

    driver_id = genl_ctrl_resolve(sk, b'NCSI')
    if driver_id < 0:
        return driver_id

    msg = nlmsg_alloc()
    genlmsg_put(msg, 0, 0, driver_id, 0, 0, NCSI_CMD_SET_INTERFACE, 0)
    ret = nla_put_u32(msg, NCSI_ATTR_IFINDEX, ifindex)
    if package:
        ret = nla_put_u32(msg, NCSI_ATTR_PACKAGE_ID, int(package))
    if channel:
        ret = nla_put_u32(msg, NCSI_ATTR_CHANNEL_ID, int(channel))

    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, dump_callback, None)

    ret = nl_send_auto(sk, msg)
    if ret < 0:
        print("Failed to send message: {}".format(ret))
        return ret

    ret = nl_recvmsgs_default(sk) # blocks
    if ret < 0:
        reason = errmsg[abs(ret)]
        print("recvmsg returned {}, {}".format(ret, reason))

'''
Send an NCSI_CMD_PKG_INFO command. If a package ID is not specified we pass the
NLM_F_DUMP flag to tell NCSI to list all packages.
'''
def ncsi_get_info(ifindex, package):

    # Open socket to kernel
    sk = nl_socket_alloc()
    ret = genl_connect(sk)
    if ret < 0:
        print("Failed to open socket")
        return -1

    # Find NCSI
    driver_id = genl_ctrl_resolve(sk, b'NCSI')
    if driver_id < 0:
        print("Could not resolve NCSI")
        return -1;

    # Setup up a Generic Netlink message
    msg = nlmsg_alloc()
    if package is None:
        ret = genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NCSI_CMD_PKG_INFO, 0)
    else:
        ret = genlmsg_put(msg, 0, 0, driver_id, 0, 0, NCSI_CMD_PKG_INFO, 0)
        nla_put_u32(msg, NCSI_ATTR_PACKAGE_ID, int(package))

    if ret < 0:
        reason = errmsg[abs(ret)]
        print("genlmsg_put returned {}, {}".format(ret, reason))
        return -1

    nla_put_u32(msg, NCSI_ATTR_IFINDEX, ifindex)

    # Add a callback function to the socket
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, info_callback, None)

    ret = nl_send_auto(sk, msg)
    if ret < 0:
        print("Failed to send message: {}".format(ret))
        return ret
    ret = nl_recvmsgs_default(sk) # blocks
    if ret < 0:
        reason = errmsg[abs(ret)]
        print("recvmsg returned {}, {}".format(ret, reason))

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--info",
            help="retrieve info about NCSI topology",
            action="store_true")
    parser.add_argument("-s", "--set",
            help="set a specific package / channel",
            action="store_true")
    parser.add_argument("-p", "--package",
            help="specify a package")
    parser.add_argument("-c", "--channel",
            help="specify a channel")
    # On a Witherspoon BMC eth0 is 2
    parser.add_argument("-x", "--index", type=int, default=2,
            help="specify device ifindex")

    args = parser.parse_args()

    if args.info:
        ncsi_get_info(args.index, args.package)
        return

    if args.channel and not args.package:
        print('You must specify a package id with a channel id')
        return -1

    if args.set:
        ncsi_set_interface(args.index, args.package, args.channel)
        return

if __name__ == '__main__':
    main()
