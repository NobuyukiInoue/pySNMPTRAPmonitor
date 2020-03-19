# -*- coding: utf-8 -*-

import socket
import sys
import datetime

def main():
    argv = sys.argv
    argc = len(argv)

    timeout = 60

    if argc >= 2:
        try:
            timeout = int(argv[1])
        except:
            print("Usage)\n"
                  "python {0} [timeout(s)] [testmode]".format(argv[0]))
            sys.exit(-1)

    print("recvfrom() timeout has been set to {0:d} seconds.".format(timeout))

    if argc <= 2:
        HOST = ""
        PORT = 162
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.bind((HOST, PORT))
   
    while True:
        if argc >= 3:
            # test mode
            address = ["", ""]
            msg = select_msg_for_test()

        else:
            # snmp trap monitoring mode
            try:
                msg, address = s.recvfrom(8192)
            except:
                print("recvfrom() was timed out.  ({0:d} second)".format(timeout))
                s.close()
                sys.exit(0)

        print("------------------------------------------------------------\n"
            "Date: {0:%Y-%m-%d %H:%M:%S}\n"
            "From: {1}:{2}\n"
            "------------------------------------------------------------"
            .format(datetime.datetime.now(), address[0], address[1]))

        print_trap_msg(msg)

        print("------------------------------------------------------------\n"
              "End of SNMP trap reception.\n")

    s.close()

def select_msg_for_test():
    # command write
    msg1 = b'0l\x02\x01\x00\x04\x07Mpublic\xa4^\x06\t+\x06\x01\x04\x01\t\t+\x02@\x04\n\x02\x0f\xfe\x02\x01\x06\x02\x01\x01C\x04\x00\xb3\xf2\xf70?0\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x03W\x02\x01\x010\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x04W\x02\x01\x030\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x05W\x02\x01\x04'

    # port linkdown(shutdown)
    msg2 = b"0\x81\x9d\x02\x01\x00\x04\x07Mpublic\xa4\x81\x8e\x06\x08+\x06\x01\x06\x03\x01\x01\x05@\x04\n\x02\x0f\xfe\x02\x01\x02\x02\x01\x00C\x04\x01%\xbe\x160p0\x11\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x01\xcew\x02\x02'w0!\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x02\xcew\x04\x12GigabitEthernet0/30\x10\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x03\xcew\x02\x01\x060&\x06\r+\x06\x01\x04\x01\t\x02\x02\x01\x01\x14\xcew\x04\x15administratively down"

    # port linkup(no shutdown)
    msg3 = b"0\x81\x89\x02\x01\x00\x04\x07Mpublic\xa4{\x06\x08+\x06\x01\x06\x03\x01\x01\x05@\x04\n\x02\x0f\xfe\x02\x01\x03\x02\x01\x00C\x04\x01%\xd6\x930]0\x11\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x01\xcew\x02\x02'w0!\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x02\xcew\x04\x12GigabitEthernet0/30\x10\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x03\xcew\x02\x01\x060\x13\x06\r+\x06\x01\x04\x01\t\x02\x02\x01\x01\x14\xcew\x04\x02up"

    while True:
        print("1 ... {0}\n{1}".format("command write", msg1))
        print("2 ... {0}\n{1}".format("link-down", msg2))
        print("3 ... {0}\n{1}".format("link-up", msg3))
        print("select [1-3]")
        res = input()
        if res == "1":
            msg = msg1
            break
        elif res == "2":
            msg = msg2
            break
        elif res == "3":
            msg = msg3
            break
    return msg


def print_trap_msg(msg):
    """
    print_trap_msg()
    """
    offset = 0

    """ header """
    offset_start = offset
    offset, tag_head = get_datatype(offset, msg[offset])
    offset, len_head = get_length(offset, msg[offset:])
    header = msg[offset_start:offset_start+2]
    len_flds = offset - offset_start
    print("{0:04x}: {1:<13x} {2:<18s} {3:x}(0x{4:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), tag_head + " size", len_head, len_head))

    """ version """
    offset_start = offset
    offset, type_version = get_datatype(offset, msg[offset])

    if type_version != "INTEGER":
        print("SNMP TRAP Version error.")
        return

    offset, version = get_version(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:<06x} {2:>21s} {3:s}(0x{4:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "SNMP verision:", get_version_string(version), version))

    if version > 3:
        print("SNMP Version: unknown")
        return

    """ community """
    offset_start = offset
    offset, type_str_community = get_datatype(offset, msg[offset])
    offset, len_str_community = get_length(offset, msg[offset:])
    str_community = msg[offset:offset + len_str_community]
    offset += len_str_community
    len_flds = offset - offset_start
    print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
    print("{0:18s}  {1:s} {2:>15s}".format("", "community:", str(str_community, encoding="ascii")))

    """ data """
    # a4 81 8e 06 08 2b

    offset_start = offset
    data_head = msg[offset]
    offset += 1
    offset, len_trap_data = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:x} {2:6s} {3:<18s}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "data"))
    print("{0:18s}  {1:18s} {2:d}(0x{3:x})".format("", "size:", len_trap_data, len_trap_data))

    if version == 0:
        # version 1
        """ enterprise """
        offset_start = offset
        offset, type_enterprise = get_datatype(offset, msg[offset])
        offset, len_enterprise = get_length(offset, msg[offset:])
        str_enterprise = msg[offset:offset+len_enterprise]
        offset += len_enterprise
        len_flds = offset - offset_start
        print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
        print("{0:18s}  {1:18s} {2:s}".format("", "enterprise:", get_oid_string(str_enterprise)))

    elif version == 1:
        #version 2c
        print()

    """ ipaddr """
    offset_start = offset
    offset, type_ipaddr = get_datatype(offset, msg[offset])
    offset, len_ipaddr = get_length(offset, msg[offset:])
    str_ipaddr = msg[offset:offset+len_ipaddr]
    offset += len_ipaddr
    len_flds = offset - offset_start
    print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
    print("{0:18s}  {1:18s} {2:s}".format("", "agent-addr:", get_ipaddr4_string(str_ipaddr)))

    """ generic-trap """
    offset_start = offset
    offset, type_generic_trap = get_datatype(offset, msg[offset])
    offset, len_type_generic_trap = get_length(offset, msg[offset:])
    val_generic_trap = int.from_bytes(msg[offset:offset+len_type_generic_trap], "big")
    len_flds = offset - offset_start + len_type_generic_trap
    print("{0:04x}: {1:06x} {2:6s} {3:18s} {4:s}(0x{5:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "generic-trap:", get_generictrap_string(val_generic_trap), val_generic_trap))
    offset += len_type_generic_trap

    """ specific-trap """
    offset_start = offset
    offset, type_specific_trap = get_datatype(offset, msg[offset])
    offset, len_specific_trap = get_length(offset, msg[offset:])
    val_specific_trap = int.from_bytes(msg[offset:offset+len_specific_trap], "big")
    offset += len_specific_trap
    len_flds = offset - offset_start
    print("{0:04x}: {1:04x} {2:7s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "specific-trap:", val_specific_trap))

    """ time-stamp """
    offset_start = offset
    offset, type_timestamp = get_datatype(offset, msg[offset])
    offset, len_timestamp = get_length(offset, msg[offset:])
    timeStamp = int.from_bytes(msg[offset:offset+len_timestamp], "big")
    offset += len_timestamp
    len_flds = offset - offset_start
    print("{0:04x}: {1:06x} {2:s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "time-stamp:", timeStamp))

    """ variable-bindings """
    offset_start = offset
    offset, type_variable_binding = get_datatype(offset, msg[offset])
    offset, len_variable_binding = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:04x} {2:8s} {3:7s} type = {4:s}(0x{5:x}), size = {6:d}(0x{6:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "variable-bindings:", type_variable_binding, msg[offset_start], len_variable_binding))

    while offset < len(msg):
        """ obj """
        offset, type_obj = get_datatype(offset, msg[offset])
        offset, len_obj = get_length(offset, msg[offset:])

        """ Name """
        offset_start = offset
        offset, type_name = get_datatype(offset, msg[offset])
        offset, len_name = get_length(offset, msg[offset:])

        obj = msg[offset:offset+len_name]
        offset += len_name
        len_flds = offset - offset_start
        print("{0:04x}: {1:x}\n{2:19s} {3:18s} {4:s}".format(offset_start, int.from_bytes(msg[offset_start :  offset_start + len_flds], "big"), "", "Obj:", get_oid_string(obj)))

        """ Val """
        offset_start = offset
        offset, type_val = get_datatype(offset, msg[offset])
        offset, len_val = get_length(offset, msg[offset:])
        val = msg[offset:offset+len_val]
        offset += len_val
        len_flds = offset - offset_start
        if type_val == "INTEGER":
            print("{0:04x}: {1:x}\n{2:19s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start :  offset_start + len_flds], "big"), "", "val:", int.from_bytes(val, "big")))
        elif type_val == "OCTET STRING":
            print("{0:04x}: {1:x}\n{2:19s} {3:18s} {4:s}(0x{5:x})".format(offset_start, int.from_bytes(msg[offset_start :  offset_start + len_flds], "big"), "", "val:", str(val, encoding="ascii"), int.from_bytes(val, "big")))
        else:
            print("{0:04x}: {1:x}\n{2:19s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start :  offset_start + len_flds], "big"), "", "val:", int.from_bytes(val, "big")))

    return


def get_datatype(offset, tag):
    if tag == 0x01:
        return offset + 1, "BOOLEAN"
    elif tag == 0x02:
        return offset + 1, "INTEGER"
    elif tag == 0x03:
        return offset + 1, "BIT STRING"
    elif tag == 0x04:
        return offset + 1, "OCTET STRING"
    elif tag == 0x05:
        return offset + 1, "NULL"
    elif tag == 0x06:
        return offset + 1, "OBJECT IDENTIFIER"
    elif tag == 0x30:
        return offset + 1, "Sequence"
    elif tag == 0x40:
        return offset + 1, "IpAddress"
    elif tag == 0x41:
        return offset + 1, "Counter32"
    elif tag == 0x42:
        return offset + 1, "Gauge32"
    elif tag == 0x43:
        return offset + 1, "TimeTicks"
    elif tag == 0x44:
        return offset + 1, "Opeque"
    elif tag == 0x46:
        return offset + 1, "Counter64"
    else:
        return offset + 1, "unknown"


def get_length(offset, msg):
    if msg[0] <= 127:
        return offset + 1, msg[0]
    else:
        length = msg[0] & 0x7f
        return offset + 2, length


def get_version(offset, msg):
    offset, len_version = get_length(offset, msg)

    if len_version == 1:
        return offset + len_version, msg[1]
    elif len_version > 1:
        return offset + len_version, int.from_bytes(msg[1 : 1+len_version+1], "little")


def get_version_string(version):
    if version == 0:
        return "1"
    elif version == 1:
        return "2c"
    elif version == 2:
        return "3"
    else:
        return "unkown"

def get_oid_string(targetStr):
    resultStr = ""
    i = 0
    while i < len(targetStr):
        if i > 0:
            resultStr += "."

        if targetStr[i] == 43:
            resultStr += "iso"
            i += 1

        elif targetStr[i] >= 0x80:
            flds = []
            flds.append(targetStr[i] & 0x7f)        # remove MSB and append
            i += 1
            while True:
                flds.append(targetStr[i] & 0x7f)    # remove MSB and append
                if targetStr[i] >= 0x80:
                    i += 1
                    continue
                else:
                    break

            oid_bin_str = ""

            for j in range(0, len(flds)):
                oid_bin_str += bin(flds[j]).replace("0b", "")

            resultStr += str(int(oid_bin_str, 2))
            i += 1

        else:
            resultStr += str(targetStr[i])
            i += 1

    return resultStr


def get_ipaddr4_string(targetStr):
    resultStr = ""
    for i in range(len(targetStr)):
        if i > 0:
            resultStr += "."
        resultStr += "{0:d}".format(targetStr[i])
    return resultStr


def get_generictrap_string(targetVal):
    if targetVal == 0:
        return "coldStart"
    elif targetVal == 1:
        return "warmStart"
    elif targetVal == 2:
        return "linkDown"
    elif targetVal == 3:
        return "linkUp"
    elif targetVal == 4:
        return "authenticationFailure"
    elif targetVal == 5:
        return "egpNeighborLoss"
    elif targetVal == 6:
        return "enterpriseSpecific"
    else:
        return "{0:d}".format(targetVal)


if __name__ == "__main__":
    main()
