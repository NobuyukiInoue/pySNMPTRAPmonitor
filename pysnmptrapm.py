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
    testdata = []
    # command write(version 1)
    testdata.append(b"0l\x02\x01\x00\x04\x07Mpublic\xa4^\x06\t+\x06\x01\x04\x01\t\t+\x02@\x04\n\x01\x01\xfe\x02\x01\x06\x02\x01\x01C\x04\x00\xb3\xf2\xf70?0\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x03W\x02\x01\x010\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x04W\x02\x01\x030\x13\x06\x0e+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x05W\x02\x01\x04")

    # port linkdown(version 1)
    testdata.append(b"0\x81\x9d\x02\x01\x00\x04\x07Mpublic\xa4\x81\x8e\x06\x08+\x06\x01\x06\x03\x01\x01\x05@\x04\n\x01\x01\xfe\x02\x01\x02\x02\x01\x00C\x04\x01%\xbe\x160p0\x11\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x01\xcew\x02\x02'w0!\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x02\xcew\x04\x12GigabitEthernet0/30\x10\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x03\xcew\x02\x01\x060&\x06\r+\x06\x01\x04\x01\t\x02\x02\x01\x01\x14\xcew\x04\x15administratively down")

    # port linkup(version 1)
    testdata.append(b"0\x81\x89\x02\x01\x00\x04\x07Mpublic\xa4{\x06\x08+\x06\x01\x06\x03\x01\x01\x05@\x04\n\x01\x01\xfe\x02\x01\x03\x02\x01\x00C\x04\x01%\xd6\x930]0\x11\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x01\xcew\x02\x02'w0!\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x02\xcew\x04\x12GigabitEthernet0/30\x10\x06\x0b+\x06\x01\x02\x01\x02\x02\x01\x03\xcew\x02\x01\x060\x13\x06\r+\x06\x01\x04\x01\t\x02\x02\x01\x01\x14\xcew\x04\x02up")

    # command write(version 2c)
    testdata.append(b'0\x81\x88\x02\x01\x01\x04\x06public\xa7{\x02\x02\x07\xf0\x02\x01\x00\x02\x01\x000o0\x10\x06\x08+\x06\x01\x02\x01\x01\x03\x00C\x04\x01\xa3_\xa60\x19\x06\n+\x06\x01\x06\x03\x01\x01\x04\x01\x00\x06\x0b+\x06\x01\x04\x01\t\t+\x02\x00\x010\x14\x06\x0f+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x03\x81\x13\x02\x01\x010\x14\x06\x0f+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x04\x81\x13\x02\x01\x030\x14\x06\x0f+\x06\x01\x04\x01\t\t+\x01\x01\x06\x01\x05\x81\x13\x02\x01\x04')

    while True:
        print("0 ... {0}\n{1}".format("command write(version 1)", testdata[0]))
        print("1 ... {0}\n{1}".format("link-down(version 1)", testdata[1]))
        print("2 ... {0}\n{1}".format("link-up(version 1)", testdata[2]))
        print("3 ... {0}\n{1}".format("command write(version 2c)", testdata[3]))
        print("select [0-3] : ", end = "")
        res = input()
        try:
            if 0 <= int(res) < 4:
                return testdata[int(res)]
        except:
            continue


def get_flds(offset, msg):
    offset_start = offset
    offset, current_type = get_datatype(offset, msg[offset])
    offset, current_length = get_length(offset, msg[offset:])
    current_data = msg[offset : offset+current_length]
    int_current_data = int.from_bytes(current_data, "big")
    offset += current_length
    len_flds = offset - offset_start
    hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

    return offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata


def print_trap_msg(msg):
    """
    print_trap_msg()
    """
    offset = 0

    """ header """
    offset_start = offset
    offset, current_type = get_datatype(offset, msg[offset])
    offset, current_length = get_length(offset, msg[offset:])
    header = int.from_bytes(msg[offset_start : offset_start+2], "big")
    len_flds = offset - offset_start

    format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:x})"
    print(format_str.format(offset_start, header, "", current_type, msg[offset_start]))

    format_str = "{0:20s}  {1:18s} {2:d}(0x{2:x})\n"
    print(format_str.format("", "size:", current_length))


    """ version """
    offset_start = offset
    offset, type_version = get_datatype(offset, msg[offset])

    if type_version != "INTEGER":
        print("SNMP TRAP Version error.")
        return

    offset, version = get_version(offset, msg[offset:])
    len_flds = offset - offset_start
    hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

    format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:s}(0x{5:02x})"
    print(format_str.format(offset_start, hexdata, "", "SNMP verision:", get_version_string(version), version))

    if version > 3:
        print("SNMP Version: unknown")
        return

    """ community """
    offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

    format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:20s}  {3:18s} {4:s}"
    print(format_str.format(offset_start, hexdata, "", "community:", str(current_data, encoding="ascii")))

    """ data """
    offset_start = offset
    data_head = msg[offset]
    offset += 1
    offset, current_length = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

    format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:<18s}\n{4:20s}  {5:18s} {6:d}(0x{7:x})"
    print(format_str.format(offset_start, hexdata, "", "data", "", "size:", current_length, current_length))

    if version == 0:
        # version 1
        """ enterprise """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:20s}  {3:18s} {4:s}"
        print(format_str.format(offset_start, hexdata, "", "enterprise:", get_oid_string(current_data)))

        """ ipaddr """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:20s}  {3:18s} {4:s}"
        print(format_str.format(offset_start, hexdata, "", "agent-addr:", get_ipaddr4_string(current_data)))

    
        """ generic-trap """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        int_current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        len_flds = offset - offset_start + current_length
        hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:s}(0x{5:0" + str(2*current_length) + "x})"
        print(format_str.format(offset_start, hexdata, "", "generic-trap:", get_generictrap_string(int_current_data), int_current_data))
        offset += current_length

        """ specific-trap """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:0" + str(2*current_length) + "x})"
        print(format_str.format(offset_start, hexdata, "", "specific-trap:", int_current_data))

        """ time-stamp """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        timeStamp = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:0" + str(2*current_length) + "x})"
        print(format_str.format(offset_start, hexdata, "", "time-stamp:", timeStamp))

    elif version == 1:
        # version 2c
        """ request-id """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:x})"
        print(format_str.format(offset_start, hexdata, "", "request-id:", int_current_data))

        """ error-status """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:x})"
        print(format_str.format(offset_start, hexdata, "", "error-status:", int_current_data))

        """ error-index """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s} {4:d}(0x{4:x})"
        print(format_str.format(offset_start, hexdata, "", "error-index:", int_current_data))


    """ variable-bindings """
    offset_start = offset
    offset, current_type = get_datatype(offset, msg[offset])
    offset, current_length = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    hexdata = int.from_bytes(msg[offset_start : offset_start+len_flds], "big")

    format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x} {2:" + str(14 - 2*len_flds) + "s} {3:18s}"

    print(format_str.format(offset_start, hexdata, "", "variable-bindings:"))
    print("{0:40s} {1:s} {2:s}(0x{3:x})".format("", "type:", current_type, msg[offset_start]))
    print("{0:40s} {1:s} {2:d}(0x{2:x})".format("", "size:", current_length))

    while offset < len(msg):
        """ obj """
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])

        """ Name """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:s}"
        print(format_str.format(offset_start, hexdata, "", "Obj:", get_oid_string(current_data)))

        """ Val """
        offset_start, offset, current_type, current_length, current_data, int_current_data, len_flds, hexdata = get_flds(offset, msg)

        if current_type == "INTEGER" or current_type == "Gauge32":
            format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:d}(0x{4:0" + str(2*current_length) + "x})"
            print(format_str.format(offset_start, hexdata, "", current_type + ":", int_current_data))

        elif current_type == "OCTET STRING":
            format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:s}(0x{5:0" + str(2*current_length) + "x})"
            print(format_str.format(offset_start, hexdata, "", current_type + ":", str(current_data, encoding="ascii"), int_current_data))

        elif current_type == "TimeTicks":
            format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:d}(0x{4:0" + str(2*current_length) + "x})"
            print(format_str.format(offset_start, hexdata, "", current_type + ":", int_current_data))

        elif current_type == "OBJECT IDENTIFIER":
            format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:s}(0x{5:0" + str(2*current_length) + "x})"
            print(format_str.format(offset_start, hexdata, "", current_type + ":", get_oid_string(current_data), int_current_data))

        else:
            format_str = "{0:04x}: {1:0" + str(2*len_flds) + "x}\n{2:21s} {3:18s} {4:d}(0x{4:0" + str(2*current_length) + "x})"
            print(format_str.format(offset_start, hexdata, "", "val:", int_current_data))

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
        return offset + 2, msg[0] & 0x7f


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

        if i == 0 and targetStr[i] == 43:
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
