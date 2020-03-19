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
        print("select [0-3]")
        res = input()
        try:
            if int(res) < 4:
                return testdata[int(res)]
        except:
            continue


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
    print("{0:04x}: {1:<12x} {2:s} {3:18s} {4:x}(0x{4:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", tag_head + " size", len_head))

    """ version """
    offset_start = offset
    offset, type_version = get_datatype(offset, msg[offset])

    if type_version != "INTEGER":
        print("SNMP TRAP Version error.")
        return

    offset, version = get_version(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:06x} {2:6s} {3:18s} {4:s}(0x{5:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "SNMP verision:", get_version_string(version), version))

    if version > 3:
        print("SNMP Version: unknown")
        return

    """ community """
    offset_start = offset
    offset, current_type= get_datatype(offset, msg[offset])
    offset, current_length = get_length(offset, msg[offset:])
    current_data = msg[offset:offset + current_length]
    offset += current_length
    len_flds = offset - offset_start
    print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
    print("{0:18s}  {1:s} {2:>15s}".format("", "community:", str(current_data, encoding="ascii")))

    """ data """
    # a4 81 8e 06 08 2b

    offset_start = offset
    data_head = msg[offset]
    offset += 1
    offset, current_length = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:x} {2:8s} {3:<18s}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "data"))
    print("{0:18s}  {1:18s} {2:d}(0x{3:x})".format("", "size:", current_length, current_length))

    if version == 0:
        # version 1
        """ enterprise """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        current_data = msg[offset : offset+current_length]
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
        print("{0:18s}  {1:18s} {2:s}".format("", "enterprise:", get_oid_string(current_data)))

        """ ipaddr """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        current_data = msg[offset : offset+current_length]
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:x}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big")))
        print("{0:18s}  {1:18s} {2:s}".format("", "agent-addr:", get_ipaddr4_string(current_data)))

        """ generic-trap """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        int_current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        len_flds = offset - offset_start + current_length
        print("{0:04x}: {1:06x} {2:6s} {3:18s} {4:s}(0x{5:d})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "generic-trap:", get_generictrap_string(int_current_data), int_current_data))
        offset += current_length

        """ specific-trap """
        offset_start = offset
        offset, type_specific_trap = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        int_current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:04x} {2:7s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "specific-trap:", int_current_data))

        """ time-stamp """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        timeStamp = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:06x} {2:s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "time-stamp:", timeStamp))

    elif version == 1:
        # version 2c
        """ request-id """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:04x} {2:5s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "request-id:", current_data))

        """ error-status """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:02x} {2:7s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "error-status:", current_data))

        """ error-index """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        current_data = int.from_bytes(msg[offset : offset+current_length], "big")
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:02x} {2:7s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "error-index:", current_data))


    """ variable-bindings """
    offset_start = offset
    offset, current_type = get_datatype(offset, msg[offset])
    offset, current_length = get_length(offset, msg[offset:])
    len_flds = offset - offset_start
    print("{0:04x}: {1:04x} {2:8s} {3:7s}".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "variable-bindings:"))
    print("{0:38s} {1:s} {2:s}(0x{3:x})".format("", "type:", current_type, msg[offset_start]))
    print("{0:38s} {1:s} {2:d}(0x{2:x})".format("", "size:", current_length))

    while offset < len(msg):
        """ obj """
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])

        """ Name """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])

        obj = msg[offset : offset+current_length]
        offset += current_length
        len_flds = offset - offset_start
        print("{0:04x}: {1:x}\n{2:19s} {3:18s} {4:s}".format(offset_start, int.from_bytes(msg[offset_start :  offset_start + len_flds], "big"), "", "Obj:", get_oid_string(obj)))

        """ Val """
        offset_start = offset
        offset, current_type = get_datatype(offset, msg[offset])
        offset, current_length = get_length(offset, msg[offset:])
        val = msg[offset : offset+current_length]
        offset += current_length
        len_flds = offset - offset_start

        if current_type == "INTEGER" or current_type == "Gauge32":
            print("{0:04x}: {1:0x}\n{2:19s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start + len_flds], "big"), "", current_type + ":", int.from_bytes(val, "big")))

        elif current_type == "OCTET STRING":
            print("{0:04x}: {1:0x}\n{2:19s} {3:18s} {4:s}(0x{5:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start + len_flds], "big"), "", "OCTET STRING:", str(val, encoding="ascii"), int.from_bytes(val, "big")))

        elif current_type == "TimeTicks":
            print("{0:04x}: {1:06x} {2:s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start+len_flds], "big"), "", "TimeTicks:", int.from_bytes(val, "big")))

        else:
            print("{0:04x}: {1:0x}\n{2:19s} {3:18s} {4:d}(0x{4:x})".format(offset_start, int.from_bytes(msg[offset_start : offset_start + len_flds], "big"), "", "val:", int.from_bytes(val, "big")))

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
