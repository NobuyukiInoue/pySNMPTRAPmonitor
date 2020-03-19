# pySNMPTRAPmonitor

Monitor and Dump SNMP TRAP by Python3


## Requirements

Python 3.5 or later.

This program uses UDP port 162.


### Supported OS

* MS-Windows
* macOS
* Linux


### Supported SNMP version

* SNMP version 1
* SNMP version 2c


## How to execute pySNMPTRAPmonitor

```
python snmptrapm.py [timeout(s)] [testmode]
```


## Execution Example

```
PS D:\pySNMPTRAPmonitor> python pysnmptrapm.py
recvfrom() timeout has been set to 60 seconds.
------------------------------------------------------------
Date: 2020-03-18 23:20:05
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 30818b        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4076e736d716c616e
                    community:         nsmqlan
000f: a47d        data
                    size:              125(0x7d)
0011: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001b: 40040a0101fe
                    agent-addr:        10.1.1.254
0021: 020102        generic-trap:      linkDown(0x2)
0024: 20100         specific-trap:     0(0x0)
0027: 4304019c1e25  time-stamp:        27008549(0x19c1e25)
002d: 305f          variable-bindings: type = Sequence(0x30), size = 95(0x5f)
0031: 60b2b0601020102020101ce7c
                    Obj:               iso.6.1.2.1.2.2.1.1.10108
003e: 202277c
                    val:               10108(0x277c)
0044: 60b2b0601020102020102ce7c
                    Obj:               iso.6.1.2.1.2.2.1.2.10108
0051: 4124769676162697445746865726e6574302f38
                    val:               GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0067: 60b2b0601020102020103ce7c
                    Obj:               iso.6.1.2.1.2.2.1.3.10108
0074: 20106
                    val:               6(0x6)
0079: 60d2b06010401090202010114ce7c
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
0088: 404646f776e
                    val:               down(0x646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:05
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 30818a        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4067075626c6963
                    community:          public
000e: a47d        data
                    size:              125(0x7d)
0010: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001a: 40040a0101fe
                    agent-addr:        10.1.1.254
0020: 020102        generic-trap:      linkDown(0x2)
0023: 20100         specific-trap:     0(0x0)
0026: 4304019c1e25  time-stamp:        27008549(0x19c1e25)
002c: 305f          variable-bindings: type = Sequence(0x30), size = 95(0x5f)
0030: 60b2b0601020102020101ce7c
                    Obj:               iso.6.1.2.1.2.2.1.1.10108
003d: 202277c
                    val:               10108(0x277c)
0043: 60b2b0601020102020102ce7c
                    Obj:               iso.6.1.2.1.2.2.1.2.10108
0050: 4124769676162697445746865726e6574302f38
                    val:               GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0066: 60b2b0601020102020103ce7c
                    Obj:               iso.6.1.2.1.2.2.1.3.10108
0073: 20106
                    val:               6(0x6)
0078: 60d2b06010401090202010114ce7c
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
0087: 404646f776e
                    val:               down(0x646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:05
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 30818b        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4076e736d716c616e
                    community:         nsmqlan
000f: a47d        data
                    size:              125(0x7d)
0011: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001b: 40040a0101fe
                    agent-addr:        10.1.1.254
0021: 020102        generic-trap:      linkDown(0x2)
0024: 20100         specific-trap:     0(0x0)
0027: 4304019c1e4d  time-stamp:        27008589(0x19c1e4d)
002d: 305f          variable-bindings: type = Sequence(0x30), size = 95(0x5f)
0031: 60b2b0601020102020101ce7d
                    Obj:               iso.6.1.2.1.2.2.1.1.10109
003e: 202277d
                    val:               10109(0x277d)
0044: 60b2b0601020102020102ce7d
                    Obj:               iso.6.1.2.1.2.2.1.2.10109
0051: 4124769676162697445746865726e6574302f39
                    val:               GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0067: 60b2b0601020102020103ce7d
                    Obj:               iso.6.1.2.1.2.2.1.3.10109
0074: 20106
                    val:               6(0x6)
0079: 60d2b06010401090202010114ce7d
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
0088: 404646f776e
                    val:               down(0x646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:05
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 30818a        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4067075626c6963
                    community:          public
000e: a47d        data
                    size:              125(0x7d)
0010: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001a: 40040a0101fe
                    agent-addr:        10.1.1.254
0020: 020102        generic-trap:      linkDown(0x2)
0023: 20100         specific-trap:     0(0x0)
0026: 4304019c1e4d  time-stamp:        27008589(0x19c1e4d)
002c: 305f          variable-bindings: type = Sequence(0x30), size = 95(0x5f)
0030: 60b2b0601020102020101ce7d
                    Obj:               iso.6.1.2.1.2.2.1.1.10109
003d: 202277d
                    val:               10109(0x277d)
0043: 60b2b0601020102020102ce7d
                    Obj:               iso.6.1.2.1.2.2.1.2.10109
0050: 4124769676162697445746865726e6574302f39
                    val:               GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0066: 60b2b0601020102020103ce7d
                    Obj:               iso.6.1.2.1.2.2.1.3.10109
0073: 20106
                    val:               6(0x6)
0078: 60d2b06010401090202010114ce7d
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
0087: 404646f776e
                    val:               down(0x646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:10
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 303f          Sequence size      3f(0x63)
0002: 201000        SNMP verision: 1(0x0)
0005: 4076e736d716c616e
                    community:         nsmqlan
000e: a431        data
                    size:              49(0x31)
0010: 6072b060102012f02
                    enterprise:        iso.6.1.2.1.47.2
0019: 40040a0101fe
                    agent-addr:        10.1.1.254
001f: 020106        generic-trap:      enterpriseSpecific(0x6)
0022: 20101         specific-trap:     1(0x1)
0025: 4304019c2054  time-stamp:        27009108(0x19c2054)
002b: 3014          variable-bindings: type = Sequence(0x30), size = 20(0x14)
002f: 60a2b060102012f01040100
                    Obj:               iso.6.1.2.1.47.1.4.1.0
003b: 4304019c2054
                    val:               27009108(0x19c2054)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:11
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 303e          Sequence size      3e(0x62)
0002: 201000        SNMP verision: 1(0x0)
0005: 4067075626c6963
                    community:          public
000d: a431        data
                    size:              49(0x31)
000f: 6072b060102012f02
                    enterprise:        iso.6.1.2.1.47.2
0018: 40040a0101fe
                    agent-addr:        10.1.1.254
001e: 020106        generic-trap:      enterpriseSpecific(0x6)
0021: 20101         specific-trap:     1(0x1)
0024: 4304019c2054  time-stamp:        27009108(0x19c2054)
002a: 3014          variable-bindings: type = Sequence(0x30), size = 20(0x14)
002e: 60a2b060102012f01040100
                    Obj:               iso.6.1.2.1.47.1.4.1.0
003a: 4304019c2054
                    val:               27009108(0x19c2054)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:13
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 308189        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4076e736d716c616e
                    community:         nsmqlan
000f: a47b        data
                    size:              123(0x7b)
0011: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001b: 40040a0101fe
                    agent-addr:        10.1.1.254
0021: 020103        generic-trap:      linkUp(0x3)
0024: 20100         specific-trap:     0(0x0)
0027: 4304019c217e  time-stamp:        27009406(0x19c217e)
002d: 305d          variable-bindings: type = Sequence(0x30), size = 93(0x5d)
0031: 60b2b0601020102020101ce7c
                    Obj:               iso.6.1.2.1.2.2.1.1.10108
003e: 202277c
                    val:               10108(0x277c)
0044: 60b2b0601020102020102ce7c
                    Obj:               iso.6.1.2.1.2.2.1.2.10108
0051: 4124769676162697445746865726e6574302f38
                    val:               GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0067: 60b2b0601020102020103ce7c
                    Obj:               iso.6.1.2.1.2.2.1.3.10108
0074: 20106
                    val:               6(0x6)
0079: 60d2b06010401090202010114ce7c
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
0088: 4027570
                    val:               up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:14
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 308188        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4067075626c6963
                    community:          public
000e: a47b        data
                    size:              123(0x7b)
0010: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001a: 40040a0101fe
                    agent-addr:        10.1.1.254
0020: 020103        generic-trap:      linkUp(0x3)
0023: 20100         specific-trap:     0(0x0)
0026: 4304019c217e  time-stamp:        27009406(0x19c217e)
002c: 305d          variable-bindings: type = Sequence(0x30), size = 93(0x5d)
0030: 60b2b0601020102020101ce7c
                    Obj:               iso.6.1.2.1.2.2.1.1.10108
003d: 202277c
                    val:               10108(0x277c)
0043: 60b2b0601020102020102ce7c
                    Obj:               iso.6.1.2.1.2.2.1.2.10108
0050: 4124769676162697445746865726e6574302f38
                    val:               GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0066: 60b2b0601020102020103ce7c
                    Obj:               iso.6.1.2.1.2.2.1.3.10108
0073: 20106
                    val:               6(0x6)
0078: 60d2b06010401090202010114ce7c
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
0087: 4027570
                    val:               up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:14
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 308189        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4076e736d716c616e
                    community:         nsmqlan
000f: a47b        data
                    size:              123(0x7b)
0011: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001b: 40040a0101fe
                    agent-addr:        10.1.1.254
0021: 020103        generic-trap:      linkUp(0x3)
0024: 20100         specific-trap:     0(0x0)
0027: 4304019c217f  time-stamp:        27009407(0x19c217f)
002d: 305d          variable-bindings: type = Sequence(0x30), size = 93(0x5d)
0031: 60b2b0601020102020101ce7d
                    Obj:               iso.6.1.2.1.2.2.1.1.10109
003e: 202277d
                    val:               10109(0x277d)
0044: 60b2b0601020102020102ce7d
                    Obj:               iso.6.1.2.1.2.2.1.2.10109
0051: 4124769676162697445746865726e6574302f39
                    val:               GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0067: 60b2b0601020102020103ce7d
                    Obj:               iso.6.1.2.1.2.2.1.3.10109
0074: 20106
                    val:               6(0x6)
0079: 60d2b06010401090202010114ce7d
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
0088: 4027570
                    val:               up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:14
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 308188        Sequence size      1(0x1)
0003: 201000        SNMP verision: 1(0x0)
0006: 4067075626c6963
                    community:          public
000e: a47b        data
                    size:              123(0x7b)
0010: 6082b06010603010105
                    enterprise:        iso.6.1.6.3.1.1.5
001a: 40040a0101fe
                    agent-addr:        10.1.1.254
0020: 020103        generic-trap:      linkUp(0x3)
0023: 20100         specific-trap:     0(0x0)
0026: 4304019c217f  time-stamp:        27009407(0x19c217f)
002c: 305d          variable-bindings: type = Sequence(0x30), size = 93(0x5d)
0030: 60b2b0601020102020101ce7d
                    Obj:               iso.6.1.2.1.2.2.1.1.10109
003d: 202277d
                    val:               10109(0x277d)
0043: 60b2b0601020102020102ce7d
                    Obj:               iso.6.1.2.1.2.2.1.2.10109
0050: 4124769676162697445746865726e6574302f39
                    val:               GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0066: 60b2b0601020102020103ce7d
                    Obj:               iso.6.1.2.1.2.2.1.3.10109
0073: 20106
                    val:               6(0x6)
0078: 60d2b06010401090202010114ce7d
                    Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
0087: 4027570
                    val:               up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:15
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 303f          Sequence size      3f(0x63)
0002: 201000        SNMP verision: 1(0x0)
0005: 4076e736d716c616e
                    community:         nsmqlan
000e: a431        data
                    size:              49(0x31)
0010: 6072b060102012f02
                    enterprise:        iso.6.1.2.1.47.2
0019: 40040a0101fe
                    agent-addr:        10.1.1.254
001f: 020106        generic-trap:      enterpriseSpecific(0x6)
0022: 20101         specific-trap:     1(0x1)
0025: 4304019c2248  time-stamp:        27009608(0x19c2248)
002b: 3014          variable-bindings: type = Sequence(0x30), size = 20(0x14)
002f: 60a2b060102012f01040100
                    Obj:               iso.6.1.2.1.47.1.4.1.0
003b: 4304019c2054
                    val:               27009108(0x19c2054)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-18 23:20:16
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 303e          Sequence size      3e(0x62)
0002: 201000        SNMP verision: 1(0x0)
0005: 4067075626c6963
                    community:          public
000d: a431        data
                    size:              49(0x31)
000f: 6072b060102012f02
                    enterprise:        iso.6.1.2.1.47.2
0018: 40040a0101fe
                    agent-addr:        10.1.1.254
001e: 020106        generic-trap:      enterpriseSpecific(0x6)
0021: 20101         specific-trap:     1(0x1)
0024: 4304019c2248  time-stamp:        27009608(0x19c2248)
002a: 3014          variable-bindings: type = Sequence(0x30), size = 20(0x14)
002e: 60a2b060102012f01040100
                    Obj:               iso.6.1.2.1.47.1.4.1.0
003a: 4304019c2054
                    val:               27009108(0x19c2054)
------------------------------------------------------------
End of SNMP trap reception.

recvfrom() was timed out.  (60 second)
PS D:\pySNMPTRAPmonitor>
```
