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
Date: 2020-03-19 22:32:02
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 003081          Sequence           48(0x30)
                      size:              1(0x1)

0003: 020101          SNMP verision:     2c(0x01)
0006: 04067075626c6963
                      community:         public
000e: a78197          data
                      size:              1(0x1)
0011: 0202087c        request-id:        2172(0x87c)
0015: 020100          error-status:      0(0x0)
0018: 020100          error-index:       0(0x0)
001b: 30818a          variable-bindings:
                                         type: Sequence(0x30)
                                         size: 1(0x1)
0020: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
002a: 430401be2bac
                      TimeTicks:         29240236(0x01be2bac)
0032: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003e: 06092b0601060301010503
                      OBJECT IDENTIFIER: iso.6.1.6.3.1.1.5.3(0x2b0601060301010503)
004b: 060b2b0601020102020101ce7d
                      Obj:               iso.6.1.2.1.2.2.1.1.10109
0058: 0202277d
                      INTEGER:           10109(0x277d)
005e: 060b2b0601020102020102ce7d
                      Obj:               iso.6.1.2.1.2.2.1.2.10109
006b: 04124769676162697445746865726e6574302f39
                      OCTET STRING:      GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0081: 060b2b0601020102020103ce7d
                      Obj:               iso.6.1.2.1.2.2.1.3.10109
008e: 020106
                      INTEGER:           6(0x06)
0093: 060d2b06010401090202010114ce7d
                      Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
00a2: 0404646f776e
                      OCTET STRING:      down(0x646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-19 22:32:04
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 003081          Sequence           48(0x30)
                      size:              1(0x1)

0003: 020101          SNMP verision:     2c(0x01)
0006: 04067075626c6963
                      community:         public
000e: a781a8          data
                      size:              1(0x1)
0011: 0202087e        request-id:        2174(0x87e)
0015: 020100          error-status:      0(0x0)
0018: 020100          error-index:       0(0x0)
001b: 30819b          variable-bindings:
                                         type: Sequence(0x30)
                                         size: 1(0x1)
0020: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
002a: 430401be2c4d
                      TimeTicks:         29240397(0x01be2c4d)
0032: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003e: 06092b0601060301010503
                      OBJECT IDENTIFIER: iso.6.1.6.3.1.1.5.3(0x2b0601060301010503)
004b: 060b2b0601020102020101ce7c
                      Obj:               iso.6.1.2.1.2.2.1.1.10108
0058: 0202277c
                      INTEGER:           10108(0x277c)
005e: 060b2b0601020102020102ce7c
                      Obj:               iso.6.1.2.1.2.2.1.2.10108
006b: 04124769676162697445746865726e6574302f38
                      OCTET STRING:      GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0081: 060b2b0601020102020103ce7c
                      Obj:               iso.6.1.2.1.2.2.1.3.10108
008e: 020106
                      INTEGER:           6(0x06)
0093: 060d2b06010401090202010114ce7c
                      Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
00a2: 041561646d696e6973747261746976656c7920646f776e
                      OCTET STRING:      administratively down(0x61646d696e6973747261746976656c7920646f776e)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-19 22:32:15
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 3058            Sequence           48(0x30)
                      size:              88(0x58)

0002: 020101          SNMP verision:     2c(0x01)
0005: 04067075626c6963
                      community:         public
000d: a74b            data
                      size:              75(0x4b)
000f: 02020880        request-id:        2176(0x880)
0013: 020100          error-status:      0(0x0)
0016: 020100          error-index:       0(0x0)
0019: 303f            variable-bindings:
                                         type: Sequence(0x30)
                                         size: 63(0x3f)
001d: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
0027: 430401be30ba
                      TimeTicks:         29241530(0x01be30ba)
002f: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003b: 06092b060102012f020001
                      OBJECT IDENTIFIER: iso.6.1.2.1.47.2.0.1(0x2b060102012f020001)
0048: 060a2b060102012f01040100
                      Obj:               iso.6.1.2.1.47.1.4.1.0
0054: 430401be30ba
                      TimeTicks:         29241530(0x01be30ba)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-19 22:32:18
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 003081          Sequence           48(0x30)
                      size:              1(0x1)

0003: 020101          SNMP verision:     2c(0x01)
0006: 04067075626c6963
                      community:         public
000e: a78195          data
                      size:              1(0x1)
0011: 02020882        request-id:        2178(0x882)
0015: 020100          error-status:      0(0x0)
0018: 020100          error-index:       0(0x0)
001b: 308188          variable-bindings:
                                         type: Sequence(0x30)
                                         size: 1(0x1)
0020: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
002a: 430401be31e5
                      TimeTicks:         29241829(0x01be31e5)
0032: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003e: 06092b0601060301010504
                      OBJECT IDENTIFIER: iso.6.1.6.3.1.1.5.4(0x2b0601060301010504)
004b: 060b2b0601020102020101ce7d
                      Obj:               iso.6.1.2.1.2.2.1.1.10109
0058: 0202277d
                      INTEGER:           10109(0x277d)
005e: 060b2b0601020102020102ce7d
                      Obj:               iso.6.1.2.1.2.2.1.2.10109
006b: 04124769676162697445746865726e6574302f39
                      OCTET STRING:      GigabitEthernet0/9(0x4769676162697445746865726e6574302f39)
0081: 060b2b0601020102020103ce7d
                      Obj:               iso.6.1.2.1.2.2.1.3.10109
008e: 020106
                      INTEGER:           6(0x06)
0093: 060d2b06010401090202010114ce7d
                      Obj:               iso.6.1.4.1.9.2.2.1.1.20.10109
00a2: 04027570
                      OCTET STRING:      up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-19 22:32:18
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 003081          Sequence           48(0x30)
                      size:              1(0x1)

0003: 020101          SNMP verision:     2c(0x01)
0006: 04067075626c6963
                      community:         public
000e: a78195          data
                      size:              1(0x1)
0011: 02020884        request-id:        2180(0x884)
0015: 020100          error-status:      0(0x0)
0018: 020100          error-index:       0(0x0)
001b: 308188          variable-bindings:
                                         type: Sequence(0x30)
                                         size: 1(0x1)
0020: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
002a: 430401be31e9
                      TimeTicks:         29241833(0x01be31e9)
0032: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003e: 06092b0601060301010504
                      OBJECT IDENTIFIER: iso.6.1.6.3.1.1.5.4(0x2b0601060301010504)
004b: 060b2b0601020102020101ce7c
                      Obj:               iso.6.1.2.1.2.2.1.1.10108
0058: 0202277c
                      INTEGER:           10108(0x277c)
005e: 060b2b0601020102020102ce7c
                      Obj:               iso.6.1.2.1.2.2.1.2.10108
006b: 04124769676162697445746865726e6574302f38
                      OCTET STRING:      GigabitEthernet0/8(0x4769676162697445746865726e6574302f38)
0081: 060b2b0601020102020103ce7c
                      Obj:               iso.6.1.2.1.2.2.1.3.10108
008e: 020106
                      INTEGER:           6(0x06)
0093: 060d2b06010401090202010114ce7c
                      Obj:               iso.6.1.4.1.9.2.2.1.1.20.10108
00a2: 04027570
                      OCTET STRING:      up(0x7570)
------------------------------------------------------------
End of SNMP trap reception.

------------------------------------------------------------
Date: 2020-03-19 22:32:20
From: 10.1.1.254:60829
------------------------------------------------------------
0000: 3058            Sequence           48(0x30)
                      size:              88(0x58)

0002: 020101          SNMP verision:     2c(0x01)
0005: 04067075626c6963
                      community:         public
000d: a74b            data
                      size:              75(0x4b)
000f: 02020886        request-id:        2182(0x886)
0013: 020100          error-status:      0(0x0)
0016: 020100          error-index:       0(0x0)
0019: 303f            variable-bindings:
                                         type: Sequence(0x30)
                                         size: 63(0x3f)
001d: 06082b06010201010300
                      Obj:               iso.6.1.2.1.1.3.0
0027: 430401be32af
                      TimeTicks:         29242031(0x01be32af)
002f: 060a2b060106030101040100
                      Obj:               iso.6.1.6.3.1.1.4.1.0
003b: 06092b060102012f020001
                      OBJECT IDENTIFIER: iso.6.1.2.1.47.2.0.1(0x2b060102012f020001)
0048: 060a2b060102012f01040100
                      Obj:               iso.6.1.2.1.47.1.4.1.0
0054: 430401be30ba
                      TimeTicks:         29241530(0x01be30ba)
------------------------------------------------------------
End of SNMP trap reception.

recvfrom() was timed out.  (60 second)
PS D:\pySNMPTRAPmonitor>
```
