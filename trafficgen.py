#!/usr/bin/env python

from scapy.all import Dot11, Dot11Elt, RadioTap, sendp
from scapy.all import Dot11Beacon, Dot11Auth, Dot11ProbeReq, USER_CLASS_DATA

import sys

if len(sys.argv) < 4:
    print ('Usage: sudo ./trafficgen.py <wlan_iface> '
           '<interval_sec> <length> [<packet_type>]'
          )
    sys.exit()

netSSID = 'TRAFFIC_GENERATOR'
iface = sys.argv[1]
interval = float(sys.argv[2])
payload_len = int(sys.argv[3])
packet_type = None

if len(sys.argv) > 4:
    packet_type = sys.argv[4]
    if packet_type not in ['auth', 'beacon', 'probereq']:
        print 'Possible protocols: auth, beacon, probereq'
        sys.exit()

protocol = None;
if packet_type:
    if packet_type == 'auth':
        protocol = Dot11Auth()
    elif packet_type == 'beacon':
        protocol = Dot11Beacon()
    else:
        protocol = Dot11ProbeReq()
else:
    protocol = "\0\0\0\0TRAFFIC_GENERATOR"

#type=frame_type, FCfield=flags,
dot11 = Dot11(addr1='ff:ff:ff:ff:ff:ff',
addr2='21:37:21:37:21:37', addr3='10:10:10:10:10:10')

if packet_type is None:
    dot11.type = 'Data'
    dot11.subtype = 0
    dot11.FCfield = 0x42

essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))

frame = RadioTap()/dot11/protocol

if packet_type is not None:
    frame = RadioTap()/dot11/protocol/essid

# 22 is the size of the payload wrapper in protocol
required_payload_len = payload_len - len(frame) - 22

if required_payload_len > 0:
    payload = ''
    for x in range(0, required_payload_len):
        payload += '*'
    frame = frame/payload

frame.show()

raw_input("\nPress enter to start sending packets...\n")

sendp(frame, iface=iface, inter=interval, loop=1)
