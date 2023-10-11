import pyshark

path= "/home/sj/local-datasets/ModbusTCP/ModbusTCP-noTLS-socketFraming.pcap"
capture = pyshark.FileCapture(path)



pkt = capture[1]
"""print(pkt.tcp.field_names)
print(pkt.tcp.options_wscale.name)
print(pkt.tcp.flags)
print(pkt.tcp.flags_reset)"""
print("TCP" in pkt)
print("{}:{}".format(pkt["ip"].src, pkt["tcp"].srcport))