import pyshark

path= "/home/sj/local-datasets/ModbusTCP/ModbusTCP-TLS1.2-socketFraming.pcap"
keypath = "/home/sj/local-datasets/ModbusTCP/secret-export"
decodes = {
    "tcp.port==5000":"tls",
    "tcp.port==63433":"tls",
    "tls.port==5000":"mbtcp",
    "tls.port==63433":"mbtcp"}
options = ["-o", "tls.keylog_file:"+keypath,"-o", "mbtcp.tls.port:5000"]

capture = pyshark.FileCapture(
    path,
    decode_as=decodes,
    custom_parameters=options
    )



pkt = capture[4]
print(pkt["TLS"].record_content_type.showname_value)
print(pkt["TLS"].handshake_version.showname_value)
"""print(pkt.tcp.field_names)
print(pkt.tcp.options_wscale.name)
print(pkt.tcp.flags)
print(pkt.tcp.flags_reset)"""
#print("TCP" in pkt)
#print("{}:{}".format(pkt["ip"].src, pkt["tcp"].srcport))