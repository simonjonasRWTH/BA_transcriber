import pyshark


# path = "/media/sj/2nd SSD/10. local repositories/UROP/tls-ipal-extension/samples/ModbusTCP/ModbusTCP-TLS1.2-socketFraming.pcap"
# keypath = "/media/sj/2nd SSD/10. local-datasets/UROP/tls-ipal-extension/samples/ModbusTCP/secret-export"
# decodes = {
#     "tcp.port==5000": "tls",
#     "tcp.port==63433": "tls",
#     "tls.port==5000": "mbtcp",
#     "tls.port==63433": "mbtcp"}
# options = ["-o", "tls.keylog_file:" + keypath, "-o", "mbtcp.tls.port:5000"]

# capture = pyshark.FileCapture(
#     path,
#     decode_as=decodes,
#     custom_parameters=options
# )


# pkt = capture[4]
# pkt2 = capture[6]
# print(pkt["TLS"].record_content_type.showname_value)
# print(pkt["TLS"].handshake_version.showname_value)
# print(pkt2["TLS"].field_names)
# print(pkt2["TLS"].handshake_ciphersuite)
# print(pkt2["TLS"].record_content_type)
# print(pkt2["TLS"].handshake_type)
"""print(pkt.tcp.field_names)
print(pkt.tcp.options_wscale.name)
print(pkt.tcp.flags)
print(pkt.tcp.flags_reset)"""
# print("TCP" in pkt)
# print("{}:{}".format(pkt["ip"].src, pkt["tcp"].srcport))


_option_showname_to_keyname = {
    "No-Operation (NOP)" : "options_nop",           # No Operation
    "Maximum segment size" : "options_mss_val",     # Maximum Segment Size
    "Window scale" : "options_wscale_multiplier",   # Scale factor for window size
    "SACK permitted" : "options_sack_perm",         # SACK supported?
    "SACK" : "options_sack",                        # SACK
    "Timestamps" : "options_timestamp",             # timestamps
}

path = "/home/kali/BA_transcriber/tmp/ModbusTCP-noTLS.pcap"
decodes = {
    "tcp.port==5000" : "mbtcp", 
    "tcp.port==46479" : "mbtcp"}
capture = pyshark.FileCapture(
    path, 
    decode_as = decodes
)
pkt = capture[0]
available_options = pkt["TCP"].options.showname_value.split(",")
available_options = {s.strip() for s in available_options} # set of available options

for option in available_options:
    access_name = _option_showname_to_keyname.get(option)
    print(option)
    print(access_name)
    print("--")
    #print(getattr(pkt["TCP"], access_name))
