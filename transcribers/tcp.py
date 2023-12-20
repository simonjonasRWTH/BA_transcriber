import re
import transcriber.settings as settings
from transcriber.messages import Activity, IpalMessage
from transcribers.transcriber import Transcriber

# RFC 9293 & RFC 7323 & RFC 2018
# @todo: simultanious tcp handshake
# @todo: selective-repeat (RFC 1106)
# @todo: SACK (RFC 2018)
# @todo: what about graceful connection termination


class TCPTranscriber(Transcriber):
    _name = "tcp"

    _option_showname_to_keyname = {
        "No-Operation (NOP)" : "options_nop",           # No Operation
        "Maximum segment size" : "options_mss_val",     # Maximum Segment Size
        "Window scale" : "options_wscale_multiplier",   # Scale factor for window size
        "SACK permitted" : "options_sack_perm",         # SACK supported?
        "SACK" : "options_sack",                        # SACK
        "Timestamps" : "options_timestamp_tsval",       # timestamps
    }

    def matches_protocol(self, pkt):
        return "TCP" in pkt

    def _parse_tcp_options(self, pkt):
        # available TCP options
        if "options" in pkt["TCP"].field_names:
            available_options = pkt["TCP"].options.showname_value.split(",")
            available_options = {s.strip() for s in available_options}  # set of available options
        else:
            available_options = []
        
        # parse tcp options
        options = {}
        for option in available_options:
            access_name = self._option_showname_to_keyname.get(option)
            if access_name is None:  # option supported?
                continue
            elif access_name == "options_sack_perm":
                options["tcp_sack_permitted"] = True
            else:
                # rest is appended
                options["tcp_{}".format(option)] = getattr(pkt["TCP"], access_name)

        return options
            
    def _parse_tcp_data(self, pkt):
        flags = pkt["TCP"].flags.showname_value
        flags = re.findall(r'\(.*?\)', flags)[0].strip("()").split(",")     # set flags in a string like: "SYN, ACK, FIN"
        flags = [s.strip() for s in flags] 
        
        data = {
            "tcp_seqnr" : pkt["TCP"].seq_raw,
            "tcp_ack" : pkt["TCP"].ack_raw,
            "tcp_windowsize" : pkt["TCP"].window_size,
            "tcp_flags" : flags,
        }

        return data
    
    def parse_packet(self, pkt):        
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        
        # @todo broken since response matching is not suitable for bidirectional connections
        flow = (src, dest)

        data = {}
        data |= self._parse_tcp_data(pkt)
        data |= self._parse_tcp_options(pkt)

        m = IpalMessage(
            id=self._id_counter.get_next_id(),
            timestamp=float(pkt.sniff_time.timestamp()),
            protocol=self._name,
            src=src,
            dest=dest,
            length=pkt["TCP"].len,
            crc=int(pkt["TCP"].checksum_status),
            type="transport",
            activity=Activity.UNKNOWN,                      # macht eigentlich gar keinen Sinn für TCP
            flow=flow,
            data=data,
        )

        # RST is never requested
        m._add_to_request_queue = False if ["RST"] == m.data["tcp_flags"] else True

        # everything is a response to something despite connection start
        m._match_to_requests = False if ["SYN"] == m.data["tcp_flags"] else True

        return [m]

    def parse_layer(self, pkt):

        data = {}
        data |= self._parse_tcp_data(pkt)
        data |= self._parse_tcp_options(pkt)

        return data

    def match_response(self, requests, response):
        remove_from_queue = []

        curr_ack = response.data["tcp_ack"]
        
        # remove every packet with a sequence nr < ack
        for r in requests:
            if r.data["tcp_seqnr"] < curr_ack:
                remove_from_queue.append(r)
                continue
        # connection termination herausarbeiten
        # ansonsten einfach chronologisch pro flow?
        return remove_from_queue
