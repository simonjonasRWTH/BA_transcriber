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

    def parse_packet(self, pkt):
        flags = pkt["TCP"].flags.showname_value
        flags = re.findall(r'\(.*?\)', flags)[0].strip("()").split(",")     # set flags in a string like: "SYN, ACK, FIN"
        flags = [s.strip() for s in flags]                                  # Now a list of flags contained in packet
        
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        
        # @todo broken since response matching is not suitable for bidirectional connections
        flow = (src, dest)

        m = IpalMessage(
            id=self._id_counter.get_next_id(),
            timestamp=float(pkt.sniff_time.timestamp()),
            protocol=self._name,
            src=src,
            dest=dest,
            length=pkt["TCP"].len,
            crc=int(pkt["TCP"].checksum_status),
            type=flags,                                     # maybe in data?
            activity=Activity.UNKNOWN,                      # macht eigentlich gar keinen Sinn für TCP
            flow=flow
        )
        # RST is never requested
        m._add_to_request_queue = False if ["RST"] == flags else True

        # everything is a response to something despite connection start
        m._match_to_requests = False if ["SYN"] == flags else True

        # available TCP options
        if "options" in pkt["TCP"].field_names:
            available_options = pkt["TCP"].options.showname_value.split(",")
            available_options = {s.strip() for s in available_options} # set of available options
        else:
            available_options = []
        data = {
            "seqnr" : pkt["TCP"].seq,
            "ack" : pkt["TCP"].ack,
            "windowsize" : pkt["TCP"].window_size,
            "options" : None,
        }

        # parse tcp options
        options = []
        for option in available_options:
            access_name = self._option_showname_to_keyname.get(option)
            if access_name is None:  # option supported?
                continue
            elif access_name == "options_sack_perm":
                options.append("SACK permitted:true")
            elif access_name == "option_sack":  # special handling for sack
                options.append("SACK_left_edge:{}".format(pkt["TCP"].options_sack_le))
                options.append("SACK_right_edge:{}".format(pkt["TCP"].options_sack_re))
            else:
                # rest is appended
                options.append("{}:{}".format(option, getattr(pkt["TCP"], access_name)))  
        data["options"] = options
        # finished
        m.data = data
        return [m]

    def match_response(self, requests, response):
        remove_from_queue = []

        curr_ack = response.data["ack"]
        
        # remove every packet with a sequence nr < ack
        for r in requests:
            if r.data["seqnr"] < curr_ack:
                remove_from_queue.append(r)
                continue
        # connection termination herausarbeiten
        # ansonsten einfach chronologisch pro flow?
        return remove_from_queue
