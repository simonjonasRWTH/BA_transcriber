import re
import transcriber.settings as settings
from transcriber.messages import Activity, IpalMessage
from transcribers.transcriber import Transcriber

class TCPTranscriber(Transcriber):
    _name = "tcp"

    _option_showname_to_keyname = {
        "No-Operation (NOP)" : "options_nop", # No Operation
        "Maximum segment size" : "options_mss_val", # Maximum Segment Size
        "Window scale" : "options_wscale_multiplier", # Scale factor for window size
        "SACK permitted" : "options_sack_perm", # SACK supported? 
        "SACK" : "options_sack", # SACK
        "Timestamps" : "options_timestamp", # timestamps
    }

    def matches_protocol(self,pkt):
        return "TCP" in pkt
    
    def parse_packet(self, pkt):
        flags = pkt["TCP"].flags.showname_value
        flags = re.findall(r'\(.*?\)', flags)[0].strip("()").split(",") # set flags in a string like: "SYN, ACK, FIN"
        flags = {s.strip() for s in flags} # Now a set of each Flag contained in packet
        
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
               
        m = IpalMessage(
            id = self._id_counter.get_next_id(),
            timestamp = float(pkt.sniff_time.timestamp()),
            protocol = self._name,
            src = src,
            dest = dest,
            length = pkt["TCP"].len,
            crc = int(pkt["TCP"].checksum_status),
            type = flags, # maybe in data?
            activity = Activity.UNKNOWN, # macht eigentlich gar keinen Sinn für TCP
            flow = "{} - {} - {}".format(src, dest, flags)
        )
        # RST is never requested, handle graceful connection termination in match-function
        m._add_to_request_queue = False if {"RST"} == flags else True
        
        # everything is a response to something despite connection start
        m._match_to_requests = False if {"SYN"} == flags else True 

        # available TCP options
        available_options = pkt["TCP"].options.showname_value.split(",")
        available_options = {s.strip() for s in available_options}
    
        data = {
            "seqnr" : pkt["TCP"].seq,
            "ack" : pkt["TCP"].ack,
            "windowsize" : pkt["TCP"].window_size,
        }

        # parse tcp options
        for option in available_options:
            access_name = self._option_showname_to_keyname.get(option)
            if access_name == None: # option supported?
                continue
            elif access_name == "option_sack": # special handling for sack
                data["SACK_left_edge"] = pkt["TCP"].options_sack_le
                data["SACK_right_edge"] = pkt["TCP"].options_sack_re
            else:
                data[option] = pkt["TCP"].access_name #rest is appended
        
        # finished
        m.data = data
        return m

    def match_response(self, requests, response):
        # connection termination herausarbeiten
        # ansonsten einfach chronologisch?
        return 