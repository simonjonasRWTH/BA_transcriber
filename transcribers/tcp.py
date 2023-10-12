import re
import transcriber.settings as settings
from transcriber.messages import Activity, IpalMessage
from transcribers.transcriber import Transcriber

class TcpTranscriber(Transcriber):
    _name = "tcp"

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
            timestamp=float(pkt.sniff_time.timestamp()),
            protocol=self._name,
            src=src,
            dest = dest,
            length=pkt["TCP"].len,
            crc = int(pkt["TCP"].checksum_status),
            type = flags,
            activity=Activity.UNKNOWN,
            flow="{} - {} - {}".format(src, dest, flags)
        )
        # RST is never requested, handle graceful connection termination in match-function
        m._add_to_request_queue = False if {"RST"} == flags else True
        
        # everything is a response to something despite connection start
        m._match_to_requests = False if {"SYN"} == flags else True 
