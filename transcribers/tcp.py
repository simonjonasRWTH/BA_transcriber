import transcriber.settings as settings
from transcriber.messages import IpalMessage
from transcribers.transcriber import Transcriber

class TCPTranscriber(Transcriber):
    _name = "tcp"

    def matches_protocol(self, pkt):
        return "TCP" in pkt
    
    def parse_packet(self,pkt):
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        
    