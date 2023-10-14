import transcriber.settings as settings
from transcriber.messages import Activity, IpalMessage
from transcribers.transcriber import Transcriber

class TLSTranscriber(Transcriber):
    _name = "tls"

    def matches_protocol(self, pkt):
        return "TLS" in pkt
    def parse_packet(self, pkt):
        