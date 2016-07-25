from scapy.all import *

class Handler :
    def __init__(self) :
        self.WAP_list = []

    def process_packet_capture(self, packet_capture) :
            for packet in packet_capture :
                if packet.haslayer(Dot11) :
                    if packet.subtype == 8 :
                        bssid = packet.addr3
                        if packet.haslayer(Dot11Elt) :
                            p = packet[Dot11Elt]
                            while isinstance(p, Dot11Elt) :
                                if p.ID == 0 :
                                    essid = p.info
                                if p.ID == 3 :
                                    channel = ord(p.info)
                                p = p.payload

                            wap = WirelessAccessPoint(bssid, essid, channel)

                            is_duplicate = self.check_for_duplicates(wap)
                            if is_duplicate == False :
                                self.WAP_list.append(wap)

    def check_for_duplicates(self, wap) :
        for x in self.WAP_list :
            if wap.bssid == x.bssid :
                return True
        return False

class WirelessAccessPoint :
    def __init__(self, bssid, essid, channel) :
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
