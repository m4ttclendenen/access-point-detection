from scapy.all import *
import subprocess

class Collector :
    def __init__(self) :
        self.wap_list = []

    def display_wap_list(self) :
        print ' CHANNEL\t\tBSSID\t\t\t\tESSID'
        for w in self.wap_list :
            print ' ' + str(w.channel) + '\t\t\t' + w.bssid + '\t\t' + w.essid

    def run(self) :
        packet_capture = sniff(count=50)
        self.process_packet_capture(packet_capture)

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
                                try :
                                    channel = ord(p.info)
                                except :
                                    channel = ''
                            p = p.payload

                        TempWAP = WirelessAccessPoint(bssid, essid, channel)

                        if self.check_for_duplicates(TempWAP) == False:
                            self.wap_list.append(TempWAP)

    def check_for_duplicates(self, TempWAP) :
        for w in self.wap_list :
            if TempWAP.bssid == w.bssid :
                return True
        return False

class WirelessAccessPoint :
    def __init__(self, bssid, essid, channel) :
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
