from access_point_detection_classes_module import *
import curses

def enable_monitor_mode(iface):
    subprocess.call('ifconfig ' + iface + ' down', shell=True)
    subprocess.call('iwconfig ' + iface + ' mode Monitor', shell=True)
    subprocess.call('ifconfig ' + iface + ' up', shell=True)

def enable_managed_mode(iface):
    subprocess.call('ifconfig ' + iface + ' down', shell=True)
    subprocess.call('iwconfig ' + iface + ' mode Managed', shell=True)
    subprocess.call('ifconfig ' + iface + ' up', shell=True)
    subprocess.call('nmcli d connect ' + iface, shell=True)

def set_wireless_channel(channel) :
    subprocess.call('iwconfig wlan0 channel ' + str(channel), shell=True)

#   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #
#
# while isinstance(p, Dot11Elt) :
#     if p.ID == 1 :
#         list_ascii = [ord(i) for i in p.info]
#         print list_ascii
#         s = "".join([chr(c) for c in list_ascii])
#         print s
#
#   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #
#
# p = RadioTap()/Dot11(type=0,subtype=4,addr1='ff:ff:ff:ff:ff:ff',addr2 ='bc:77:37:ad:5c:a5',addr3='ff:ff:ff:ff:ff:ff')/Dot11ProbeReq()/Dot11Elt(ID=0,info='')/Dot11Elt(ID=1,info='\x02\x04\x0b\x16')/Dot11Elt(ID=3,info='\x02')/Dot11Elt(ID=50,info='\x0c\x12\x18\x24\x30\x48\x60\x6c')
# sendp(p, iface = 'wlan0', count = 1, inter = .3)
#
#   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #   #

def main() :

    # enable_monitor_mode('wlan0')


    # conf.iface = 'wlan0'
    #
    # Create instance
    H = Handler()
    screen = curses.initscr()
    curses.noecho()
    curses.curs_set(0)
    screen.keypad(1)
    #
    # Iterator will be the channel number
    for w in range(0,10) :
        for channel in range(1,11) :

            # Set the channel number through shell process
            set_wireless_channel(channel)

            packet_capture = sniff(count = 10, store = 1)
            H.process_packet_capture(packet_capture)
            for i in range(0,len(H.wap_list)) :
                screen.addstr(i,0, str(H.wap_list[i].bssid))
                screen.addstr(i,25, str(H.wap_list[i].channel))
                screen.addstr(i,30, str(H.wap_list[i].essid))
            screen.refresh()






    # enable_managed_mode('wlan0')

if __name__ == "__main__" :
    main()
