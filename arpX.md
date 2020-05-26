In this writeup we will build a tool which can detect am **ARP SPOOFING** attack.

**IMP NOTE: We will be using some concepts and code from our writeups on ARP SPOOF AND PACKET SNIFFER so make sure read it once and if you already done than go with the flow**.


The easiest way to detect any *arp attack* is to monitor *arp tables* you can this by the command :

```bash
root@kali:~#  arp -a

```

> you can see the changes in arp table by doing an arp_spoof attack to one of your device it chnages once attack happens.

**arp -a** have one issue it works fine until you are not being attacked but after an arp_spoof attack  it stills shows MAC address of eth0/wlan0 interface because it get restored but their is far better to detect this if you took *spoof* function from our arp_spoof cod(which sends an **arp response** to fool router and victim).

```python

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)t


```
In order to send a ARP response we set <mark> op = 2 </mark> and destination(*pdst*) to target IP and *hwdst* to *Target MAC*
and **psrc to the router's IP** we can use this code and sniffer code.

```python
#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "SignIn", "password", "pass", "SignUp"]
        for keyword in keywords:
            if keyword in load:
                return  load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>>" + url)


        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Credential >>>" + load + "\n\n")



sniff("eth0")

```

But we need the entire we need some of it's lets do some refactoring:

```python
#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):


sniff("eth0")

```
> But instead of HTTP layer we need to analyse ARP layer to check the **ARP response**.

```python
#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
    print(packet.show())


sniff("eth0")

```

> if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 > check for ARP layer in scapy packet and op == 2 for ARP response.

Now if you run this code you will see nothing until you run a *arp_spoof* attack  first from another device (for testing pupose only) , once you do this all details of packets will be displayed and under **ARP** list you will  see **hsrc**(the MAC Address) of attacker pretends to be the router and again if you scroll down their will be similar reponse for target .So basically they pretends to be diifernt devices but if we can cross check that a certain IP have that specific MAC Address or not (based on ARP Protocol) and if found that  a certain IP doesn't have  legitimate MAC address than we get  to know that it is pretending to be a different device sand for this  we have **function which return MAC if we input IP (code from arp_spoof).**

Lets add both the code to create the final code:

```python
#!/usr/bin/env python

import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
       try:
           real_mac = get_mac(packet[scapy.ARP].psrc)
           response_mac = packet[scapy.ARP].hwsrc

           if real_mac != response_mac:
               print("[+] Under ATTACK!")
       except IndexError:
           pass



sniff("eth0")

```
**BREAKDOWN**
---

```
# to get real_mac of devices
real_mac = get_mac(packet[scapy.ARP].psrc)
# to get response_mac from scapy packet
response_mac = packet[scapy.ARP].hwsrc
# comparing the two MAC if not same it's attack
if real_mac == response mac:
    print("[+] Under ATTACK!")

```

>Code is ready for test run arp_spoof attack from another device run this code on victim machine to Test !
