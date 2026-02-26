import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import warnings
import json
import os
import time
import ipaddress
from collections import Counter
from IPython.display import display, HTML, Markdown
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
from scapy.all import *
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS

class Analyzer:
    def __init__(self):
        self.df = None
        self.packets = []
        self.threats = []
        self.statistics = {}
        self.file_info = {}
        self.analysis_time = 0
        self.risk_scores = defaultdict(int)
        self.network_risk_score = 0
    
    def scan_wifi(self, data, max_packets=50000, timeout=300):
        start_time = time.time()
        try:
            for i, pkt in enumerate(data):
                self.packets.append(pkt)

                if i >= max_packets:
                    break

                if time.time() - start_time > timeout:
                    break
            self._create_dataframe()
            self._collect_statistics()
            return True

        except MemoryError:
            return False
        except Exception as e:
            return False

    def load_pcap(self, file_path, max_packets=50000, timeout=300):
        if not os.path.exists(file_path):
            return False

        start_time = time.time()

        self.file_info = {
            "path": file_path,
            "filename": os.path.basename(file_path),
            "size_bytes": os.path.getsize(file_path),
            "size_mb": os.path.getsize(file_path) / (1024 * 1024),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path))
        }

        self.packets = []
        try:
            if self.file_info["size_mb"] > 50:
                with PcapReader(file_path) as reader:
                    for i, pkt in enumerate(reader):
                        self.packets.append(pkt)

                        if i >= max_packets:
                            break

                        if time.time() - start_time > timeout:
                            break
            else:
                all_packets = rdpcap(file_path)
                self.packets = all_packets[:max_packets]

            self._create_dataframe()
            self._collect_statistics()

            self.analysis_time = time.time() - start_time
            return True

        except MemoryError:
            return False
        except Exception as e:
            return False

    def _create_dataframe(self):
        data = []
        for i, packet in enumerate(self.packets):
            try:
                info = {
                    "packet_id": i,
                    "timestamp": datetime.fromtimestamp(float(packet.time)),
                    "length": len(packet),
                    "src_mac": None,
                    "dst_mac": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": "OTHER",
                    "src_port": None,
                    "dst_port": None,
                    "flags": None,
                    "ttl": None,
                    "ssid": None
                }

                if Ether in packet:
                    info["src_mac"] = packet[Ether].src
                    info["dst_mac"] = packet[Ether].dst

                if IP in packet:
                    ip = packet[IP]
                    info["src_ip"] = ip.src
                    info["dst_ip"] = ip.dst
                    info["ttl"] = ip.ttl

                    if TCP in packet:
                        tcp = packet[TCP]
                        info["protocol"] = "TCP"
                        info["src_port"] = tcp.sport
                        info["dst_port"] = tcp.dport
                        info["flags"] = self._parse_tcp_flags(int(tcp.flags))
                    elif UDP in packet:
                        udp = packet[UDP]
                        info["protocol"] = "UDP"
                        info["src_port"] = udp.sport
                        info["dst_port"] = udp.dport
                    else:
                        info["protocol"] = f"IP_PROTO_{ip.proto}"

                elif IPv6 in packet:
                    ip6 = packet[IPv6]
                    info["protocol"] = "IPv6"
                    info["src_ip"] = ip6.src
                    info["dst_ip"] = ip6.dst

                elif ARP in packet:
                    arp = packet[ARP]
                    info["protocol"] = "ARP"
                    info["src_ip"] = arp.psrc
                    info["dst_ip"] = arp.pdst

                if DNS in packet:
                    info["protocol"] = "DNS"

                if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                    info["ssid"] = pkt[Dot11Elt].info.decode(errors="ignore")

                data.append(info)

            except Exception as e:
                return
        self.df = pd.DataFrame(data)

    def _parse_tcp_flags(self, flags):
        mapping = {
            0x01: "FIN", 0x02: "SYN", 0x04: "RST",
            0x08: "PSH", 0x10: "ACK", 0x20: "URG"
        }
        return "-".join(name for bit, name in mapping.items() if flags & bit)

    def _collect_statistics(self):
        self.statistics = {
            "total_packets": len(self.df),
            "total_bytes": int(self.df["length"].sum()),
            "time_range": {
                "start": str(self.df["timestamp"].min()),
                "end": str(self.df["timestamp"].max()),
                "duration_seconds": (
                    self.df["timestamp"].max() - self.df["timestamp"].min()
                ).total_seconds()
            },
            "packet_sizes": {
                "min": int(self.df["length"].min()),
                "max": int(self.df["length"].max()),
                "mean": float(self.df["length"].mean())
            },
            "protocols": dict(self.df["protocol"].value_counts().head(10)),
            "top_sources": dict(self.df["src_ip"].value_counts().head(10)),
            "top_destinations": dict(self.df["dst_ip"].value_counts().head(10)),
        }
    
    def _check_port_scanning(self):
        grouped = self.df.groupby("src_ip")["dst_port"].nunique()

        for ip, ports in grouped.items():
            if ports and ports > 30:
                self.threats.append({
                    "type": "PORT_SCANNING",
                    "severity": "HIGH" if ports > 100 else "MEDIUM",
                    "source": ip,
                    "description": f"{ports} уникальных портов"
                })
                self.risk_scores[ip] += 30

    def _check_syn_flood(self):
        syn = self.df[
            (self.df["protocol"] == "TCP") &
            (self.df["flags"].str.contains("SYN", na=False))
        ]

        counts = syn["src_ip"].value_counts()
        for ip, count in counts.items():
            if count > 50:
                self.threats.append({
                    "type": "SYN_FLOOD",
                    "severity": "HIGH" if count > 200 else "MEDIUM",
                    "source": ip,
                    "description": f"{count} SYN пакетов"
                })
                self.risk_scores[ip] += 40

    def _check_ddos(self):
        counts = self.df["src_ip"].value_counts()
        for ip, count in counts.items():
            if count > 1000:
                self.threats.append({
                    "type": "HIGH_VOLUME",
                    "severity": "HIGH",
                    "source": ip,
                    "description": f"{count} пакетов"
                })
                self.risk_scores[ip] += 50
    
    def _is_private_ip(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str).is_private
        except Exception:
            return False
    
    def _check_suspicious_ips(self):
        seen = set()

        for src_ip, dst_ip in zip(self.df["src_ip"], self.df["dst_ip"]):
            if not src_ip or not dst_ip:
                continue

            key = (src_ip, dst_ip)
            if key in seen:
                continue
            seen.add(key)

            if self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
                self.threats.append({
                    "type": "PRIVATE_TO_PUBLIC",
                    "severity": "MEDIUM",
                    "source": src_ip,
                    "destination": dst_ip,
                    "description": "Приватный IP общается с публичным",
                    "evidence": f"{src_ip} → {dst_ip}",
                    "timestamp": datetime.now().isoformat()
                })
                self.risk_scores[src_ip] += 10
    
    def _check_anomalies(self):
        sizes = self.df["length"]
        mean = sizes.mean()
        std = sizes.std()

        if std == 0:
            return

        z_scores = (sizes - mean) / std
        anomalies = self.df[abs(z_scores) > 3]

        if len(anomalies) > 5:
            self.threats.append({
                "type": "ANOMALOUS_PACKETS",
                "severity": "MEDIUM",
                "description": "Обнаружены пакеты с аномальными размерами",
                "evidence": f"{len(anomalies)} пакетов с Z-score > 3",
                "timestamp": datetime.now().isoformat()
            })
            self.network_risk_score += 10

    def _detect_evil_twin(self):
        if "src_mac" not in self.df.columns:
            return

        ssid_map = defaultdict(list)
        for _, row in self.df.iterrows():
            ssid = row.get("ssid")
            if not ssid:
                continue

            bssid = row.get("src_mac")
            ssid_map[ssid].append({
                "bssid": bssid,
                "channel": row.get("channel"),
                "rssi": row.get("rssi"),
                "row": row.to_dict()
            })

        for ssid, networks in ssid_map.items():
            if len(networks) <= 1:
                continue
            bssids = [net["bssid"] for net in networks]
            self.threats.append({
                "type": "EVIL_TWIN",
                "severity": "HIGH",
                "description": f"Обнаружено {len(networks)} точек доступа с SSID '{ssid}'",
                "details": {
                    "ssid": ssid,
                    "bssids": bssids,
                    "networks": networks
                },
                "timestamp": datetime.now().isoformat()
            })
            self.network_risk_score += 20

    def _detect_arp_spoofing(self):
        if not hasattr(self, "arp_table"):
            self.arp_table = {}

        arp_df = self.df[self.df["protocol"] == "ARP"]

        if arp_df.empty:
            return

        for _, row in arp_df.iterrows():
            src_ip = row.get("src_ip")
            src_mac = row.get("src_mac")

            if not src_ip or not src_mac:
                continue
            if src_ip in self.arp_table:
                stored_mac = self.arp_table[src_ip]["mac"]
                if stored_mac != src_mac:
                    self.threats.append({
                        "type": "ARP_SPOOFING",
                        "severity": "HIGH",
                        "description": f"Обнаружен ARP спуфинг: IP {src_ip} имеет разные MAC",
                        "details": {
                            "ip": src_ip,
                            "original_mac": stored_mac,
                            "spoofed_mac": src_mac,
                            "seen_count": self.arp_table[src_ip]["count"]
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                    self.network_risk_score += 50

            prev_count = self.arp_table.get(src_ip, {}).get("count", 0)
            self.arp_table[src_ip] = {
                "mac": src_mac,
                "last_seen": datetime.now().isoformat(),
                "count": prev_count + 1
            }

        duration = self.statistics["time_range"]["duration_seconds"]
        if duration > 0:
            arp_rate = len(arp_df) / duration
            if arp_rate > 5:
                self.threats.append({
                    "type": "ARP_FLOOD",
                    "severity": "HIGH",
                    "description": f"Высокая частота ARP пакетов: {arp_rate:.2f}/сек",
                    "timestamp": datetime.now().isoformat()
                })
                self.network_risk_score += 30

    def _detect_mitm(self):
        http_count = len(self.df[(self.df["protocol"] == "TCP") & (self.df["dst_port"] == 80)])
        https_count = len(self.df[(self.df["protocol"] == "TCP") & (self.df["dst_port"] == 443)])

        if https_count > 0:
            ratio = http_count / https_count

            if ratio > 0.1:
                self.threats.append({
                    "type": "SSL_STRIPPING",
                    "severity": "HIGH",
                    "description": f"Высокое соотношение HTTP/HTTPS: {ratio:.2f}",
                    "details": {
                        "http_count": http_count,
                        "https_count": https_count,
                        "ratio": ratio
                    },
                    "timestamp": datetime.now().isoformat()
                })

                self.network_risk_score += 30

        dns_df = self.df[self.df["protocol"] == "DNS"]
        dns_map = {}

        for _, row in dns_df.iterrows():
            domain = row.get("dst_ip")
            answer_ip = row.get("src_ip")
            if not domain or not answer_ip:
                continue
            if domain not in dns_map:
                dns_map[domain] = set()
            dns_map[domain].add(answer_ip)

        for domain, ips in dns_map.items():
            if len(ips) > 1:
                self.threats.append({
                    "type": "DNS_SPOOFING",
                    "severity": "HIGH",
                    "description": f"Домен {domain} разрешается в {len(ips)} разных IP",
                    "details": {
                        "domain": domain,
                        "ips": list(ips)
                    },
                    "timestamp": datetime.now().isoformat()
                })

                self.network_risk_score += 50

    def analyze_security(self):
        self.threats = []

        self._check_port_scanning()
        self._check_syn_flood()
        self._check_ddos()
        self._check_suspicious_ips()
        self._check_anomalies()
        self._detect_evil_twin()
        self._detect_arp_spoofing()
        self._detect_mitm()

        result = self._security_results()

    def _security_results(self):
        total_risk = 0
        total_ip_risk = sum(self.risk_scores.values())
        max_ip_risk = max(self.risk_scores.values(), default=0)

        total_risk = total_ip_risk + self.network_risk_score

        if total_risk >= 150 or max_ip_risk >= 80:
            status = "ОПАСНА"
        elif total_risk >= 80:
            status = "ПОДОЗРИТЕЛЬНА"
        else:
            status = "В НОРМЕ"

        return {
            "status": status,
            "total_risk": total_risk,
            "max_ip_risk": max_ip_risk,
            "ip_scores": dict(self.risk_scores)
        }

    def export_results(self, output_dir="results"):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.df.to_csv(f"{output_dir}/packets_{ts}.csv", index=False)
        with open(f"{output_dir}/stats_{ts}.json", "w", encoding="utf-8") as f:
            json.dump(self.statistics, f, indent=2, ensure_ascii=False, default=str)

        if self.threats:
            with open(f"{output_dir}/threats_{ts}.json", "w", encoding="utf-8") as f:
                json.dump(self.threats, f, indent=2, ensure_ascii=False)