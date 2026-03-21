"""
RAJAN Scanner Agent
Port scanning and service detection
"""

import socket
import threading

from agents.base import BaseAgent
from tools.toolmanager import ToolManager


class ScannerAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "ScannerAgent"

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 8888: "Dev-Server", 27017: "MongoDB",
        9200: "Elasticsearch", 5000: "Flask/Dev", 3000: "Node.js",
    }

    def run_task(self, task_name):
        task_lower = task_name.lower()
        if "port" in task_lower:
            return self.port_scan()
        elif "service" in task_lower or "version" in task_lower:
            return self.service_detection()
        return self.port_scan()

    def port_scan(self):
        self.logger.info(f"Port scanning {self.target}", "Scanner")
        open_ports = []
        lock = threading.Lock()

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    with lock:
                        open_ports.append((port, service))
                sock.close()
            except Exception:
                pass

        threads = []
        for port in self.COMMON_PORTS:
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        open_ports.sort()
        for port, service in open_ports:
            self.save_intel("port", str(port), service)
            self.logger.success(f"Port {port}/tcp OPEN — {service}", "Scanner")
            self._check_port_risk(port, service)

        return f"Open ports: {[p for p,s in open_ports]}"

    def _check_port_risk(self, port, service):
        risky = {
            21: ("FTP open — check for anonymous login", "MEDIUM", "T1190"),
            23: ("Telnet open — unencrypted protocol!", "HIGH", "T1021.004"),
            445: ("SMB open — check for EternalBlue/PrintNightmare", "HIGH", "T1021.002"),
            3389: ("RDP open — brute force & BlueKeep risk", "HIGH", "T1021.001"),
            6379: ("Redis open — check if auth required", "HIGH", "T1190"),
            27017: ("MongoDB open — check if auth required", "HIGH", "T1190"),
            9200: ("Elasticsearch open — check if auth required", "HIGH", "T1190"),
        }
        if port in risky:
            msg, severity, mitre = risky[port]
            self.add_finding(
                f"Risky Port Open: {port}/{service}",
                severity, msg,
                f"{self.target}:{port}", "", mitre
            )

    def service_detection(self):
        self.logger.info("Service & version detection via nmap", "Scanner")
        ports = self.memory.get_intel(self.session_id, "port")
        if not ports:
            return "No open ports in memory yet"

        port_list = ",".join([k for _, k, _ in ports])
        ok, out = ToolManager.run(
            "nmap", ["-sV", "--version-intensity", "5", "-p", port_list, self.target],
            timeout=120
        )
        if ok and out:
            self.save_intel("nmap", "service_scan", out[:1000])
            self.logger.success("Service detection complete", "Scanner")
            return out
        return f"nmap not available: {out}"
