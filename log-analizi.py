"""
LogGuard Pro - SOC Analysis Engine
Author: [Senin Adın/GitHub Kullanıcı Adın]
Description: MITRE ATT&CK aligned log analyzer for detecting web attacks.
"""

import re
import json
import logging
import os
from collections import Counter
from datetime import datetime

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LogAnalyzer:
    """Sistem loglarını analiz eden ve şüpheli aktiviteleri raporlayan ana sınıf."""
    
    def __init__(self, log_path, output_path="reports"):
        self.log_path = log_path
        self.output_path = output_path
        self.alerts = []
        self.metrics = {
            "start_time": datetime.now().isoformat(),
            "scan_count": 0,
            "threat_distribution": Counter(),
            "top_malicious_ips": Counter()
        }

        # MITRE ATT&CK tabanlı geliştirilmiş kurallar
        self.signatures = {
            "T1190 - SQL Injection": r"(?i)(SELECT|UNION|INSERT|DELETE|DROP|--|'|OR\s+1=1)",
            "T1083 - Path Traversal": r"(?i)(\.\.\/|\.\.\\|/etc/passwd|/windows/system32)",
            "T1059 - Command Injection": r"(?i)(;|\||&&|\$\(|whoami|curl\s|wget\s)",
            "T1505.003 - Web Shell Access": r"(?i)(shell\.php|cmd\.jsp|root\.asp)",
            "T1595 - Active Scanning": r"(?i)(nmap|sqlmap|nikto|dirbuster|masscan)"
        }

    def _validate_path(self):
        """Dosya yolu güvenliğini kontrol eder."""
        if not os.path.exists(self.log_path):
            logging.error(f"Dosya bulunamadı: {self.log_path}")
            return False
        return True

    def process(self):
        """Log dosyasını satır satır işler."""
        if not self._validate_path():
            return

        logging.info(f"Analiz başlatılıyor: {self.log_path}")
        
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                self.metrics["scan_count"] += 1
                self._analyze_line(line)

        self._finalize_report()

    def _analyze_line(self, line):
        """Her bir satırı güvenlik imzalarıyla karşılaştırır."""
        # Basit IP ayıklama
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        ip = ip_match.group(1) if ip_match else "Unknown"

        for signature_name, pattern in self.signatures.items():
            if re.search(pattern, line):
                alert = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": ip,
                    "threat_type": signature_name,
                    "evidence": line.strip()[:100] # Logun sadece ilgili kısmını al
                }
                self.alerts.append(alert)
                self.metrics["threat_distribution"][signature_name] += 1
                self.metrics["top_malicious_ips"][ip] += 1

    def _finalize_report(self):
        """Sonuçları dosyaya kaydeder."""
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)

        report_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        full_path = os.path.join(self.output_path, report_name)

        final_data = {
            "summary": self.metrics,
            "alerts": self.alerts
        }

        with open(full_path, "w") as f:
            json.dump(final_data, f, indent=4)
        
        logging.info(f"Analiz tamamlandı. Rapor şurada: {full_path}")
        print(f"\n[+] Tespit Edilen Kritik Olay Sayısı: {len(self.alerts)}")

if __name__ == "__main__":
    # Kullanım örneği
    analyzer = LogAnalyzer("kadir.log")
    analyzer.process()