import math
import re
from urllib.parse import urlparse
import requests

class URLSecurityAnalyzer:
    def __init__(self):
        self.ENTROPY_THRESHOLD = 3.5

    def _check_external_blacklists(self, domain: str) -> bool:
        try:
            try:
                r = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": domain},
                    timeout=3
                )
                if r.json().get("query_status") == "ok":
                    return True
            except:
                pass

            try:
                r = requests.get(
                    f"https://checkurl.phishtank.com/checkurl/{domain}?format=json",
                    timeout=3
                )
                data = r.json()
                if data.get("results", {}).get("in_database") and \
                data["results"].get("verified") and \
                data["results"].get("valid"):
                    return True
            except:
                pass

            try:
                feed = requests.get(
                    "https://openphish.com/feed.txt",
                    timeout=3
                ).text.splitlines()
                if any(domain in url for url in feed):
                    return True
            except:
                pass

            return False

        except:
            return False

    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def _is_ip_address(self, domain: str) -> bool:
        ip_pattern = re.compile(
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )
        return bool(ip_pattern.match(domain))

    def analyze_url(self, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            if not domain:
                return {"status": "ERROR", "message": "Некорректный URL"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        risk_score = 0
        details = []
        is_suspicious = False
        if self._check_external_blacklists(domain):
            return {
                "domain": domain,
                "status": "DANGER",
                "risk_score": 100,
                "details": ["Домен найден в URLHaus (вредоносный)"]
            }
        if self._is_ip_address(domain):
            risk_score += 40
            details.append("Используется прямой IP-адрес (подозрительно для публичного сайта)")
            is_suspicious = True

        entropy = self._calculate_shannon_entropy(domain)
        entropy_formatted = round(entropy, 2)
        
        if entropy > self.ENTROPY_THRESHOLD:
            risk_score += 50
            details.append(f"Высокая энтропия ({entropy_formatted}). Возможен DGA-алгоритм.")
            is_suspicious = True
        else:
            details.append(f"Энтропия в норме ({entropy_formatted}).")
        if len(domain) > 30:
            risk_score += 10
            details.append("Подозрительно длинное имя домена.")

        status = "SAFE"
        if risk_score >= 70:
            status = "DANGER"
        elif risk_score >= 30:
            status = "WARNING"

        return {
            "domain": domain,
            "status": status,
            "risk_score": min(risk_score, 100), # Максимум 100
            "entropy": entropy_formatted,
            "details": details
        }