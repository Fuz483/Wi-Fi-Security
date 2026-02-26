import math
import re
from urllib.parse import urlparse
import requests

class URLSecurityAnalyzer:
    def __init__(self):
        self.ENTROPY_THRESHOLD = 3.5
        self.SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'signin', 'wallet', 'crypto']
        self.RISKY_TLDS = ['.zip', '.mov', '.top', '.gq', '.cf', '.tk', '.ml', '.ga', '.work', '.click']
        self.LEET_CHARS = r'[01345]'

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
    
    def _analyze_anomalies(self, domain_part: str) -> list:
        anomalies = []
        if re.search(r'[a-z]', domain_part) and re.search(self.LEET_CHARS, domain_part):
            if len(domain_part) > 4:
                anomalies.append(f"Подозрительная замена букв цифрами (Leet-speak) в '{domain_part}'")

        if domain_part.count('-') >= 2:
            anomalies.append(f"Слишком много дефисов в сегменте '{domain_part}' (признак фишинга)")

        if re.search(r'(.)\1\1', domain_part):
            anomalies.append(f"Подозрительные повторы символов в '{domain_part}'")
            
        return anomalies

    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text: return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def _is_ip_address(self, domain: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    def analyze_url(self, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0].lower()
            if not domain:
                return {"status": "ERROR", "message": "Некорректный URL"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        risk_score = 0
        details = []

        if domain.startswith('xn--'):
            risk_score += 60
            details.append("Обнаружен Punycode (возможна подмена символов/Homograph attack)")

        if self._is_ip_address(domain):
            risk_score += 50
            details.append("Используется прямой IP вместо домена")

        found_keywords = [word for word in self.SUSPICIOUS_KEYWORDS if word in domain]
        if found_keywords:
            risk_score += 30 * len(found_keywords)
            details.append(f"Подозрительные слова: {', '.join(found_keywords)}")

        if any(domain.endswith(tld) for tld in self.RISKY_TLDS):
            risk_score += 25
            details.append("Доменная зона (TLD) часто используется для фишинга")

        subdomains = domain.split('.')
        if len(subdomains) > 3:
            risk_score += 20
            details.append(f"Слишком много поддоменов ({len(subdomains)})")

        entropy = self._calculate_shannon_entropy(domain)
        if entropy > self.ENTROPY_THRESHOLD:
            risk_score += 40
            details.append(f"Высокая энтропия ({round(entropy, 2)}): похоже на генерацию случайных символов")

        if '-' in domain or '@' in url:
            risk_score += 15
            details.append("Спецсимволы в домене или URL (тире/собачка)")
        domain_parts = domain.replace('-', '.').split('.')
        
        for part in domain_parts:
            found_anomalies = self._analyze_anomalies(part)
            if found_anomalies:
                risk_score += 35 * len(found_anomalies)
                details.extend(found_anomalies)

        if '@' in url:
            risk_score += 50
            details.append("Символ '@' в URL — классический прием для скрытия реального домена")

        status = "SAFE"
        if risk_score >= 70: status = "DANGER"
        elif risk_score >= 30: status = "WARNING"

        return {
            "domain": domain,
            "status": status,
            "risk_score": min(risk_score, 100),
            "details": details
        }
