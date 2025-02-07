import re
import argparse
import requests
import tldextract  # pour extraire proprement le domaine, le sous-domaine et le suffixe d’une URL ou d’un nom de domaine
from urllib.parse import urlparse
import asyncio
from virus_total_api import get_virustotal_analysis_id, get_virustotal_report


SHORTENED_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl"}
SUSPICIOUS_KEYWORDS = {"free", "win", "prize", "click", "bonus", "money", "reward", "claim"}
BLACKLISTED_DOMAINS = {"hacker.com", "phishing.net", "argent.org"}

def analyze_url(url: str) -> int:
    """Analyse une URL et retourne un score de risque (0-10)."""
    risk_score = 0

    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    path = parsed_url.path.lower()

    if domain in SHORTENED_DOMAINS:
        risk_score += 3

    if any(keyword in path for keyword in SUSPICIOUS_KEYWORDS):
        risk_score += 2

    if domain in BLACKLISTED_DOMAINS:
        risk_score += 5

    special_chars = re.findall(r"[!@#$%^&*()+=]", url)
    if len(special_chars) > 2:
        risk_score += 2

    return min(risk_score, 10) 

def is_url_accessible(url: str) -> bool:
    """Teste si l'URL est accessible (retourne un code 200)."""
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

async def main():
    parser = argparse.ArgumentParser(description="Analyseur d'URL malveillantes")
    parser.add_argument("url_or_file", type=str, help="URL à analyser ou fichier contenant une liste d'URLs")
    args = parser.parse_args()

    try:
        with open(args.url_or_file, "r") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        urls = [args.url_or_file]

    for url in urls:
        score = analyze_url(url)
        accessible = is_url_accessible(url)
        analysis_id = await get_virustotal_analysis_id(url)

        if analysis_id:
            virustotal_score = await get_virustotal_report(analysis_id)
        else:
            virustotal_score = 0
        
        status = "Accessible" if accessible else "Inaccessible"
        
        print(f"URL: {url}\n  → Score de risque (analyse locale): {score}/10")
        print(f"  → Statut: {status}")
        print(f"  → Score de réputation (VirusTotal): {virustotal_score}/100\n")

if __name__ == "__main__":
    asyncio.run(main())