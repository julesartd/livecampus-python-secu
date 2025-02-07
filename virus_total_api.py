import aiohttp
from typing import Optional

# IMPORTANT: VIRUS TOTAL AUTORISE 4 REQUETES PAR MINUTE AVEC UNE CLE API GRATUITE
# J'AI 4 URLS dans mon fichier urls.txt donc je vais faire 4 requetes, donc attrndre 1 minute avant de relancer l'exo 3
# https://docs.virustotal.com/reference/public-vs-premium-api

VIRUSTOTAL_API_KEY = '67d7d1b7764edb63282261917b847010f4271a66fe358b174be3947b98a0380e'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3'

async def get_virustotal_analysis_id(url: str) -> Optional[str]:
    """Envoie l'URL à VirusTotal pour l'analyser et retourne un ID d'analyse."""
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        data = {
            'url': url
        }
        endpoint = f"{VIRUSTOTAL_URL}/urls"
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, headers=headers, data=data) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['data']['id']
                else:
                    print(f"Erreur lors de l'envoi de l'URL à VirusTotal: {response.status} - {await response.text()}")
                    return None
    except Exception as e:
        print(f"Exception lors de l'envoi de l'URL à VirusTotal: {e}")
        return None

async def get_virustotal_report(analysis_id: str) -> int:
    """Récupère le rapport d'analyse de VirusTotal à partir de l'ID d'analyse."""
    total_score: int = 0
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        endpoint = f"{VIRUSTOTAL_URL}/analyses/{analysis_id}"
    
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                    print(f"STATS: {stats}")
                    total_score = sum(stats.values())
            
                else:
                    print(f"Erreur lors de la récupération du rapport VirusTotal: {response.status} - {await response.text()}")
        return total_score
                
    except Exception as e:
        print(f"Exception lors de la récupération du rapport VirusTotal: {e}")
        return total_score
    
