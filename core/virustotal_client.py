import os
import json
import httpx

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

def load_vt_api_key():
    """
    Loads VirusTotal API key from config.json.
    """
    if not os.path.exists(CONFIG_PATH):
        # Create empty template
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump({"virustotal_api_key": ""}, f, indent=2)
        except Exception:
            pass
        return ""
    
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
            return data.get("virustotal_api_key", "").strip()
    except Exception:
        return ""

async def check_hash_vt(file_hash):
    """
    Checks the file hash against VirusTotal API v3.
    Returns a dict with VT results or raises exception.
    """
    api_key = load_vt_api_key()
    if not api_key:
        return {
            "status": "missing_key",
            "message": "Sin API Key en config.json. Solo se muestran datos locales."
        }
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    # 10s timeout
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + undetected + harmless
                
                # Simple verdict logic
                if malicious > 3:
                    verdict = "MALICIOSO"
                elif malicious > 0 or suspicious > 1:
                    verdict = "SOSPECHOSO"
                else:
                    verdict = "SEGURO / INDETECTADO"
                    
                return {
                    "status": "success",
                    "detections": f"{malicious}/{total}",
                    "verdict": verdict,
                    "malicious": malicious,
                    "total": total,
                    "stats": stats
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "Archivo no encontrado en la base de datos de VirusTotal."
                }
            elif response.status_code == 401 or response.status_code == 403:
                return {
                    "status": "error",
                    "message": "API Key inválida o no autorizada."
                }
            elif response.status_code == 429:
                return {
                    "status": "error",
                    "message": "Límite de solicitudes de VirusTotal excedido (4 req/min)."
                }
            else:
                return {
                    "status": "error",
                    "message": f"Error de VirusTotal (HTTP {response.status_code})."
                }
        except httpx.RequestError as exc:
            return {
                "status": "error",
                "message": f"Error de red: {str(exc)}"
            }
