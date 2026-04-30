import requests
import json
from datetime import datetime

DISCORD_WEBHOOK_URL = "PASTE_YOUR_WEBHOOK_URL_HERE"

DISCORD_ENABLED = True


def send_discord_alert(event_type, file_path, severity, mitre_technique, action_taken=""):
    if not DISCORD_ENABLED or DISCORD_WEBHOOK_URL == "PASTE_YOUR_WEBHOOK_URL_HERE":
        return False
    
    color_map = {
        "HIGH": 15158332,
        "MEDIUM": 15844367,
        "LOW": 3066993
    }
    color = color_map.get(severity, 9807270)
    
    embed = {
        "title": f"FIM Alert: {event_type}",
        "description": f"**Severity:** {severity}",
        "color": color,
        "fields": [
            {"name": "File Path", "value": f"`{file_path}`", "inline": False},
            {"name": "MITRE ATT&CK", "value": mitre_technique or "N/A", "inline": True},
            {"name": "Severity", "value": severity, "inline": True},
        ],
        "footer": {"text": "Real-Time File Integrity Monitor"},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if action_taken:
        embed["fields"].append({"name": "Action Taken", "value": action_taken, "inline": False})
    
    payload = {
        "username": "FIM Bot",
        "embeds": [embed]
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        return response.status_code == 204
    except Exception as e:
        print(f"  -> Discord alert failed: {e}")
        return False