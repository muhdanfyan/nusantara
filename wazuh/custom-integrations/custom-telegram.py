#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests
import os

# Konfigurasi Telegram Bot
# Ganti dengan Token Bot dan Chat ID Anda
CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '846880203')
BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8810225012:AAErJCcVG7CBgJe-Zn6hZ6rzsJzKHZjPGK4')

def send_telegram_alert(alert_json):
    try:
        # Load JSON log dari stdin (Wazuh mengirimnya via argumen atau stdin)
        alert_data = json.loads(alert_json)
        
        rule_level = alert_data.get('rule', {}).get('level', 0)
        rule_desc = alert_data.get('rule', {}).get('description', 'No description')
        agent_name = alert_data.get('agent', {}).get('name', 'Unknown Agent')
        
        # Ekstrak data VirusTotal jika tersedia
        vt_positives = alert_data.get('data', {}).get('virustotal', {}).get('positives', 0)
        vt_permalink = alert_data.get('data', {}).get('virustotal', {}).get('permalink', 'N/A')
        
        # Ekstrak data file (FIM)
        file_path = alert_data.get('syscheck', {}).get('path', 'Unknown Path')
        
        message = (
            f"🚨 *T-GUARD MALWARE ALERT* 🚨\n\n"
            f"💻 *Agent:* {agent_name}\n"
            f"📊 *Level:* {rule_level}\n"
            f"📝 *Deskripsi:* {rule_desc}\n"
            f"📂 *Target File:* `{file_path}`\n\n"
            f"🦠 *VirusTotal Positives:* {vt_positives}\n"
            f"🔗 *Detail VT:* [Klik di Sini]({vt_permalink})\n\n"
            f"🛠 *Status:* Proses *Active Response* (Penghapusan File) sedang dijalankan."
        )
        
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            with open('/var/log/custom-telegram.log', 'a') as log_file:
                log_file.write(f"Alert sent to Telegram successfully for rule level {rule_level}\n")
        else:
            with open('/var/log/custom-telegram.log', 'a') as log_file:
                log_file.write(f"Failed to send alert. Status code: {response.status_code}. Response: {response.text}\n")
                
    except Exception as e:
        with open('/var/log/custom-telegram.log', 'a') as log_file:
            log_file.write(f"Error processing alert: {str(e)}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Wazuh passes the path to the alerts.json file as the first argument
        alert_file_path = sys.argv[1]
        with open(alert_file_path, 'r') as file:
            alert_json = file.read()
            send_telegram_alert(alert_json)
