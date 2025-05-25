from flask import Flask, send_from_directory, jsonify, request
import os
import json
import requests
import logging
import time
import hashlib
from threading import Thread
from retrying import retry

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

WEBHOOK_SECRET = ""  # Set this for security
FILES_TO_MONITOR = ["botard_alert.json", "", ""]
CHECK_INTERVAL = 5
TRADINGVIEW_WEBHOOK_URL = "https://botard-server.onrender.com"  # Replace with actual ngrok URL

@retry(stop_max_attempt_number=3, wait_fixed=5000)
def send_webhook_to_tradingview(rules):
    headers = {"Content-Type": "application/json"}
    payload = {
        "message": rules.get("message", "BOTARD SIGNAL"),
        "symbol": "XAUUSD",
        "action": rules.get("signal", "buy"),
        "confidence": rules.get("confidence", 0),
        "price": rules.get("price", 0),
        "quantity": rules.get("position_size", 1.0),
        "open": rules.get("open", 0),
        "high": rules.get("high", 0),
        "low": rules.get("low", 0),
        "volume": rules.get("volume", 0),
        "money_flow": rules.get("money_flow", 0),
        "hyperwave": rules.get("hyperwave", 0),
        "soft_signal_prob": rules.get("soft_signal_prob", 0.0),
        "confluence": rules.get("confluence_meter", 0),
        "timestamp": rules.get("timestamp"),
        "source": "bot"
    }
    simple_message = f"{payload.get('symbol', 'XAUUSD')} {payload.get('signal', '').upper()} @ {payload.get('price', '???')}"
    response = requests.post(TRADINGVIEW_WEBHOOK_URL, json={"message": simple_message})
    response.raise_for_status()
    logger.info(f"📤 Webhook payload sent: {simple_message}")


@app.route("/files/<path:filename>")
def serve_file(filename):
    try:
        return send_from_directory(os.getcwd(), filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return jsonify({"error": str(e)}), 404

@app.route("/signal")
def get_signal():
    try:
        with open("botard_alert.json", "r") as f:
            return jsonify(json.load(f))
    except Exception as e:
        logger.error(f"Error reading botard_alert.json: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/webhook", methods=["POST"])
def receive_webhook():
    try:
        if WEBHOOK_SECRET:
            auth_header = request.headers.get("X-Webhook-Secret")
            if auth_header != WEBHOOK_SECRET:
                logger.warning("Invalid webhook secret")
                return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json(silent=True) or request.form
        if not data:
            logger.warning("No payload received in webhook")
            return jsonify({"error": "No payload"}), 400

        logger.info(f"Received webhook payload: {data}")
        with open("webhook_log.json", "a") as f:
            json.dump({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "data": dict(data)}, f)
            f.write("\n")

        if data.get("source") == "bot":
            logger.info("Bot-generated signal received. Skipping rule file update.")
            return jsonify({"status": "success", "message": "Bot signal processed"}), 200

        rules = {
            "message": data.get("message", "Alert from TradingView"),
            "signal": data.get("action", "buy"),
            "open": float(data.get("open", data.get("price", 0))),
            "high": float(data.get("high", data.get("price", 0))),
            "low": float(data.get("low", data.get("price", 0))),
            "close": float(data.get("price", 0)),
            "price": float(data.get("price", 0)),
            "volume": float(data.get("volume", 0)),
            "money_flow": float(data.get("money_flow", 50.0)),
            "hyperwave": float(data.get("hyperwave", 88.727)),
            "bull_confidence": f"{float(data.get('confidence', 100))}%",
            "confidence": float(data.get("confidence", 100)),
            "position_size": float(data.get("quantity", 1.0)),
            "soft_signal_prob": float(data.get("soft_signal_prob", 0.0)),
            "confluence_meter": int(data.get("confluence", 50)),
            "timestamp": data.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
        }

        rules_file = "rules_urgent.json" if "urgent" in data.get("message", "").lower() else "rules.json"
        with open(rules_file, "w") as f:
            json.dump(rules, f, indent=4)
        logger.info(f"Updated {rules_file} based on external alert")
        return jsonify({"status": "success", "message": "Webhook processed"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({"error": str(e)}), 500

def get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {filepath}: {e}")
        return None

@app.route('/signal-text')
def signal_text():
    try:
        with open("botard_alert.json", "r") as f:
            signal_data = json.load(f)
        return signal_data["signal"]
    except Exception as e:
        return "none"

def monitor_rules_files():
    last_hashes = {file: None for file in FILES_TO_MONITOR}
    while True:
        try:
            for file in FILES_TO_MONITOR:
                if os.path.exists(file):
                    current_hash = get_file_hash(file)
                    if current_hash and current_hash != last_hashes[file]:
                        logger.info(f"Detected update to {file}")
                        with open(file, "r") as f:
                            rules = json.load(f)
                        send_webhook_to_tradingview(rules)
                        last_hashes[file] = current_hash
                else:
                    logger.warning(f"{file} not found")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            logger.error(f"Error in monitor loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_thread = Thread(target=monitor_rules_files, daemon=True)
    monitor_thread.start()
    logger.info("Started monitoring botard_alert.json and rules_urgent.json")
    app.run(host='0.0.0.0', port=8000, debug=False)

