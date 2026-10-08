import sys
import threading
import time
import webbrowser
import uvicorn
from lab.live_traffic_generator import run_live_generator


def main():
    print("=" * 60)
    print("  NetGuard IDS - All-in-One Live Demo Runner")
    print("=" * 60)
    print("[*] Starting continuous background traffic & attack generator...")

    # Start live traffic generator in a background daemon thread
    gen_thread = threading.Thread(
        target=run_live_generator,
        kwargs={"db_path": "netguard.db", "interval": 4.0},
        daemon=True
    )
    gen_thread.start()

    # Automatically open browser after 1.5 seconds
    def open_browser():
        time.sleep(1.5)
        print("[*] Opening dashboard at http://localhost:8000 ...")
        webbrowser.open("http://localhost:8000")

    threading.Thread(target=open_browser, daemon=True).start()

    print("[*] Starting FastAPI Web Server & Dashboard on http://localhost:8000 ...")
    print("[*] Press Ctrl+C in this terminal to stop everything.\n")

    # Run Uvicorn server in the main thread
    try:
        uvicorn.run("netguard.api.main:app", host="127.0.0.1", port=8000, log_level="info")
    except KeyboardInterrupt:
        print("\n[*] Shutting down NetGuard IDS demo. Goodbye!")


if __name__ == "__main__":
    main()
