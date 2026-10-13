import requests

SITES = [
    # Pagini obișnuite (Părțile 2, 3 și 4)
    "https://example.com",
    "https://httpbin.org/html",
    "https://httpbin.org/json",
    "https://httpbin.org/status/200",
    "https://httpbin.org/redirect/1",
    "https://httpbin.org/delay/2",
    # Pagini care eșuează
    "https://httpbin.org/status/404",
    "https://httpbin.org/status/500",
    "https://httpbin.org/delay/10",
    "http://this-site-does-not-exist.invalid",
    # Anteturi de securitate (Partea 5)
    "https://httpbin.org/response-headers?X-Frame-Options=DENY&X-Content-Type-Options=nosniff",
    "https://httpbin.org/response-headers?x-frame-options=DENY",
    # Răspunde aleatoriu cu 200 sau 500 (Partea 6)
    "https://httpbin.org/status/200,500",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def build_url(host, path):
    return "https://" + host.rstrip("/") + "/" + path.lstrip("/")


def is_https(url):
    return url.startswith("https://")


def show_response(url):
    try:
        r = requests.get(url, timeout=5)
        print("Status:", r.status_code)
        print("Content-Type:", r.headers.get("Content-Type", "unknown"))
    except requests.RequestException as e:
        print("Eroare:", e)


def check_site(url):
    try:
        r = requests.get(url, timeout=5)
        return {
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type", "unknown"),
            "length": len(r.content),
            "server": r.headers.get("Server", "unknown"),
        }
    except requests.RequestException as e:
        return {"status": None, "error": str(e)[:120]}


def scan_sites():
    results = []
    for url in SITES:
        results.append((url, check_site(url)))

    ok = [x for x in results if x[1]["status"] == 200]
    ok.sort(key=lambda x: x[1]["length"], reverse=True)

    for url, res in ok:
        print(url, "-> 200,", res["length"], "octeți")

    print("Reușite:", len(ok), "| Eșuate:", len(results) - len(ok))


def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
        names = [h.lower() for h in r.headers]
        present = []
        missing = []
        for h in SECURITY_HEADERS:
            if h.lower() in names:
                present.append(h)
            else:
                missing.append(h)
        score = len(present) * 100 // len(SECURITY_HEADERS)
        return {"present": present, "missing": missing, "score": score}
    except requests.RequestException as e:
        return {"status": None, "error": str(e)}


def retry_check(url, attempts=3):
    count = 0
    status = None
    for i in range(attempts):
        count += 1
        try:
            r = requests.get(url, timeout=5)
            status = r.status_code
            if status < 500:
                break
        except requests.RequestException:
            status = None
    return {"status": status, "attempts": count}
