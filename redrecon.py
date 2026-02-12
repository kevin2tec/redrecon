import requests
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ==============================
# CONFIG
# ==============================

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) RedRecon/4.5"
TIMEOUT = 8

# ==============================
# UTILITIES
# ==============================

def fetch(url):
    headers = {"User-Agent": USER_AGENT}
    return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)

def resolve_dns(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def detect_hosting(headers):
    server = headers.get("Server", "").lower()

    if "cloudflare" in headers.get("CF-Ray", "").lower():
        return "Cloudflare"
    if "vercel" in server:
        return "Vercel"
    if "netlify" in server:
        return "Netlify"
    if "supabase" in server:
        return "Supabase"
    if "nginx" in server:
        return "Nginx"
    if "apache" in server:
        return "Apache"

    return server if server else "Unknown"

def inspect_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert.get("notAfter")
    except:
        return None

# ==============================
# HEADER ANALYSIS
# ==============================

def analyze_headers(headers):
    table = Table(title="Security Headers", box=box.ROUNDED)
    table.add_column("Header")
    table.add_column("Value")

    important = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Access-Control-Allow-Origin"
    ]

    for h in important:
        table.add_row(h, headers.get(h, "Missing"))

    console.print(table)

    csp = headers.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        console.print("[red][!] Weak CSP detected[/red]")

    if headers.get("Access-Control-Allow-Origin") == "*":
        console.print("[red][!] Wildcard CORS Enabled[/red]")

# ==============================
# JS EXTRACTION
# ==============================

def extract_js_urls(base_url, html):
    pattern = r'<script[^>]+src="([^"]+)"'
    matches = re.findall(pattern, html)
    return list(set([urljoin(base_url, m) for m in matches]))

# ==============================
# SECRET DETECTION
# ==============================

def scan_secrets(content):
    findings = []

    patterns = {
        "JWT": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Key": r"pk_live_[0-9a-zA-Z]{24,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for m in matches:
            findings.append((name, m[:35] + "..."))

    return findings

# ==============================
# SOURCE-SINK CORRELATION
# ==============================

def analyze_dom_flows(content):
    sources = []
    sinks = []

    source_patterns = ["location.search", "location.hash", "URLSearchParams"]
    sink_patterns = ["innerHTML", "dangerouslySetInnerHTML", "eval(", "document.write"]

    for s in source_patterns:
        if s in content:
            sources.append(s)

    for s in sink_patterns:
        if s in content:
            sinks.append(s)

    return sources, sinks

# ==============================
# ENDPOINT EXTRACTION
# ==============================

def extract_endpoints(content):
    pattern = r"https?://[^\s\"']+"
    urls = re.findall(pattern, content)
    return list(set([u for u in urls if "example.com" not in u and "..." not in u]))

# ==============================
# TECH DETECTION
# ==============================

def detect_tech(content):
    tech = []

    content_lower = content.lower()

    if "supabase" in content_lower:
        tech.append("Supabase")
    if "firebase" in content_lower:
        tech.append("Firebase")
    if "stripe" in content_lower:
        tech.append("Stripe")
    if "gtag(" in content:
        tech.append("Google Analytics")
    if "sentry.init" in content_lower:
        tech.append("Sentry")
    if "react" in content_lower:
        tech.append("React")
    if "vue" in content_lower:
        tech.append("Vue")

    return tech

# ==============================
# PORT SCANNING (OPTIONAL)
# ==============================

def scan_port(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            sock.close()
            return port
        sock.close()
    except:
        pass
    return None

def scan_common_ports(ip):
    ports = [21,22,25,53,80,110,143,443,3306,3389,8080,8443]
    open_ports = []

    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(scan_port, ip, p) for p in ports]
        for f in futures:
            result = f.result()
            if result:
                open_ports.append(result)

    return open_ports

# ==============================
# MAIN ENGINE
# ==============================

def main():
    url = input("Enter target URL: ").strip()
    active_scan = input("Enable port scan? (y/N): ").lower() == "y"

    console.print(Panel(f"[bold cyan]RedRecon Enhanced Engine[/bold cyan]\nTarget: {url}"))

    try:
        response = fetch(url)
    except Exception as e:
        console.print(f"[red]Connection error: {e}[/red]")
        return

    for r in response.history:
        console.print(f"[yellow]Redirected: {r.url}[/yellow]")

    domain = urlparse(url).hostname
    ip = resolve_dns(domain)
    ssl_expiry = inspect_ssl(domain)

    console.print(f"\n[bold]IP Address:[/bold] {ip if ip else 'Resolution Failed'}")
    console.print(f"[bold]Hosting:[/bold] {detect_hosting(response.headers)}")

    if ssl_expiry:
        console.print(f"[bold]SSL Expiry:[/bold] {ssl_expiry}")

    analyze_headers(response.headers)

    html = response.text
    js_urls = extract_js_urls(url, html)

    console.print(f"\n[bold]Discovered JS Files:[/bold] {len(js_urls)}")

    all_secrets = []
    all_sources = []
    all_sinks = []
    all_endpoints = []
    all_tech = []

    def process_js(js):
        try:
            js_response = fetch(js)
            content = js_response.text
            return (
                scan_secrets(content),
                analyze_dom_flows(content),
                extract_endpoints(content),
                detect_tech(content)
            )
        except:
            return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(process_js, js_urls)

    for r in results:
        if r:
            secrets, flows, endpoints, tech = r
            sources, sinks = flows
            all_secrets.extend(secrets)
            all_sources.extend(sources)
            all_sinks.extend(sinks)
            all_endpoints.extend(endpoints)
            all_tech.extend(tech)

    if all_secrets:
        console.print("\n[bold red]Potential Exposed Secrets:[/bold red]")
        for name, value in set(all_secrets):
            console.print(f"[red]- {name}: {value}[/red]")

    if all_sources and all_sinks:
        console.print("\n[bold red][!] DOM XSS Surface Detected[/bold red]")

    if all_endpoints:
        console.print("\n[bold green]External Endpoints:[/bold green]")
        for e in set(all_endpoints):
            console.print(f"[green]{e}[/green]")

    if all_tech:
        console.print("\n[bold cyan]Detected Technologies:[/bold cyan]")
        for t in set(all_tech):
            console.print(f"[cyan]- {t}[/cyan]")

    if active_scan and ip:
        console.print("\n[bold magenta]Scanning Common Ports...[/bold magenta]")
        open_ports = scan_common_ports(ip)
        if open_ports:
            for p in open_ports:
                console.print(f"[green]Port {p} OPEN[/green]")
        else:
            console.print("[yellow]No common open ports detected[/yellow]")

    console.print("\n[bold magenta]Recon Complete[/bold magenta]")


if __name__ == "__main__":
    main()
