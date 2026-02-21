import requests
import mmh3
import codecs
import argparse
import socket
import shodan
import sqlite3
import subprocess
import concurrent.futures
import random
from datetime import datetime
from colorama import Fore, Style, init


init(autoreset=True)


SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]


def init_db():
    """Initializes the SQLite database to store findings."""
    conn = sqlite3.connect('tifa_scans.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (target TEXT, ip TEXT, favicon_hash TEXT, vulnerabilities TEXT, severity TEXT, scan_date TEXT)''')
    conn.commit()
    conn.close()

def save_result(target, ip, fav_hash, vulns, severity="Info"):
    """Saves a single scan result to the database."""
    conn = sqlite3.connect('tifa_scans.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", 
              (target, ip, str(fav_hash), vulns, severity, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class TifaEngine:
    def __init__(self, target):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.clean_host = self.target.replace("http://", "").replace("https://", "").split('/')[0]
        self.ip = self._resolve_ip()
        self.found_vulns = []

    def _resolve_ip(self):
        try:
            return socket.gethostbyname(self.clean_host)
        except:
            return "N/A"

    def get_favicon_hash(self):
        """Fingerprints the server using Favicon Hash to bypass hidden banners."""
        fav_url = f"{self.target.rstrip('/')}/favicon.ico"
        try:
            res = requests.get(fav_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=5, verify=False)
            if res.status_code == 200:
                favicon = codecs.encode(res.content, 'base64')
                return mmh3.hash(favicon)
        except:
            pass
        return "None"

    def run_shodan(self):
        """Passive Recon using Shodan API."""
        if self.ip == "N/A": return "No IP"
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            results = api.host(self.ip)
            data = f"Org: {results.get('org', 'N/A')} | OS: {results.get('os', 'N/A')}"
            return data
        except:
            return "Shodan Error"

    def run_nuclei(self):
        """Active Vulnerability Verification using Nuclei."""
        print(f"{Fore.MAGENTA}[*] Nuclei checking: {self.target}")
        try:
            cmd = ["nuclei", "-u", self.target, "-silent", "-nc", "-severity", "critical,high"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.stdout.strip() if res.stdout else None
        except FileNotFoundError:
            return "Nuclei not installed"

    def scan_pipeline(self):
        """Executes the full scan logic for a single target."""
        print(f"{Fore.CYAN}[*] Starting Scan: {self.target}")
        
        fav_hash = self.get_favicon_hash()
        shodan_info = self.run_shodan()
        nuclei_results = self.run_nuclei()
        
        severity = "Info"
        results_summary = f"Shodan: {shodan_info}"
        
        if nuclei_results:
            severity = "CRITICAL"
            results_summary += f" | Nuclei: {nuclei_results}"
            print(f"{Fore.RED}[!!!] CRITICAL FOUND on {self.target}")
        
        save_result(self.target, self.ip, fav_hash, results_summary, severity)


def show_dashboard():
    """Displays critical findings from the database in a table format."""
    conn = sqlite3.connect('tifa_scans.db')
    c = conn.cursor()
    c.execute("SELECT target, ip, severity, scan_date FROM scans WHERE severity='CRITICAL'")
    rows = c.fetchall()
    
    print(f"\n{Fore.RED}{'='*70}\n       TIFA SECURITY SUITE - CRITICAL TARGETS DASHBOARD\n{'='*70}")
    if not rows:
        print(f"{Fore.WHITE} No critical targets found yet.")
    else:
        print(f"{Fore.YELLOW}{'TARGET':<30} | {'IP':<15} | {'DATE'}")
        print("-" * 70)
        for row in rows:
            print(f"{Fore.GREEN}{row[0]:<30} | {row[1]:<15} | {row[3]}")
    conn.close()

def print_banner():
    print(f"""{Fore.RED}
    ████████╗██╗███████╗ █████╗     ███████╗██╗   ██╗██╗████████╗███████╗
    ╚══██╔══╝██║██╔════╝██╔══██╗    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
       ██║   ██║█████╗  ███████║    ███████╗██║   ██║██║   ██║   █████╗  
       ██║   ██║██╔══╝  ██╔══██║    ╚════██║██║   ██║██║   ██║   ██╔══╝  
       ██║   ██║██║     ██║  ██║    ███████║╚██████╔╝██║   ██║   ███████╗
       ╚═╝   ╚═╝╚═╝     ╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
    {Fore.WHITE}             >> Tifa-TVE Massive Vulnerability Engine github -> https://github.com/Tifa400<<
    """)


if __name__ == "__main__":
    init_db()
    print_banner()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Scan a single URL")
    parser.add_argument("-f", "--file", help="Scan multiple targets from a file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--show", help="Display all critical findings from DB", action="store_true")
    
    args = parser.parse_args()

    if args.show:
        show_dashboard()
    elif args.url:
        TifaEngine(args.url).scan_pipeline()
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"{Fore.BLUE}[*] Mass Scanning {len(targets)} targets with {args.threads} threads...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                executor.map(lambda t: TifaEngine(t).scan_pipeline(), targets)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}")
    else:
        parser.print_help()