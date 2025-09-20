import requests
import os
import json
import semver
import argparse
from pathlib import Path
import getpass

TOOL_NAME = r"""
███╗░░██╗██████╗░███╗░░░███╗██████╗░░██████╗░██╗░░░██╗░█████╗░██████╗░██████╗░
████╗░██║██╔══██╗████╗░████║╚════██╗██╔════╝░██║░░░██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗██║██████╔╝██╔████╔██║░░███╔═╝██║░░██╗░██║░░░██║███████║██████╔╝██║░░██║
██║╚████║██╔═══╝░██║╚██╔╝██║██╔══╝░░██║░░╚██╗██║░░░██║██╔══██║██╔══██╗██║░░██║
██║░╚███║██║░░░░░██║░╚═╝░██║███████╗╚██████╔╝╚██████╔╝██║░░██║██║░░██║██████╔╝
╚═╝░░╚══╝╚═╝░░░░░╚═╝░░░░░╚═╝╚══════╝░╚═════╝░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░


                        ▂▃▅▇█▓▒░ By Muthu D ░▒▓█▇▅▃▂
                        https://www.linkedin.com/in/anonysm
"""

COMPROMISED_PACKAGES = {
    "chalk": ">=5.0.0 <5.0.5",
    "debug": ">=4.3.1 <4.3.3",
    "ansi-styles": ">=4.3.0 <4.3.4",
    "@ctrl/tinycolor": "*",
    "minimist": ">=1.2.6 <1.2.11",
    "strip-ansi": ">=6.0.0 <6.0.3",
    "camelcase": ">=6.2.0 <6.2.1",
    "micromatch": ">=4.0.0 <4.0.4",
    "wordwrap": "*"
}

TARGET_FILES = ['package.json', 'package-lock.json', 'yarn.lock']

CONFIG_DIR = Path.home() / '.npm-supply-chain-scanner'
CONFIG_FILE = CONFIG_DIR / 'config.json'

def save_token(token):
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'github_token': token}, f)

def load_token():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
            return data.get('github_token')
    return None

def prompt_github_token():
    print("[*] Please enter your GitHub Personal Access Token (Fine-grained token starting with 'github_pat_'):")
    token = getpass.getpass(prompt="Token (leave blank to skip): ").strip()
    if token:
        if not token.startswith("github_pat_"):
            print("[!] Warning: Recommended to use a fine-grained token starting with 'github_pat_'")
        save_token(token)
        print("[*] Token saved for future runs.\n")
        return token
    print("[!] No token entered. Will proceed unauthenticated (limited API rate limit).\n")
    return None

class NpmSupplyChainScanner:
    def __init__(self, github_token, org_name):
        self.token = github_token
        self.org = org_name
        self.headers = {'Authorization': f'token {self.token}'} if self.token else {}
        self.base_api = 'https://api.github.com'
        self.download_dir = f'downloaded_files_{self.org}'
        os.makedirs(self.download_dir, exist_ok=True)

    def get_repos(self):
        repos = []
        page = 1
        print(f"[+] Fetching repos for org '{self.org}'...")
        while True:
            url = f'{self.base_api}/orgs/{self.org}/repos?per_page=100&page={page}'
            r = requests.get(url, headers=self.headers)
            if r.status_code == 404:
                print(f"[-] Organization '{self.org}' not found or inaccessible.")
                break
            if r.status_code != 200:
                print(f"[-] Failed to fetch repos for '{self.org}', status code {r.status_code}.")
                break
            data = r.json()
            if not data:
                break
            repos.extend([repo['name'] for repo in data])
            page += 1
        print(f"[+] Found {len(repos)} repositories in '{self.org}'.")
        return repos

    def get_default_branch_sha(self, repo):
        url = f'{self.base_api}/repos/{self.org}/{repo}'
        r = requests.get(url, headers=self.headers)
        if r.status_code != 200:
            return None
        repo_info = r.json()
        default_branch = repo_info.get('default_branch')
        if not default_branch:
            return None
        ref_url = f'{self.base_api}/repos/{self.org}/{repo}/git/ref/heads/{default_branch}'
        r2 = requests.get(ref_url, headers=self.headers)
        if r2.status_code != 200:
            return None
        ref_info = r2.json()
        return ref_info.get('object', {}).get('sha')

    def get_tree(self, repo, sha):
        url = f'{self.base_api}/repos/{self.org}/{repo}/git/trees/{sha}?recursive=1'
        r = requests.get(url, headers=self.headers)
        if r.status_code != 200:
            return None
        return r.json()

    def download_file(self, repo, path):
        url = f'{self.base_api}/repos/{self.org}/{repo}/contents/{path}'
        r = requests.get(url, headers=self.headers)
        if r.status_code != 200:
            return None
        content = r.json()
        download_url = content.get('download_url')
        if not download_url:
            return None
        file_data = requests.get(download_url).content
        safe_filename = f"{repo}-{path.replace('/', '_')}"
        filepath = os.path.join(self.download_dir, safe_filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        return filepath

    def is_version_vulnerable(self, version, vuln_range):
        if vuln_range == '*':
            return True
        try:
            return semver.VersionInfo.parse(version) in semver.Range(vuln_range)
        except ValueError:
            return False

    def scan_package_lock_json(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        vulnerable_found = []
        dependencies = data.get('dependencies') or {}
        for pkg_name, pkg_info in dependencies.items():
            if pkg_name in COMPROMISED_PACKAGES:
                vuln_range = COMPROMISED_PACKAGES[pkg_name]
                version = pkg_info.get('version')
                if version and self.is_version_vulnerable(version, vuln_range):
                    vulnerable_found.append((pkg_name, version))
        return vulnerable_found

    def scan_package_json(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        vulnerable_found = []
        deps_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
        for section in deps_sections:
            deps = data.get(section, {})
            for pkg_name, version_spec in deps.items():
                if pkg_name in COMPROMISED_PACKAGES:
                    vuln_range = COMPROMISED_PACKAGES[pkg_name]
                    if vuln_range == '*' or vuln_range in version_spec:
                        vulnerable_found.append((pkg_name, version_spec))
        return vulnerable_found

    def scan_yarn_lock(self, filepath):
        vulnerable_found = []
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        lines = content.split('\n')
        current_pkg = None
        for line in lines:
            if line and not line.startswith(' ') and line.endswith(':'):
                parts = line.split('@')
                if len(parts) > 1:
                    current_pkg = parts[0]
                else:
                    current_pkg = None
            elif current_pkg and line.strip().startswith('version'):
                version = None
                try:
                    version = line.strip().split(' ')[1].strip('"')
                except:
                    pass
                if version and current_pkg in COMPROMISED_PACKAGES:
                    vuln_range = COMPROMISED_PACKAGES[current_pkg]
                    if self.is_version_vulnerable(version, vuln_range):
                        vulnerable_found.append((current_pkg, version))
                current_pkg = None
        return vulnerable_found

    def scan_file(self, filepath):
        fname = os.path.basename(filepath)
        if fname == 'package-lock.json':
            return self.scan_package_lock_json(filepath)
        elif fname == 'package.json':
            return self.scan_package_json(filepath)
        elif fname == 'yarn.lock':
            return self.scan_yarn_lock(filepath)
        else:
            return []

    def run(self):
        print(TOOL_NAME)
        repos = self.get_repos()
        overall_results = {}

        for repo in repos:
            print(f"\n[+] Scanning repo: {repo}")
            sha = self.get_default_branch_sha(repo)
            if not sha:
                print(f"[-] Cannot find default branch SHA for {repo}, skipping.")
                continue

            tree = self.get_tree(repo, sha)
            if not tree or 'tree' not in tree:
                print(f"[-] Cannot fetch tree for {repo}, skipping.")
                continue

            found_files = []
            for file in tree['tree']:
                if file['type'] == 'blob' and any(file['path'].endswith(tf) for tf in TARGET_FILES):
                    found_files.append(file['path'])

            if not found_files:
                print("[-] No dependency files found in this repo.")
                continue

            repo_vulns = {}

            for file_path in found_files:
                filepath = self.download_file(repo, file_path)
                if not filepath:
                    print(f"[-] Failed to download {file_path}")
                    continue
                vulns = self.scan_file(filepath)
                if vulns:
                    repo_vulns[file_path] = vulns

            if repo_vulns:
                overall_results[repo] = repo_vulns
                print(f"[!] Vulnerabilities found in repo: {repo}")
            else:
                print("[+] No vulnerabilities found in this repo.")

        print("\n### Scan Summary ###")
        if not overall_results:
            print("No compromised packages found in any repo.")
        else:
            for repo, files in overall_results.items():
                print(f"Repo: {repo}")
                for file, vulns in files.items():
                    print(f"  File: {file}")
                    for pkg, ver in vulns:
                        print(f"    - {pkg} (version {ver}) is vulnerable.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='NPM Supply Chain Vulnerability Scanner\nUse --org or --org-file to specify organization(s) to scan.'
    )
    parser.add_argument('--org', help='GitHub organization name to scan')
    parser.add_argument('--org-file', help='File with list of GitHub organizations, one per line')
    args = parser.parse_args()

    if not args.org and not args.org_file:
        print('Error: You must specify either --org or --org-file')
        exit(1)

    token = load_token()

    if not token:
        # no saved token found, prompt user for one
        token = prompt_github_token()

    if args.org:
        scanner = NpmSupplyChainScanner(token, args.org)
        scanner.run()

    if args.org_file:
        with open(args.org_file, 'r') as f:
            for line in f:
                org = line.strip()
                if org:
                    print(f'\n\n=== Scanning organization: {org} ===')
                    scanner = NpmSupplyChainScanner(token, org)
                    scanner.run()
