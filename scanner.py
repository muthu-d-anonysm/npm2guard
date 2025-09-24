import requests
import os
import json
import argparse
from pathlib import Path
import getpass
from semantic_version import Version, NpmSpec

# ------------------ Tool Banner ------------------
TOOL_NAME = r"""
███╗░░██╗██████╗░███╗░░░███╗██████╗░░██████╗░██╗░░░██╗░█████╗░██████╗░██████╗░
████╗░██║██╔══██╗████╗░████║╚════██╗██╔════╝░██║░░░██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗██║██████╔╝██╔████╔██║░░███╔═╝██║░░██╗░██║░░░██║███████║██████╔╝██║░░██║
██║╚████║██╔═══╝░██║╚██╔╝██║██╔══╝░░██║░░╚██╗██║░░░██║██╔══██║██╔══██╗██║░░██║
██║░╚███║██║░░░░░██║░╚═╝░██║███████╗╚██████╔╝╚██████╔╝██║░░██║██║░░██║██████╔╝
╚═╝░░╚══╝╚═╝░░░░░╚═╝░░░░░╚═╝╚══════╝░╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░


                                    ▂▃▅▇█▓▒░ By Muthu D ░▒▓█▇▅▃▂ 
                                    https://www.linkedin.com/in/anonysm

"""

# ------------------ Vulnerable Packages ------------------
COMPROMISED_PACKAGES = {
    "chalk": ">=5.0.0 <5.0.5",
    "express": ">=4.0.0 <4.18.3",
    "lodash": "<4.17.21",
    "jquery": "<3.5.1",
    "axios": "<0.21.2",
    "react": ">=18.0.0 <18.2.1",
    "debug": "<=4.3.1",
    "is": ">=3.3.1 <5.0.0",
    "eslint-config-prettier": ">=6.0.0 <8.0.0",
    "eslint-plugin-prettier": ">=3.0.0 <4.0.0",
    "synckit": ">=1.0.0 <2.0.0",
    "@pkgr/core": ">=1.0.0 <2.0.0",
    "napi-postinstall": ">=1.0.0 <2.0.0",
    "@ctrl/tinycolor": ">=4.1.1 <4.1.3",
    "ngx-toastr": ">=14.0.0 <15.0.0",
    "angulartics2": ">=8.0.0 <9.0.0",
    "react-xterm2": ">=1.0.0 <2.0.0",
    "flipper-plugins": ">=1.0.0 <2.0.0",
    "react-xterm": ">=1.0.0 <2.0.0",
    "react-json-view": ">=1.0.0 <2.0.0",
    "react-virtualized": ">=9.0.0 <10.0.0",
    "react-table": ">=7.0.0 <8.0.0",
    "react-dnd": ">=14.0.0 <15.0.0",
    "react-dnd-html5-backend": ">=14.0.0 <15.0.0",
    "react-beautiful-dnd": ">=13.0.0 <14.0.0",
    "react-router": ">=6.0.0 <7.0.0",
    "react-router-dom": ">=6.0.0 <7.0.0",
    "react-redux": ">=8.0.0 <9.0.0",
    "redux": ">=5.0.0 <6.0.0",
    "redux-thunk": ">=3.0.0 <4.0.0",
    "redux-saga": ">=1.0.0 <2.0.0",
    "redux-form": ">=8.0.0 <9.0.0",
    "react-intl": ">=5.0.0 <6.0.0",
    "react-i18next": ">=11.0.0 <12.0.0",
    "react-bootstrap": ">=2.0.0 <3.0.0",
    "reactstrap": ">=9.0.0 <10.0.0",
    "react-select": ">=5.0.0 <6.0.0",
    "react-datepicker": ">=5.0.0 <6.0.0",
    "react-dropzone": ">=11.0.0 <12.0.0",
    "react-quill": ">=2.0.0 <3.0.0",
    "react-spring": ">=9.0.0 <10.0.0",
    "react-motion": ">=1.0.0 <2.0.0",
    "react-transition-group": ">=5.0.0 <6.0.0",
    "react-copy-to-clipboard": ">=5.0.0 <6.0.0",
    "react-clipboard.js": ">=1.0.0 <2.0.0",
    "react-copy-to-clipboard": ">=5.0.0 <6.0.0",
    "react-copy-to-clipboard": ">=5.0.0 <6.0.0",
    "react-copy-to-clipboard": ">=5.0.0 <6.0.0",
}

# ------------------ Terminal Colors ------------------
RED = "\033[91m"
RESET = "\033[0m"

# ------------------ Semver Helpers ------------------
def is_version_in_range(version, range_expr):
    try:
        spec = NpmSpec(range_expr)
        return Version(version.lstrip("^~")) in spec
    except Exception:
        return False

def is_version_vulnerable(installed_version, vulnerable_range):
    if vulnerable_range == "*":
        return True
    return is_version_in_range(installed_version, vulnerable_range)

# ------------------ GitHub Token Prompt ------------------
def get_github_token():
    token = getpass.getpass("Enter your GitHub Personal Access Token: ").strip()
    if not token:
        print("[!] No token provided. Only public repos will be scanned.")
        return None
    return token

# ------------------ Scan Dependency Functions ------------------
def scan_dependencies(dependencies, repo_name):
    vulns = []
    for dep, version in dependencies.items():
        if dep in COMPROMISED_PACKAGES:
            vuln_range = COMPROMISED_PACKAGES[dep]
            if is_version_vulnerable(version, vuln_range):
                vulns.append((dep, version, vuln_range))
    return vulns

def scan_file(filepath):
    vulns = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        dependencies = data.get("dependencies", {})
        dev_dependencies = data.get("devDependencies", {})
        all_deps = {**dependencies, **dev_dependencies}
        vulns = scan_dependencies(all_deps, filepath)
    except Exception:
        pass
    return vulns

def scan_yarn_lock(filepath):
    vulns = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        current_pkg = None
        for line in lines:
            if line and not line.startswith(" ") and line.endswith(":"):
                key = line.rstrip(":")
                pkg_name = key.split("@")[0]
                current_pkg = pkg_name
            elif current_pkg and line.strip().startswith("version"):
                version = line.strip().split(" ")[1].strip('"')
                if current_pkg in COMPROMISED_PACKAGES:
                    vuln_range = COMPROMISED_PACKAGES[current_pkg]
                    if is_version_vulnerable(version, vuln_range):
                        vulns.append((current_pkg, version, vuln_range))
                current_pkg = None
    except Exception:
        pass
    return vulns

# ------------------ Repo Scanner ------------------
def scan_repo(repo, headers, base_path):
    repo_name = repo["name"]
    print(f"\n[+] Scanning repo: {repo_name}")
    dep_files = []
    for dep_file in ["package.json", "package-lock.json", "yarn.lock"]:
        url = f"https://raw.githubusercontent.com/{repo['full_name']}/main/{dep_file}"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            save_path = Path(base_path) / f"{repo_name}-{dep_file}"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(r.text)
            dep_files.append(save_path)
            print(f"[DEBUG] Downloaded dependency file at: {save_path}")

    if not dep_files:
        print("[-] No dependency files found in this repo.")
        return []

    all_vulns = []
    for file in dep_files:
        if file.name.endswith("yarn.lock"):
            vulns = scan_yarn_lock(file)
        else:
            vulns = scan_file(file)
        for dep, version, vuln_range in vulns:
            print(f"[!] {RED}VULNERABLE{RESET}: {dep} {version} (matches {vuln_range})")
        all_vulns.extend(vulns)

    if not all_vulns:
        print("[+] No vulnerabilities found in this repo.")

    return all_vulns

# ------------------ Main ------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GitHub org or username")
    args = parser.parse_args()

    print(TOOL_NAME)
    org = args.org
    token = get_github_token()
    headers = {"Authorization": f"token {token}"} if token else {}

    # Fetch repos (try org first, then user)
    print(f"[+] Fetching repos for '{org}' as organization...")
    r = requests.get(f"https://api.github.com/orgs/{org}/repos", headers=headers)
    if r.status_code != 200:
        print(f"[-] Not an organization. Trying as user '{org}'...")
        r = requests.get(f"https://api.github.com/users/{org}/repos", headers=headers)
    if r.status_code != 200:
        print(f"[-] Failed to fetch repos. Status code: {r.status_code}")
        return

    repos = r.json()
    if not isinstance(repos, list) or len(repos) == 0:
        print("[-] No repositories found.")
        return

    print(f"[+] Found {len(repos)} repositories in '{org}'.")
    base_path = f"downloaded_files_{org}"
    Path(base_path).mkdir(parents=True, exist_ok=True)

    total_vulns = []
    for repo in repos:
        vulns = scan_repo(repo, headers, base_path)
        total_vulns.extend(vulns)

    print("\n### Scan Summary ###")
    if total_vulns:
        for dep, version, vuln_range in total_vulns:
            print(f"[!] {RED}{dep} {version} vulnerable{RESET} (range {vuln_range})")
    else:
        print("No compromised packages found in any repo.")

if __name__ == "__main__":
    main()
