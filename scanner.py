import requests
import os
import json
import argparse
from pathlib import Path
import getpass
from semantic_version import Version, NpmSpec

# -------------------- TOOL BANNER --------------------
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

# -------------------- COLORS --------------------
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# -------------------- 40+ Vulnerable NPM Packages --------------------
COMPROMISED_PACKAGES = {
    "chalk": ">=5.0.0 <5.0.5",
    "express": ">=4.0.0 <4.18.3",
    "lodash": "<4.17.21",
    "jquery": "<3.5.1",
    "axios": "<0.21.2",
    "react": ">=18.0.0 <18.2.1",
    "debug": "<=4.3.1",
    "micromatch": ">=4.0.0 <4.0.4",
    "camelcase": ">=6.2.0 <6.2.1",
    "minimist": ">=1.2.6 <1.2.11",
    "strip-ansi": ">=6.0.0 <6.0.3",
    "ansi-styles": ">=4.3.0 <4.3.4",
    "emoji-regex": "*",
    "uid-number": "*",
    "is-fullwidth-code-point": "*",
    "text-table": "*",
    "supports-color": "*",
    "escape-string-regexp": "*",
    "string-width": "*",
    "dashdash": "*",
    "ini": "*",
    "color": "*",
    "color-name": ">=2.0.0 <2.0.2",
    "color-convert": "*",
    "color-string": "*",
    "@ctrl/tinycolor": "*",
    "rxnt-authentication": "0.0.1",
    "crowdstrike-npm": "*",
    "debug-utils": "*",
    "dane-util": "*",
    "@npmcli/arborist": "*",
    "@npmcli/package-json-lint": "*",
    "js-tokens": "*",
    "emoji-regex": "*",
    "unique-slug": "*",
    "universalify": "*",
    "uuid": "*",
    "strip-json-comments": "*",
    "prettier": "<3.5.4",
}

# -------------------- HELPER FUNCTIONS --------------------
def is_version_in_range(version, range_expr):
    """Check if a version satisfies a given npm semver range."""
    try:
        spec = NpmSpec(range_expr)
        return Version(version.lstrip('^~')) in spec
    except Exception:
        return False


def is_version_vulnerable(installed_version, vulnerable_range):
    if vulnerable_range == "*":
        return True
    return is_version_in_range(installed_version, vulnerable_range)


def scan_dependencies(dependencies):
    """Scan a dictionary of dependencies for vulnerabilities."""
    vulns = []
    for dep, version in dependencies.items():
        if dep in COMPROMISED_PACKAGES:
            vuln_range = COMPROMISED_PACKAGES[dep]
            if is_version_vulnerable(version, vuln_range):
                vulns.append((dep, version, vuln_range))
    return vulns


def parse_yarn_lock(file_path):
    """Parse yarn.lock file to extract package versions."""
    deps = {}
    with open(file_path) as f:
        lines = f.readlines()
    current_pkg = None
    for line in lines:
        if line.strip() and not line.startswith(" "):
            key = line.split("@")[0]
            current_pkg = key.strip()
        elif current_pkg and line.strip().startswith("version"):
            version = line.strip().split(" ")[1].strip('"')
            deps[current_pkg] = version
            current_pkg = None
    return deps


# -------------------- SCANNING FUNCTION --------------------
def scan_repo(repo, base_path):
    repo_name = repo["name"]
    print(f"\n[+] Scanning repo: {repo_name}")

    dep_files = []
    for dep_file in ["package.json", "package-lock.json", "yarn.lock"]:
        url = f"{repo['html_url']}/raw/main/{dep_file}"
        r = requests.get(url)
        if r.status_code == 200:
            save_path = Path(base_path) / f"{repo_name}-{dep_file}"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, "w") as f:
                f.write(r.text)
            dep_files.append(save_path)
            print(f"[DEBUG] Downloaded dependency file at: {save_path}")

    if not dep_files:
        print("[-] No dependency files found in this repo.")
        return []

    all_vulns = []
    for file in dep_files:
        with open(file) as f:
            all_deps = {}
            if file.suffix == ".json":
                data = json.load(f)
                dependencies = data.get("dependencies", {})
                dev_dependencies = data.get("devDependencies", {})
                all_deps = {**dependencies, **dev_dependencies}
            else:  # yarn.lock
                all_deps = parse_yarn_lock(file)

            vulns = scan_dependencies(all_deps)
            if vulns:
                print(f"\n[!] Vulnerabilities found in file: {file.name}")
                for dep, version, vuln_range in vulns:
                    print(f"    {RED}{dep} {version} (matches {vuln_range}){RESET}")
            all_vulns.extend(vulns)

    if not all_vulns:
        print(f"{GREEN}[+] No vulnerabilities found in this repo.{RESET}")

    return all_vulns


# -------------------- MAIN FUNCTION --------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GitHub org or username")
    args = parser.parse_args()

    print(TOOL_NAME)
    org = args.org

    # Fetch repos
    print(f"[+] Fetching repos for '{org}' as organization...")
    r = requests.get(f"https://api.github.com/orgs/{org}/repos")
    if r.status_code != 200:
        print(f"[-] Not an organization. Trying as user '{org}'...")
        r = requests.get(f"https://api.github.com/users/{org}/repos")

    repos = r.json()
    if not isinstance(repos, list):
        print("[-] Failed to fetch repos.")
        return

    print(f"[+] Found {len(repos)} repositories in '{org}'.")
    base_path = f"downloaded_files_{org}"
    Path(base_path).mkdir(parents=True, exist_ok=True)

    total_vulns = []
    for repo in repos:
        vulns = scan_repo(repo, base_path)
        total_vulns.extend(vulns)

    print("\n### Scan Summary ###")
    if total_vulns:
        for dep, version, vuln_range in total_vulns:
            print(f"{RED}[!] {dep} {version} vulnerable (range {vuln_range}){RESET}")
    else:
        print(f"{GREEN}No compromised packages found in any repo.{RESET}")


if __name__ == "__main__":
    main()
               
