# npm2guard

![By Muthu D](https://img.shields.io/badge/author-Muthu%20D-blue)

npm2guard is a tool to scan GitHub organizations' repositories for vulnerable NPM packages affected by recent supply chain attacks. It detects compromised dependencies in `package.json`, `package-lock.json`, and `yarn.lock` files recursively.

---

## Features

- Scans all repositories within a GitHub organization.
- Detects compromised npm package versions automatically.
- Interactive GitHub token prompt with local token storage.
- Supports scanning multiple organizations from file input.

---

## Installation

Requires Python 3.6 or higher.

git clone https://github.com/muthu-d-anonysm/npm2guard.git

cd npm2guard

pip install -r requirements.txt

---

## Usage

1. Scan a single organization:
  
      python scanner.py --org target

You will be prompted to enter your GitHub personal access token (recommended to use fine-grained tokens starting with `github_pat_`).


2. Scan multiple organizations:
   
      python scanner.py --org-file targets.txt



`targets.txt` contains one organization name per line.

---

## License

MIT License — see [LICENSE](https://github.com/muthu-d-anonysm/npm2guard/LICENSE) file.

---

## Author

Muthu D.  
[LinkedIn](https://www.linkedin.com/in/anonysm)
