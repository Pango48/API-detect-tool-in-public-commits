# API-detect-tool-in-public-commits

> A collection of YARA rules to detect leaked API keys, tokens, and credentials in public git commits.

## Overview

**API-detect-tool-in-public-commits** is an open-source set of YARA rules designed to detect exposed API keys, secrets, tokens, and credentials in public git repositories and commits.

Developers accidentally push secrets every day — in config files, CI/CD workflows, hardcoded SDK calls, or `.env` files. This project provides ready-to-use YARA rules to catch these leaks before they can be exploited.

Each rule follows a consistent structure with metadata fields for `severity`, `confidence`, `false\_positive`, and `tags`, making it easy to integrate with existing security pipelines.

\---



## Installation \& Usage

### Prerequisites

* [YARA](https://virustotal.github.io/yara/) ≥ 4.x installed on your system

```bash
# macOS
brew install yara

# Ubuntu / Debian
sudo apt-get install yara

# From source
git clone https://github.com/VirusTotal/yara.git \&\& cd yara
./bootstrap.sh \&\& ./configure \&\& make \&\& sudo make install
```

### Clone the repository

```bash
git clone https://github.com/your-org/API-detect-tool-in-public-commits.git
cd API-detect-tool-in-public-commits
```

\---

## Contributing

Contributions are welcome! Whether you want to add new rules, improve existing patterns, or fix false positives — all PRs are appreciated.

## Legal \& Ethics

This project is intended for **defensive security purposes only**: auditing your own repositories, securing CI/CD pipelines, and building secret scanning tooling.

Do **not** use these rules to scan repositories you do not own or have explicit permission to audit.

