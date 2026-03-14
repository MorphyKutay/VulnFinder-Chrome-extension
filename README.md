# VulnFinder

Chrome extension – Shows vulnerability descriptions, PoC references, and CVSS scores directly on Google search results when you search for a CVE.

[![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-Install-blue?logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/vulnfinder/ndbpegpddcoiphmjgdccmhafkafkhimn)

## Download

**[Install from Chrome Web Store](https://chromewebstore.google.com/detail/vulnfinder/ndbpegpddcoiphmjgdccmhafkafkhimn)**

## Features

- **CVE summary** – Vulnerability description at a glance
- **CVSS scores** – v2, v3, and v4 (when available)
- **PoC / reference links** – GitHub advisory, commits, and more
- **NVD & MITRE links** – Quick access to official CVE pages
- **Light & dark mode** – Theme-aware design

## How it works

Search for a CVE ID on Google (e.g. `CVE-2025-58751`). VulnFinder detects the query and adds a card at the top of the search results with the CVE details.

## Technical

- Manifest V3
- Fetches data from CVE.org (cveawg.mitre.org) and cve.circl.lu APIs
- Does not execute remote code; only processes JSON data

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).  
You may use, modify, and distribute this software under the terms of the GPL v3.  
See the [LICENSE](LICENSE) file for the full license text.
