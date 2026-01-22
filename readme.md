# UrlOsint - OSINT Web Investigation Tool

A Linux-based OSINT tool for quick web reconnaissance and surface attack analysis.

![Image de l'interface](/example/interface.png)

---


## 🔍 Features

- **50+ endpoint scanning**: robots.txt, .env, .git/, API docs, admin panels, backups
- **Shodan integration**: DNS resolution, open ports, CVE detection
- **Wayback Machine integration**: historical snapshots, archived URLs
- **Colorful terminal UI**: RGB gradients, clickable hyperlinks

---

## 🔌 APIs Used

| API | Purpose | API Key Required | Status |
|----|--------|------------------|--------|
| **Shodan** | Open ports, services, vulnerabilities (CVE) | 🔑 Yes | 🟢 Active |
| **Wayback Machine** | Historical website archives | ❌ No | 🟢 Active |

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/H4ck-J3x/UrlOsint.git
cd UrlOsint

# Install dependencies
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### Get Shodan API Key

1. Sign up at [shodan.io](https://www.shodan.io/)
2. Copy your API key from account page
3. Edit `api.json`:

```json
{
  "shodan": {
    "api_key": "YOUR_SHODAN_API_KEY",
    "search_limit": 100
  }
}
```

---

## 🚀 Usage

```bash
python main.py
> example.com
```

**Output example:**
```
🖧 Resolved IP: 93.184.216.34
👾 Exploits: CVE-2023-XXXX

🤖 ROBOTS: (https://example.com/robots.txt)
   1: User-agent: *
   2: Disallow: /admin/
```

---

## 🔒 Security & Ethics

### ⚠️ Responsible Use

- **Authorization required**: Only scan domains you own or have permission to test
- **Legal compliance**: Unauthorized scanning may be illegal in your jurisdiction
- **Ethical hacking**: Use responsibly for security research and bug bounty programs

**Disclaimer**: The authors are not responsible for misuse of this tool. Always obtain proper authorization before testing.
