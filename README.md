# MailTrace

A powerful Terminal User Interface (TUI) tool for analyzing raw email headers to detect phishing, spoofing, and spam. Built with Python and the Rich library for a modern, interactive console experience.

## Features

- **Comprehensive Header Parsing**: Extracts and organizes email headers into a structured format.
- **Authentication Verification**: Checks SPF, DKIM, and DMARC status to validate email authenticity.
- **Email Routing Analysis**: Traces the path of the email through servers by parsing "Received" headers, extracting IP addresses, and performing reverse DNS lookups.
- **Security Heuristics**:
  - Detects reply-to domain mismatches, a common phishing technique.
  - Calculates a spam/phishing risk score based on authentication failures, suspicious keywords, and missing headers.
- **Interactive TUI**: User-friendly interface with tables, panels, and color-coded output for easy interpretation.
- **Report Export**: Save analysis results to a text file for record-keeping.
- **Cross-Platform**: Works on Linux, macOS, and Windows (requires Python 3.6+).

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Install Dependencies
```bash
pip install rich
```

### Clone or Download
```bash
git clone https://github.com/anonymous0x9/MailTrace.git
cd MailTrace
```

## Usage

Run the tool with:
```bash
python3 MailTrace.py
```

### How to Use
1. Launch the script.
2. Paste your raw email headers when prompted.
3. Type `END` on a new line to finish input.
4. Review the analysis output, which includes:
   - Basic email info (From, To, Subject, etc.)
   - Authentication status (SPF/DKIM/DMARC)
   - Routing hops with IPs and reverse DNS
   - Public IPs detected
   - Spam/phishing score and flags
   - Full header list
5. Choose an option:
   - `a`: Analyze another email
   - `s`: Save the report to a file
   - `q`: Quit

### Example Input
Copy and paste raw headers like:
```
Received: by smtp.example.com with SMTP id abc123
From: sender@example.com
To: recipient@domain.com
Subject: Test Email
...
END
```

### Example Output
The tool displays a formatted analysis with color-coded results, tables for routing, and a risk score bar.

#### Sample TUI Output
Here's a text representation of the TUI (colors and styles are rendered in the terminal):

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           Email Header Analyzer                           ║
║                     Analyzed at 2026-04-08 12:00:00                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

──────────────────────────────── Basic Info ────────────────────────────────
Field          Value
─────────────  ─────────────────────────────────────────────────────────────
From           sender@example.com
To             recipient@domain.com
Reply-To       reply@phishingsite.com
Subject        Urgent: Verify Your Account
Date           Mon, 08 Apr 2026 10:30:00 +0000
Message-ID     <abc123@example.com>
Mailer         —


──────────────────────────────── Authentication ─────────────────────────────
┌─────────┐  ┌─────────┐  ┌─────────┐
│   SPF   │  │  DKIM   │  │  DMARC  │
│         │  │         │  │         │
│  FAIL ⚠ │  │   PASS  │  │  FAIL ⚠ │
└─────────┘  └─────────┘  └─────────┘

──────────────────────────────── Email Routing (Hops) ──────────────────────
Hop  Raw header                          IPs found             rDNS
───  ──────────────────────────────────  ────────────────────  ────────────
1    from mail.phish.com (mail.phish…    192.168.1.1           —
2    by smtp.example.com with SMTP…      203.0.113.1           smtp.example.com

──────────────────────────────── Public IPs Detected ───────────────────────
IP Address     Reverse DNS                    Private?
─────────────  ─────────────────────────────  ──────────
203.0.113.1    smtp.example.com               No

──────────────────────────────── Spam / Phishing Score ─────────────────────
╔══════════════════════════════════════════════════════════════════════════════╗
║  Score: 75/100  █████████████████░░░                                      ║
║  Verdict: HIGH RISK — likely spam or phishing                            ║
║                                                                          ║
║  • SPF failed                                                            ║
║  • DMARC failed                                                          ║
║  • Reply-To domain mismatch                                              ║
║  • Spam keyword in subject: 'urgent'                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

──────────────────────────────── All Headers ────────────────────────────────
Header               Value
───────────────────  ────────────────────────────────────────────────────────
from                 sender@example.com
to                   recipient@domain.com
subject              Urgent: Verify Your Account
...                  ...

Options:
  a — Analyze another email
  s — Save report to file
  q — Quit

Command:
```

## How It Works

- **Parsing**: Splits headers into key-value pairs, handling folded lines.
- **IP Extraction**: Uses regex to find IPv4 addresses in headers.
- **Reverse DNS**: Queries DNS for hostnames of public IPs (may be slow for multiple IPs).
- **Scoring**: Heuristic-based system assigning points for failed auth, mismatches, keywords, etc.
- **UI Rendering**: Leverages Rich for styled console output without external dependencies beyond the library.

## Limitations

- Heuristic scoring may produce false positives/negatives.
- Reverse DNS lookups can fail or timeout.
- Assumes valid header input; no extensive error handling for malformed data.
- Network-dependent for DNS queries.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with a clear description.

## License

This project is open-source. See LICENSE file for details (if applicable).

## Author

Created by anonymous0x9.