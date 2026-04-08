#!/usr/bin/env python3
"""
MailTrace - Email Header Analyzer TUI
Handles both multiline AND single-line pasted headers
Install: pip install rich
Run:     python3 mailtrace.py
"""

import re, os, platform, socket, sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.columns import Columns
from rich import box

console = Console()

# ══════════════════════════════════════════════════════════════════════════════
#  NORMALIZER — fixes single-line pasted headers
# ══════════════════════════════════════════════════════════════════════════════

# All known email header field names
KNOWN_HEADERS = [
    "Delivered-To", "Received", "X-Received", "Return-Path", "Received-SPF",
    "Authentication-Results", "DKIM-Signature", "DomainKey-Signature",
    "X-Google-DKIM-Signature", "X-Forwarded-To", "X-Original-To",
    "Message-ID", "X-Mailer", "X-Priority", "X-YMail-OSG",
    "X-Yahoo-Newman-Id", "X-Yahoo-Newman-Property", "X-Yahoo-SMTP",
    "From", "To", "Cc", "Bcc", "Subject", "Date", "MIME-Version",
    "Content-Type", "Content-Transfer-Encoding", "Content-Disposition",
    "Reply-To", "In-Reply-To", "References", "Importance",
    "X-Spam-Status", "X-Spam-Score", "X-Spam-Flag", "X-Spam-Report",
    "Thread-Topic", "Thread-Index", "List-Unsubscribe", "Feedback-ID",
    "X-MS-Exchange", "X-Google-Smtp-Source", "X-Originating-IP",
]

def normalize_headers(raw: str) -> str:
    """
    If headers are all on one line (common when pasting from Gmail 'Show Original'),
    split them at known header names so the parser works correctly.
    """
    # If it already has newlines with colon patterns — it's fine
    lines = raw.strip().splitlines()
    has_proper_lines = sum(1 for l in lines if re.match(r'^[\w\-]+\s*:', l))
    if has_proper_lines > 3:
        return raw  # already properly formatted

    # Build a regex that matches any known header at the start of a "segment"
    pattern = "(" + "|".join(re.escape(h) for h in KNOWN_HEADERS) + r")(\s*:)"
    # Insert newline before each header keyword
    normalized = re.sub(pattern, r"\n\1\2", raw)
    return normalized.strip()


# ══════════════════════════════════════════════════════════════════════════════
#  PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_headers(raw: str) -> dict:
    raw = normalize_headers(raw)
    headers = {}
    current_key = None
    for line in raw.splitlines():
        if not line.strip():
            break  # Stop at first blank line (end of headers)
        if line.startswith((" ", "\t")) and current_key:
            headers[current_key] += " " + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            current_key = key.strip().lower()
            if current_key in headers:
                # Append duplicate headers (e.g. multiple Received)
                headers[current_key] += "\n" + val.strip()
            else:
                headers[current_key] = val.strip()
    return headers

def extract_received(raw: str) -> list:
    raw = normalize_headers(raw)
    received = []
    current = None
    for line in raw.splitlines():
        if re.match(r'^received\s*:', line, re.IGNORECASE):
            if current:
                received.append(current)
            current = line.split(":", 1)[1].strip()
        elif line.startswith((" ", "\t")) and current is not None:
            current += " " + line.strip()
        else:
            if current:
                received.append(current)
                current = None
    if current:
        received.append(current)
    return received

def extract_ips(text: str) -> list:
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return valid_ips

def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except:
        return False

def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(2)  # Set timeout to 2 seconds
        return socket.gethostbyaddr(ip)[0]
    except:
        return "—"

# ══════════════════════════════════════════════════════════════════════════════
#  CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def check_spf(headers: dict) -> tuple:
    val = (headers.get("received-spf", "") + " " + headers.get("authentication-results", "")).lower()
    if "spf=pass"     in val: return "[bold green]PASS[/bold green]",     "green"
    if "spf=fail"     in val: return "[bold red]FAIL ⚠[/bold red]",      "red"
    if "spf=softfail" in val: return "[yellow]SOFTFAIL[/yellow]",         "yellow"
    if "spf=neutral"  in val: return "[dim]NEUTRAL[/dim]",                "dim"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_dkim(headers: dict) -> tuple:
    val = headers.get("authentication-results", "").lower()
    if "dkim=pass"    in val: return "[bold green]PASS[/bold green]",     "green"
    if "dkim=fail"    in val: return "[bold red]FAIL ⚠[/bold red]",      "red"
    if "dkim=none"    in val: return "[dim]NONE[/dim]",                   "dim"
    if headers.get("dkim-signature"): return "[yellow]PRESENT (unverified)[/yellow]", "yellow"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_dmarc(headers: dict) -> tuple:
    val = headers.get("authentication-results", "").lower()
    if "dmarc=pass"   in val: return "[bold green]PASS[/bold green]",     "green"
    if "dmarc=fail"   in val: return "[bold red]FAIL ⚠[/bold red]",      "red"
    if "dmarc=none"   in val: return "[dim]NONE[/dim]",                   "dim"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_reply_mismatch(headers: dict) -> tuple:
    from_val  = headers.get("from", "")
    reply_val = headers.get("reply-to", "")
    fe = re.search(r'[\w.+-]+@[\w.-]+', from_val)
    re_ = re.search(r'[\w.+-]+@[\w.-]+', reply_val)
    if fe and re_:
        fd = fe.group(0).split("@")[1].lower()
        rd = re_.group(0).split("@")[1].lower()
        if fd != rd:
            return True, fe.group(0), re_.group(0)
    return False, "", ""

def spam_score(headers: dict) -> tuple:
    score, flags = 0, []
    spf,_  = check_spf(headers)
    dkim,_ = check_dkim(headers)
    dmarc,_= check_dmarc(headers)

    if "FAIL" in spf:   score += 30; flags.append("SPF failed")
    if "FAIL" in dkim:  score += 25; flags.append("DKIM failed")
    if "FAIL" in dmarc: score += 20; flags.append("DMARC failed")
    if "NOT FOUND" in spf:   score += 10; flags.append("No SPF record")
    if "NOT FOUND" in dkim:  score += 10; flags.append("No DKIM signature")

    mismatch, _, _ = check_reply_mismatch(headers)
    if mismatch: score += 25; flags.append("Reply-To domain mismatch")

    subj = headers.get("subject", "").lower()
    spam_words = ["urgent","winner","free","click here","verify your account",
                  "password","suspended","unusual activity","congratulations",
                  "claim","prize","lottery","bank","wire transfer"]
    for w in spam_words:
        if w in subj:
            score += 5; flags.append(f"Spam keyword in subject: '{w}'")
            break

    if not headers.get("message-id"):
        score += 10; flags.append("Missing Message-ID")

    return min(score, 100), flags

# ══════════════════════════════════════════════════════════════════════════════
#  RENDER
# ══════════════════════════════════════════════════════════════════════════════

def render_analysis(raw: str):
    # console.clear()  # Removed to avoid double clearing

    headers  = parse_headers(raw)
    received = extract_received(raw)

    # Header banner
    console.print(Panel(
        Align.center(Text.assemble(
            Text("  MailTrace — Email Header Analyzer  \n", style="bold white on dark_blue"),
            Text(f"Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Headers found: {len(headers)}", style="dim"),
        )),
        border_style="blue", box=box.DOUBLE_EDGE,
    ))

    # ── Basic Info ─────────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Basic Info[/bold cyan]", style="dim blue"))
    info = Table(box=box.SIMPLE, show_header=False, expand=True, padding=(0,1))
    info.add_column("Field", style="dim cyan", width=20)
    info.add_column("Value")
    info.add_row("From",       headers.get("from",        "[dim]—[/dim]"))
    info.add_row("To",         headers.get("to",          "[dim]—[/dim]"))
    info.add_row("Reply-To",   headers.get("reply-to",    "[dim]—[/dim]"))
    info.add_row("Subject",    headers.get("subject",     "[dim]—[/dim]"))
    info.add_row("Date",       headers.get("date",        "[dim]—[/dim]"))
    info.add_row("Message-ID", headers.get("message-id",  "[dim]—[/dim]"))
    info.add_row("X-Mailer",   headers.get("x-mailer",    headers.get("user-agent", "[dim]—[/dim]")))
    info.add_row("Return-Path",headers.get("return-path", "[dim]—[/dim]"))
    console.print(info)

    # ── Authentication ─────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Authentication (SPF / DKIM / DMARC)[/bold cyan]", style="dim blue"))
    spf_l,  spf_c  = check_spf(headers)
    dkim_l, dkim_c = check_dkim(headers)
    dmar_l, dmar_c = check_dmarc(headers)

    def ap(name, label, color):
        return Panel(Align.center(Text.from_markup(label)),
                     title=f"[dim]{name}[/dim]", border_style=color, padding=(0,3))

    console.print(Columns([ap("SPF", spf_l, spf_c), ap("DKIM", dkim_l, dkim_c), ap("DMARC", dmar_l, dmar_c)],
                          equal=True, expand=True))

    # Full auth-results raw
    auth_raw = headers.get("authentication-results", "")
    if auth_raw:
        console.print(Panel(Text(auth_raw, style="dim"), title="[dim]Raw Authentication-Results[/dim]",
                            border_style="dim", box=box.SIMPLE))

    # ── Reply-To Mismatch ──────────────────────────────────────────────────
    mismatch, from_e, reply_e = check_reply_mismatch(headers)
    if mismatch:
        console.print(Panel(
            Text.assemble(
                Text("  Reply-To domain mismatch detected!\n", style="bold red"),
                Text(f"  From:     {from_e}\n", style="white"),
                Text(f"  Reply-To: {reply_e}\n", style="yellow"),
                Text("  Replies will go to a different domain — common phishing trick.", style="dim"),
            ),
            border_style="red", box=box.HEAVY,
        ))

    # ── Routing Hops ──────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Email Routing Hops[/bold cyan]", style="dim blue"))
    if received:
        hop_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                          expand=True, show_edge=False, padding=(0,1))
        hop_table.add_column("Hop", style="dim", width=4, justify="right")
        hop_table.add_column("Server / Info", min_width=35)
        hop_table.add_column("Public IPs", width=18)
        hop_table.add_column("Reverse DNS", min_width=22)

        for i, hop in enumerate(reversed(received), 1):
            ips     = extract_ips(hop)
            pub_ips = [ip for ip in ips if not is_private_ip(ip)]
            rdns    = reverse_dns(pub_ips[0]) if pub_ips else "—"
            ip_str  = ", ".join(pub_ips) if pub_ips else "[dim]private/local[/dim]"
            hop_table.add_row(str(i), hop[:60] + ("…" if len(hop) > 60 else ""), ip_str, rdns)

        console.print(hop_table)
    else:
        console.print("[dim]  No Received headers found.[/dim]\n")

    # ── Public IPs ────────────────────────────────────────────────────────
    all_ips = list(set(extract_ips(raw)))
    pub_ips = [ip for ip in all_ips if not is_private_ip(ip)]
    if pub_ips:
        console.print(Rule("[bold cyan]Public IPs Found[/bold cyan]", style="dim blue"))
        ip_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                         expand=True, show_edge=False, padding=(0,1))
        ip_table.add_column("IP Address", width=18)
        ip_table.add_column("Reverse DNS")
        for ip in pub_ips:
            ip_table.add_row(ip, reverse_dns(ip))
        console.print(ip_table)

    # ── Spam Score ────────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Spam / Phishing Risk Score[/bold cyan]", style="dim blue"))
    score, flags = spam_score(headers)

    if score >= 60:
        sc, verdict = "bold red",   "HIGH RISK — likely spam or phishing ⚠"
    elif score >= 30:
        sc, verdict = "yellow",     "MEDIUM RISK — suspicious"
    else:
        sc, verdict = "bold green", "LOW RISK — looks legitimate"

    bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    console.print(Panel(
        Text.assemble(
            Text(f"  Score: ", style="dim"),
            Text(f"{score}/100  [{bar}]\n", style=sc),
            Text(f"  Verdict: {verdict}\n\n", style=sc),
            *([Text(f"  • {f}\n", style="yellow") for f in flags]
              if flags else [Text("  • No issues detected\n", style="green")]),
        ),
        border_style="red" if score >= 60 else "yellow" if score >= 30 else "green",
    ))

    # ── All Headers ───────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]All Parsed Headers[/bold cyan]", style="dim blue"))
    all_tbl = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                    expand=True, show_edge=False, padding=(0,1))
    all_tbl.add_column("Header", style="dim cyan", width=28)
    all_tbl.add_column("Value")
    for k, v in headers.items():
        val = v.replace("\n", " ")
        all_tbl.add_row(k, val[:110] + ("…" if len(val) > 110 else ""))
    console.print(all_tbl)

    console.print("\n[dim]Analysis complete.[/dim]")

    sys.stdout.flush()
#  INPUT — handles multiline AND single-line paste
# ══════════════════════════════════════════════════════════════════════════════

def get_input() -> str:
    console.print(Panel(
        Text.assemble(
            Text("Paste raw email headers below.\n", style="bold cyan"),
            Text("Supports both multiline and single-line paste.\n", style="dim"),
            Text("Type ", style="dim"), Text("END", style="bold yellow"),
            Text(" on a new line and press Enter when done.", style="dim"),
        ),
        border_style="blue", box=box.SIMPLE,
    ))
    lines = []
    try:
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
    except (KeyboardInterrupt, EOFError):
        pass
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # console.clear()  # Removed to avoid terminal issues
    console.print(Panel(
        Align.center(Text.assemble(
            Text("MailTrace\n", style="bold cyan"),
            Text("Email Header Analyzer  |  Python + Rich  |  Detect phishing & spoofing", style="dim"),
        )),
        border_style="blue", box=box.DOUBLE_EDGE,
    ))

    while True:
        raw = get_input()
        if not raw.strip():
            console.print("[red]No input detected. Please paste headers and type END.[/red]\n")
            continue

        render_analysis(raw)

        console.print("\n[bold yellow]Options:[/bold yellow]  "
                      "[cyan]a[/cyan] Analyze another  "
                      "[cyan]s[/cyan] Save report  "
                      "[cyan]q[/cyan] Quit")
        console.print("Command: ", end="")

        try:
            cmd = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if cmd == "q":
            break
        elif cmd == "s":
            fname = f"mailtrace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            headers = parse_headers(raw)
            score, flags = spam_score(headers)
            spf,_  = check_spf(headers)
            dkim,_ = check_dkim(headers)
            dmarc,_= check_dmarc(headers)
            with open(fname, "w") as f:
                f.write(f"MailTrace Report — {datetime.now()}\n")
                f.write("="*60 + "\n")
                f.write(f"From:      {headers.get('from','—')}\n")
                f.write(f"To:        {headers.get('to','—')}\n")
                f.write(f"Subject:   {headers.get('subject','—')}\n")
                f.write(f"Date:      {headers.get('date','—')}\n\n")
                f.write(f"SPF:       {spf}\nDKIM:      {dkim}\nDMARC:     {dmarc}\n\n")
                f.write(f"Risk Score: {score}/100\n")
                for fl in flags:
                    f.write(f"  - {fl}\n")
                f.write(f"\n--- Raw Headers ---\n{raw}\n")
            console.print(f"[green]Report saved to [bold]{fname}[/bold][/green]")
        # 'a' or anything else loops back

    console.print(Panel("[bold green]MailTrace closed. Goodbye![/bold green]", box=box.DOUBLE))

if __name__ == "__main__":
    main()