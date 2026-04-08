#!/usr/bin/env python3
"""
Email Header Analyzer TUI
Paste raw email headers and get a full security analysis
Install: pip install rich
Run:     python3 email_header_analyzer.py
"""

import re, os, platform, socket, subprocess
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
#  PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_headers(raw: str) -> dict:
    headers = {}
    current_key = None
    for line in raw.splitlines():
        if line.startswith((" ", "\t")) and current_key:
            headers[current_key] += " " + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            current_key = key.strip().lower()
            headers[current_key] = val.strip()
    return headers

def extract_all(raw: str) -> list:
    """Extract all Received headers in order."""
    received = []
    for line in raw.splitlines():
        if line.lower().startswith("received:"):
            received.append(line[9:].strip())
    return received

def extract_ips(text: str) -> list:
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
        return (a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                a == 127)
    except:
        return False

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "—"

def check_spf(headers: dict) -> tuple[str, str]:
    val = headers.get("received-spf", "") or headers.get("authentication-results", "")
    val = val.lower()
    if "spf=pass"    in val: return "[bold green]PASS[/bold green]",  "green"
    if "spf=fail"    in val: return "[bold red]FAIL ⚠[/bold red]",   "red"
    if "spf=softfail"in val: return "[yellow]SOFTFAIL[/yellow]",      "yellow"
    if "spf=neutral" in val: return "[dim]NEUTRAL[/dim]",             "dim"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_dkim(headers: dict) -> tuple[str, str]:
    val = headers.get("authentication-results", "").lower()
    if "dkim=pass"   in val: return "[bold green]PASS[/bold green]",  "green"
    if "dkim=fail"   in val: return "[bold red]FAIL ⚠[/bold red]",   "red"
    if "dkim=none"   in val: return "[dim]NONE[/dim]",                "dim"
    if headers.get("dkim-signature"): return "[yellow]PRESENT (unverified)[/yellow]", "yellow"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_dmarc(headers: dict) -> tuple[str, str]:
    val = headers.get("authentication-results", "").lower()
    if "dmarc=pass"  in val: return "[bold green]PASS[/bold green]",  "green"
    if "dmarc=fail"  in val: return "[bold red]FAIL ⚠[/bold red]",   "red"
    if "dmarc=none"  in val: return "[dim]NONE[/dim]",                "dim"
    return "[dim]NOT FOUND[/dim]", "dim"

def check_reply_to_mismatch(headers: dict) -> tuple[bool, str, str]:
    from_val    = headers.get("from", "")
    reply_val   = headers.get("reply-to", "")
    from_email  = re.search(r'[\w.+-]+@[\w.-]+', from_val)
    reply_email = re.search(r'[\w.+-]+@[\w.-]+', reply_val)
    if from_email and reply_email:
        fd = from_email.group(0).split("@")[1].lower()
        rd = reply_email.group(0).split("@")[1].lower()
        if fd != rd:
            return True, from_email.group(0), reply_email.group(0)
    return False, "", ""

def parse_date(headers: dict) -> str:
    d = headers.get("date", "")
    return d if d else "—"

def spam_score(headers: dict) -> tuple[int, list]:
    """Simple heuristic spam scoring."""
    score  = 0
    flags  = []

    spf_val, _  = check_spf(headers)
    dkim_val, _ = check_dkim(headers)
    dmarc_val,_ = check_dmarc(headers)

    if "FAIL" in spf_val:
        score += 30; flags.append("SPF failed")
    if "FAIL" in dkim_val:
        score += 25; flags.append("DKIM failed")
    if "FAIL" in dmarc_val:
        score += 20; flags.append("DMARC failed")
    if "NOT FOUND" in spf_val:
        score += 10; flags.append("No SPF record")
    if "NOT FOUND" in dkim_val:
        score += 10; flags.append("No DKIM signature")

    mismatch, _, _ = check_reply_to_mismatch(headers)
    if mismatch:
        score += 25; flags.append("Reply-To domain mismatch")

    subj = headers.get("subject", "").lower()
    spam_words = ["urgent", "winner", "free", "click here", "verify your account",
                  "password", "suspended", "unusual activity", "congratulations",
                  "claim", "prize", "lottery", "bank", "wire transfer"]
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
    os.system("cls" if platform.system() == "Windows" else "clear")

    headers  = parse_headers(raw)
    received = extract_all(raw)

    console.print(Panel(
        Align.center(Text.assemble(
            Text("  Email Header Analyzer  \n", style="bold white on dark_blue"),
            Text(f"Analyzed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim"),
        )),
        border_style="blue", box=box.DOUBLE_EDGE,
    ))

    # ── Basic Info ─────────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Basic Info[/bold cyan]", style="dim blue"))
    info = Table(box=box.SIMPLE, show_header=False, expand=True, padding=(0,1))
    info.add_column("Field", style="dim", width=18)
    info.add_column("Value")

    info.add_row("From",       headers.get("from",       "[dim]—[/dim]"))
    info.add_row("To",         headers.get("to",         "[dim]—[/dim]"))
    info.add_row("Reply-To",   headers.get("reply-to",   "[dim]—[/dim]"))
    info.add_row("Subject",    headers.get("subject",    "[dim]—[/dim]"))
    info.add_row("Date",       parse_date(headers))
    info.add_row("Message-ID", headers.get("message-id", "[dim]—[/dim]"))
    info.add_row("Mailer",     headers.get("x-mailer",   headers.get("user-agent", "[dim]—[/dim]")))
    console.print(info)

    # ── Authentication ─────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Authentication[/bold cyan]", style="dim blue"))

    spf_label,  spf_color  = check_spf(headers)
    dkim_label, dkim_color = check_dkim(headers)
    dmarc_label,dmarc_color= check_dmarc(headers)

    def auth_panel(name, label, color):
        return Panel(Align.center(Text.from_markup(label)),
                     title=f"[dim]{name}[/dim]", border_style=color, padding=(0,2))

    console.print(Columns([
        auth_panel("SPF",  spf_label,  spf_color),
        auth_panel("DKIM", dkim_label, dkim_color),
        auth_panel("DMARC",dmarc_label,dmarc_color),
    ], equal=True, expand=True))

    # ── Reply-To Mismatch ──────────────────────────────────────────────────
    mismatch, from_e, reply_e = check_reply_to_mismatch(headers)
    if mismatch:
        console.print(Panel(
            Text.assemble(
                Text("  Reply-To domain mismatch detected!\n", style="bold red"),
                Text(f"  From:     {from_e}\n", style="white"),
                Text(f"  Reply-To: {reply_e}\n", style="yellow"),
                Text("  This is a common phishing technique.", style="dim"),
            ),
            border_style="red", box=box.HEAVY,
        ))

    # ── Routing / Received Hops ────────────────────────────────────────────
    console.print(Rule("[bold cyan]Email Routing (Hops)[/bold cyan]", style="dim blue"))

    if received:
        hop_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                          expand=True, show_edge=False, padding=(0,1))
        hop_table.add_column("Hop", style="dim", width=4, justify="right")
        hop_table.add_column("Raw header", min_width=30)
        hop_table.add_column("IPs found", width=32)
        hop_table.add_column("rDNS", min_width=20)

        for i, hop in enumerate(reversed(received), 1):
            ips = extract_ips(hop)
            pub_ips = [ip for ip in ips if not is_private_ip(ip)]
            rdns = reverse_dns(pub_ips[0]) if pub_ips else "—"
            ip_str = ", ".join(pub_ips) if pub_ips else "[dim]private/none[/dim]"
            hop_table.add_row(str(i), hop[:80] + ("…" if len(hop) > 80 else ""), ip_str, rdns)

        console.print(hop_table)
    else:
        console.print("[dim]  No Received headers found.[/dim]\n")

    # ── IP Summary ─────────────────────────────────────────────────────────
    all_ips = extract_ips(raw)
    pub_ips = list(set(ip for ip in all_ips if not is_private_ip(ip)))
    if pub_ips:
        console.print(Rule("[bold cyan]Public IPs Detected[/bold cyan]", style="dim blue"))
        ip_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                         expand=True, show_edge=False, padding=(0,1))
        ip_table.add_column("IP Address", width=18)
        ip_table.add_column("Reverse DNS", min_width=30)
        ip_table.add_column("Private?", width=10)

        for ip in pub_ips:
            rdns = reverse_dns(ip)
            ip_table.add_row(ip, rdns, "[dim]No[/dim]")
        console.print(ip_table)

    # ── Spam Score ─────────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Spam / Phishing Score[/bold cyan]", style="dim blue"))
    score, flags = spam_score(headers)

    if score >= 60:
        score_color = "bold red"
        verdict     = "HIGH RISK — likely spam or phishing"
    elif score >= 30:
        score_color = "yellow"
        verdict     = "MEDIUM RISK — suspicious"
    else:
        score_color = "bold green"
        verdict     = "LOW RISK — looks legitimate"

    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    console.print(Panel(
        Text.assemble(
            Text(f"  Score: ", style="dim"),
            Text(f"{score}/100  ", style=score_color),
            Text(f"[{bar}]\n", style=score_color),
            Text(f"  Verdict: {verdict}\n\n", style=score_color),
            *[Text(f"  • {f}\n", style="yellow") for f in flags] if flags
            else [Text("  • No issues found\n", style="green")],
        ),
        border_style="red" if score >= 60 else "yellow" if score >= 30 else "green",
        box=box.HEAVY if score >= 60 else box.SIMPLE,
    ))

    # ── All Headers ────────────────────────────────────────────────────────
    console.print(Rule("[bold cyan]All Headers[/bold cyan]", style="dim blue"))
    all_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                      expand=True, show_edge=False, padding=(0,1))
    all_table.add_column("Header", style="dim cyan", width=28)
    all_table.add_column("Value")

    for k, v in headers.items():
        all_table.add_row(k, v[:120] + ("…" if len(v) > 120 else ""))
    console.print(all_table)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def get_multiline_input() -> str:
    console.print(Panel(
        Text.assemble(
            Text("Paste your raw email headers below.\n", style="bold cyan"),
            Text("When done, type ", style="dim"),
            Text("END", style="bold yellow"),
            Text(" on a new line and press Enter.", style="dim"),
        ),
        border_style="blue", box=box.SIMPLE,
    ))
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except (KeyboardInterrupt, EOFError):
            break
    return "\n".join(lines)

def main():
    console.clear()
    console.print(Panel(
        Align.center(Text.assemble(
            Text("Email Header Analyzer\n", style="bold cyan"),
            Text("Detect phishing, spoofing, SPF/DKIM/DMARC  |  Python + Rich", style="dim"),
        )),
        border_style="blue", box=box.DOUBLE_EDGE,
    ))

    while True:
        raw = get_multiline_input()
        if not raw.strip():
            console.print("[red]No input. Try again.[/red]")
            continue

        render_analysis(raw)

        console.print("\n[bold yellow]Options:[/bold yellow]")
        console.print("  [cyan]a[/cyan] — Analyze another email")
        console.print("  [cyan]s[/cyan] — Save report to file")
        console.print("  [cyan]q[/cyan] — Quit")
        console.print("\nCommand: ", end="")

        try:
            cmd = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if cmd == "q":
            break
        elif cmd == "s":
            fname = f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w") as f:
                headers = parse_headers(raw)
                score, flags = spam_score(headers)
                spf,_  = check_spf(headers)
                dkim,_ = check_dkim(headers)
                dmarc,_= check_dmarc(headers)
                f.write(f"Email Header Analysis Report\n")
                f.write(f"Generated: {datetime.now()}\n\n")
                f.write(f"From:     {headers.get('from','—')}\n")
                f.write(f"To:       {headers.get('to','—')}\n")
                f.write(f"Subject:  {headers.get('subject','—')}\n")
                f.write(f"Date:     {headers.get('date','—')}\n\n")
                f.write(f"SPF:      {spf}\nDKIM:     {dkim}\nDMARC:    {dmarc}\n\n")
                f.write(f"Spam Score: {score}/100\n")
                for fl in flags:
                    f.write(f"  - {fl}\n")
                f.write(f"\nRaw Headers:\n{raw}\n")
            console.print(f"[green]Saved to [bold]{fname}[/bold][/green]")
        elif cmd == "a":
            continue

    console.print(Panel("[bold green]Goodbye![/bold green]", box=box.DOUBLE))

if __name__ == "__main__":
    main()
