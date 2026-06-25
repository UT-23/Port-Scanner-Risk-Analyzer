"""
Port Scanner & Risk Analyzer — FastAPI Backend v2.0
Scans TCP ports and provides detailed security risk analysis.

IMPORTANT: Only scan systems you own or have explicit written authorization to test.
Unauthorized port scanning may be illegal in your jurisdiction.
"""

import socket
import time
import logging
import re
import urllib.request
import json as _json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Port Scanner & Risk Analyzer API",
    description=(
        "TCP port scanner with detailed security risk assessment. "
        "Only scan systems you own or have explicit authorization to test."
    ),
    version="2.0.0",
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Port definitions — all ports required by the specification
# ---------------------------------------------------------------------------
PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ---------------------------------------------------------------------------
# Security intelligence database
# ---------------------------------------------------------------------------
SECURITY_INTEL: dict[int, dict] = {
    20: {
        "description": (
            "FTP Data Transfer port. Part of the File Transfer Protocol, used for the "
            "actual transfer of file data between client and server."
        ),
        "vulnerabilities": [
            "Cleartext data transmission — all transferred file content is readable",
            "Packet sniffing enables data exfiltration",
            "Session hijacking via TCP sequence prediction",
        ],
        "attack_vectors": [
            "MITM attack to intercept file transfers",
            "Packet capture tools (Wireshark) to read all transferred data",
        ],
        "mitigations": [
            "Migrate to SFTP (SSH File Transfer Protocol, port 22) or FTPS",
            "Restrict access via firewall to known IPs only",
            "If FTP is required, enforce FTPS with TLS 1.2+",
        ],
        "open_risk": "high",
    },
    21: {
        "description": (
            "FTP Control port. The File Transfer Protocol transmits both credentials "
            "and commands in plaintext, making it one of the most dangerous protocols "
            "to expose publicly."
        ),
        "vulnerabilities": [
            "Credentials (username + password) transmitted in plaintext",
            "Anonymous login may be enabled",
            "FTP bounce attack can be used for port scanning behind firewalls",
            "Susceptible to brute-force credential attacks",
        ],
        "attack_vectors": [
            "Network sniffing to capture plaintext credentials",
            "Brute force authentication attacks",
            "Anonymous file access if misconfigured",
            "FTP bounce to bypass firewall restrictions",
        ],
        "mitigations": [
            "Replace with SFTP (port 22) or FTPS immediately",
            "Disable anonymous login",
            "Restrict via firewall to known source IPs",
            "Enforce strong passwords and account lockout",
        ],
        "open_risk": "critical",
    },
    22: {
        "description": (
            "SSH — Secure Shell. Provides encrypted remote login, command execution, "
            "and tunneling. The standard for secure remote administration."
        ),
        "vulnerabilities": [
            "Password authentication enables brute-force attacks",
            "Outdated OpenSSH versions have known exploitable CVEs",
            "Weak or reused SSH private keys",
            "Misconfigured authorized_keys files",
        ],
        "attack_vectors": [
            "Credential brute force / dictionary attacks",
            "Exploitation of outdated OpenSSH vulnerabilities",
            "Stolen or leaked private key usage",
            "SSH tunneling abuse if access is gained",
        ],
        "mitigations": [
            "Disable password authentication; use key-based auth only",
            "Keep OpenSSH updated to latest stable version",
            "Use fail2ban or similar to block brute-force attempts",
            "Restrict SSH access via firewall to known IPs",
            "Consider non-standard port (security through obscurity, not a substitute for real security)",
            "Enable 2FA with SSH (e.g., Google Authenticator PAM module)",
        ],
        "open_risk": "medium",
    },
    23: {
        "description": (
            "Telnet — An entirely unencrypted remote login protocol from the 1970s. "
            "All data including passwords, commands, and responses travel in cleartext. "
            "Telnet is effectively obsolete and should never be used."
        ),
        "vulnerabilities": [
            "ALL data transmitted in cleartext — zero encryption",
            "Credentials (username + password) fully visible to anyone on the network",
            "No authentication integrity — trivial session hijacking",
            "No mutual authentication — trivial to conduct MITM attacks",
        ],
        "attack_vectors": [
            "Passive packet capture reveals full session including credentials",
            "Active MITM attack to inject commands",
            "Session hijacking via TCP sequence number prediction",
        ],
        "mitigations": [
            "Disable Telnet immediately — there is no safe use case",
            "Replace with SSH (port 22) for all remote access needs",
            "Block port 23 at all firewall levels",
            "Audit for any devices (routers, switches) still using Telnet and update firmware",
        ],
        "open_risk": "critical",
    },
    25: {
        "description": (
            "SMTP — Simple Mail Transfer Protocol. Used for server-to-server email relay. "
            "Direct exposure to the internet is normal for mail servers but introduces several risks."
        ),
        "vulnerabilities": [
            "Open relay configuration allows spammers to use your server",
            "SMTP VRFY/EXPN commands enable username enumeration",
            "Email spoofing without SPF/DKIM/DMARC",
            "Plaintext delivery without STARTTLS",
        ],
        "attack_vectors": [
            "Open relay exploitation for spam campaigns and phishing",
            "Username/address enumeration via VRFY command",
            "Email spoofing to impersonate your domain",
        ],
        "mitigations": [
            "Disable open relay — only relay for authenticated users",
            "Implement SPF, DKIM, and DMARC DNS records",
            "Require STARTTLS for all connections",
            "Disable VRFY and EXPN commands",
            "Use port 587 (submission) for client-to-server email with authentication",
        ],
        "open_risk": "medium",
    },
    53: {
        "description": (
            "DNS — Domain Name System. Resolves domain names to IP addresses. "
            "DNS is fundamental to internet operation but misconfigurations create significant risks."
        ),
        "vulnerabilities": [
            "DNS amplification enables massive DDoS attacks (UDP)",
            "Zone transfer (AXFR) may expose internal network map if unrestricted",
            "DNS cache poisoning (Kaminsky attack variants)",
            "DNS tunneling for covert data exfiltration or C2 communication",
        ],
        "attack_vectors": [
            "Amplification DDoS using open recursive resolver",
            "AXFR zone transfer to enumerate all internal hostnames/IPs",
            "DNS tunneling to bypass firewall restrictions",
            "Cache poisoning to redirect traffic to attacker-controlled servers",
        ],
        "mitigations": [
            "Restrict recursive queries to internal/authorized clients only",
            "Disable or restrict zone transfers (AXFR) to authorized secondary servers",
            "Enable DNSSEC to protect against cache poisoning",
            "Monitor for unusual DNS query patterns (tunneling)",
            "Use split-horizon DNS to separate internal and external zones",
        ],
        "open_risk": "medium",
    },
    80: {
        "description": (
            "HTTP — Unencrypted web traffic. All data exchanged between client and server "
            "travels in plaintext, including form submissions, session cookies, and API responses."
        ),
        "vulnerabilities": [
            "All traffic readable by anyone on the network path (MITM)",
            "Session cookies transmitted in plaintext are trivially stolen",
            "HTTP Strict Transport Security (HSTS) bypass is possible",
            "SSL stripping attacks can downgrade HTTPS connections to HTTP",
        ],
        "attack_vectors": [
            "Packet sniffing to steal session tokens and credentials",
            "MITM attack to inject malicious JavaScript or content",
            "SSL stripping to prevent HTTPS upgrade",
        ],
        "mitigations": [
            "Redirect all HTTP to HTTPS with 301 permanent redirect",
            "Implement HTTP Strict Transport Security (HSTS) with preloading",
            "Serve all sensitive content over HTTPS (port 443) only",
            "Set Secure flag on all cookies",
        ],
        "open_risk": "medium",
    },
    110: {
        "description": (
            "POP3 — Post Office Protocol v3. Used for email retrieval from mail servers. "
            "The plaintext version transmits credentials and email content unencrypted."
        ),
        "vulnerabilities": [
            "Credentials transmitted in plaintext",
            "Email content readable by network observers",
            "Susceptible to credential brute-force attacks",
        ],
        "attack_vectors": [
            "Network capture to steal email credentials",
            "Email content theft via packet analysis",
            "Credential brute force attacks",
        ],
        "mitigations": [
            "Disable plaintext POP3 and use POP3S (port 995) with TLS only",
            "Alternatively, migrate to IMAPS (port 993) for better functionality",
            "Implement account lockout after failed login attempts",
        ],
        "open_risk": "high",
    },
    111: {
        "description": (
            "RPCBind/Portmapper — Maps RPC (Remote Procedure Call) service names to their "
            "current port numbers. Acts as a directory service for all RPC-based services "
            "running on the host (NFS, NIS, etc.)."
        ),
        "vulnerabilities": [
            "Discloses which RPC services are running and on which ports",
            "Gateway to NFS exploitation if file shares are exported insecurely",
            "Historical buffer overflow and DoS vulnerabilities",
            "Can reveal internal network topology",
        ],
        "attack_vectors": [
            "Service enumeration to find exploitable RPC services",
            "Pivot to NFS shares with weak access controls",
            "Historical exploit code available for specific RPC daemon versions",
        ],
        "mitigations": [
            "Block port 111 at the perimeter firewall — never expose to internet",
            "Restrict to trusted internal networks only",
            "Disable RPCBind if NFS and NIS are not required",
            "Apply all OS vendor patches",
        ],
        "open_risk": "high",
    },
    135: {
        "description": (
            "MS-RPC Endpoint Mapper — Microsoft's RPC endpoint mapper used by Windows "
            "for DCOM (Distributed Component Object Model) and WMI (Windows Management Instrumentation). "
            "A critical Windows service that has been a historical worm vector."
        ),
        "vulnerabilities": [
            "DCOM vulnerabilities historically used by worms (Blaster, Sasser)",
            "WMI abuse for lateral movement in Windows environments",
            "Remote code execution via DCOM if unpatched",
            "Information disclosure of available RPC services",
        ],
        "attack_vectors": [
            "Remote code execution via DCOM protocol (MS03-026)",
            "Lateral movement using WMI for command execution",
            "Malware propagation (historically wormable)",
        ],
        "mitigations": [
            "Block at perimeter firewall — never expose to internet",
            "Restrict to domain-internal traffic via Windows Firewall",
            "Apply all Windows security patches immediately",
            "Monitor WMI activity for lateral movement indicators",
        ],
        "open_risk": "critical",
    },
    139: {
        "description": (
            "NetBIOS Session Service — Legacy Windows networking protocol for file and "
            "printer sharing over NetBIOS. Predates SMB's direct TCP mode and carries "
            "significant security risk."
        ),
        "vulnerabilities": [
            "NetBIOS enumeration reveals usernames, shares, and group memberships",
            "Null session attacks allow unauthenticated information gathering",
            "NTLM hash capture for offline cracking (Pass-the-Hash)",
            "NTLM relay attacks enable privilege escalation",
        ],
        "attack_vectors": [
            "Enumeration via nbtscan or nmap to map internal resources",
            "Pass-the-Hash attack using captured NTLM hashes",
            "NTLM relay to escalate privileges or gain remote code execution",
        ],
        "mitigations": [
            "Block at perimeter firewall — never expose to internet",
            "Disable NetBIOS over TCP/IP if not required (modern environments)",
            "Enable SMB signing to prevent NTLM relay",
            "Use Kerberos authentication where possible",
        ],
        "open_risk": "critical",
    },
    143: {
        "description": (
            "IMAP — Internet Message Access Protocol. Allows email clients to access "
            "email on a mail server. The plaintext version sends credentials and email "
            "content unencrypted."
        ),
        "vulnerabilities": [
            "Credentials transmitted in plaintext without STARTTLS",
            "Email content readable by network observers",
            "Susceptible to brute-force credential attacks",
        ],
        "attack_vectors": [
            "Network capture to steal IMAP credentials",
            "Email content interception",
            "Credential brute force attacks",
        ],
        "mitigations": [
            "Enforce STARTTLS to upgrade connections to TLS",
            "Better: use IMAPS (port 993) with TLS required from the start",
            "Disable plaintext authentication without TLS",
            "Implement fail2ban or rate limiting for authentication",
        ],
        "open_risk": "high",
    },
    443: {
        "description": (
            "HTTPS — TLS-encrypted web traffic. The standard for secure web communication. "
            "While encryption is present, the strength of the TLS configuration matters greatly."
        ),
        "vulnerabilities": [
            "Outdated TLS versions (TLS 1.0/1.1 are deprecated) with known weaknesses",
            "Weak cipher suites (RC4, DES, EXPORT ciphers) can be exploited",
            "Heartbleed (CVE-2014-0160) on old OpenSSL versions",
            "Certificate misconfiguration or use of weak signing algorithms",
        ],
        "attack_vectors": [
            "Protocol downgrade attacks (POODLE, BEAST) against weak TLS versions",
            "Cipher suite exploitation against weak configurations",
            "Certificate spoofing if CA compromise occurs",
        ],
        "mitigations": [
            "Enforce TLS 1.2 minimum; prefer TLS 1.3",
            "Disable RC4, DES, 3DES, and EXPORT cipher suites",
            "Implement HSTS with preloading",
            "Test configuration with Qualys SSL Labs (ssllabs.com/ssltest)",
            "Keep OpenSSL/TLS library updated",
            "Use OCSP stapling for certificate validation",
        ],
        "open_risk": "low",
    },
    445: {
        "description": (
            "SMB — Server Message Block. Windows file sharing protocol operating directly "
            "over TCP without NetBIOS. This port was responsible for the WannaCry and "
            "NotPetya ransomware outbreaks and should NEVER be internet-facing."
        ),
        "vulnerabilities": [
            "EternalBlue (MS17-010/CVE-2017-0144) — wormable remote code execution used by WannaCry",
            "SMBGhost (CVE-2020-0796) — RCE in SMBv3 compression",
            "NTLM relay attacks for privilege escalation",
            "Ransomware primary propagation mechanism",
            "SMBv1 has no security features — completely unsafe",
        ],
        "attack_vectors": [
            "EternalBlue exploit for remote code execution (WannaCry/NotPetya)",
            "NTLM relay attack using Responder to gain code execution",
            "Ransomware lateral movement via SMB file share access",
            "Credential brute force against SMB authentication",
        ],
        "mitigations": [
            "NEVER expose SMB port 445 to the internet — block at all perimeter firewalls",
            "Disable SMBv1 immediately on all Windows systems",
            "Apply MS17-010 patch if not already done",
            "Enable SMB signing on all systems",
            "Use SMBv3 with encryption in domain environments",
            "Consider disabling SMB entirely on systems that don't need it",
        ],
        "open_risk": "critical",
    },
    587: {
        "description": (
            "SMTP Submission — The modern, authenticated email submission port. "
            "Email clients use this port (with TLS) to submit outgoing messages to their mail server. "
            "Safer than port 25 when properly configured."
        ),
        "vulnerabilities": [
            "Brute-force attacks against weak email account passwords",
            "Credential stuffing using leaked password databases",
            "Compromised accounts used to send spam or phishing emails",
        ],
        "attack_vectors": [
            "Credential brute force to gain email account access",
            "Account takeover for spam campaigns or Business Email Compromise (BEC)",
            "Phishing email campaigns via compromised accounts",
        ],
        "mitigations": [
            "Enforce strong password policy and MFA for all email accounts",
            "Implement rate limiting and account lockout on authentication failures",
            "Monitor sending volume for anomaly detection",
            "Use application-specific passwords for SMTP clients",
        ],
        "open_risk": "medium",
    },
    993: {
        "description": (
            "IMAPS — IMAP over SSL/TLS. The encrypted, secure version of IMAP. "
            "Connections are encrypted from the start (unlike IMAP with STARTTLS)."
        ),
        "vulnerabilities": [
            "Brute-force attacks on email credentials",
            "Outdated TLS library vulnerabilities",
            "Certificate misconfiguration",
        ],
        "attack_vectors": [
            "Credential brute force attacks against email accounts",
            "Exploitation of TLS library vulnerabilities if unpatched",
        ],
        "mitigations": [
            "Enforce TLS 1.2+ with strong cipher suites",
            "Implement fail2ban / rate limiting for authentication",
            "Enable MFA for email accounts",
            "Keep mail server software updated",
        ],
        "open_risk": "low",
    },
    995: {
        "description": (
            "POP3S — POP3 over SSL/TLS. The encrypted version of POP3 for secure "
            "email retrieval. Connections are encrypted from the start."
        ),
        "vulnerabilities": [
            "Brute-force credential attacks",
            "TLS configuration weaknesses if poorly configured",
        ],
        "attack_vectors": [
            "Credential brute force against email accounts",
        ],
        "mitigations": [
            "Enforce TLS 1.2+ with strong cipher suites",
            "Implement account lockout after failed logins",
            "Consider migrating to IMAPS (995 → 993) for better feature support",
        ],
        "open_risk": "low",
    },
    1433: {
        "description": (
            "Microsoft SQL Server — The primary port for MSSQL database connections. "
            "Database servers should never be directly internet-facing. "
            "Exposure significantly increases ransomware and data breach risk."
        ),
        "vulnerabilities": [
            "Brute force against SA (system administrator) account",
            "xp_cmdshell stored procedure enables OS command execution",
            "SQL injection exposure if used via untrusted connections",
            "Ransomware groups specifically target exposed MSSQL instances",
        ],
        "attack_vectors": [
            "Brute force against default SA account or weak passwords",
            "Remote OS command execution via xp_cmdshell if SA access obtained",
            "Data exfiltration of entire database contents",
            "Ransomware deployment via compromised SA credentials",
        ],
        "mitigations": [
            "Block at perimeter firewall — never expose to internet",
            "Restrict to application servers only via host firewall",
            "Disable xp_cmdshell and other dangerous extended stored procedures",
            "Use Windows Authentication instead of SQL Authentication where possible",
            "Rename or disable the SA account; use dedicated application accounts",
            "Enable SQL Server Audit for suspicious activity detection",
        ],
        "open_risk": "critical",
    },
    1521: {
        "description": (
            "Oracle Database Listener — The default port for Oracle RDBMS. "
            "Oracle databases contain business-critical data and internet exposure "
            "represents a severe risk."
        ),
        "vulnerabilities": [
            "Default credentials (scott/tiger, system/manager) may not be changed",
            "TNS Poison attack enables MITM on database connections",
            "Listener enumeration reveals database instance names (SIDs)",
            "Historical remote buffer overflow vulnerabilities in Oracle listener",
        ],
        "attack_vectors": [
            "Default credential exploitation for unauthorized database access",
            "TNS poisoning for MITM of application database traffic",
            "SID enumeration to identify target databases",
            "Remote code execution via unpatched Oracle vulnerabilities",
        ],
        "mitigations": [
            "Block at perimeter firewall — never expose to internet",
            "Change all default Oracle credentials immediately",
            "Enable Oracle Connection Manager (CMAN) for connection filtering",
            "Use sqlnet.ora VALID_NODE_CHECKING to restrict client IPs",
            "Keep Oracle CPU (Critical Patch Update) current",
            "Enable Oracle Audit Vault for suspicious activity monitoring",
        ],
        "open_risk": "critical",
    },
    1723: {
        "description": (
            "PPTP VPN — Point-to-Point Tunneling Protocol. A deprecated VPN protocol "
            "with well-documented cryptographic weaknesses. MS-CHAPv2 (its authentication "
            "method) can be broken in real time with modern hardware."
        ),
        "vulnerabilities": [
            "MS-CHAPv2 authentication can be broken via offline dictionary attack",
            "PPTP encryption (MPPE) has fundamental cryptographic weaknesses",
            "Captured VPN handshakes can be decrypted offline",
            "No perfect forward secrecy",
        ],
        "attack_vectors": [
            "Capture PPTP handshake and perform offline password cracking",
            "Decrypt VPN tunnel traffic once password is recovered",
        ],
        "mitigations": [
            "Disable PPTP VPN immediately — the protocol is cryptographically broken",
            "Migrate to WireGuard (modern, high performance, secure)",
            "Alternatively: OpenVPN with certificate authentication, or IKEv2/IPSec",
            "Block port 1723 at the firewall",
        ],
        "open_risk": "critical",
    },
    2049: {
        "description": (
            "NFS — Network File System. Enables file sharing across networks. "
            "NFSv3 and below have minimal authentication (UID-based) and no encryption. "
            "Internet exposure of NFS is extremely dangerous."
        ),
        "vulnerabilities": [
            "NFSv3 uses UID/GID for access control — trivially spoofed",
            "No encryption in NFSv3 — all file content readable on the network",
            "Misconfigured exports may allow access from any host (wildcard *)",
            "Privilege escalation via UID manipulation (set UID 0 on attacking machine)",
        ],
        "attack_vectors": [
            "Mount NFS shares without authentication if exported with wildcard",
            "Spoof UID to gain unauthorized file access",
            "Read/write to sensitive files (SSH keys, /etc/passwd, etc.)",
            "Privilege escalation by overwriting system files",
        ],
        "mitigations": [
            "Block at perimeter firewall — never expose to internet",
            "Restrict NFS exports to specific trusted hosts (no wildcards)",
            "Use NFSv4 with Kerberos authentication (sec=krb5p)",
            "Mount with nosuid,noexec,nodev options",
            "Audit /etc/exports regularly for overly permissive entries",
        ],
        "open_risk": "critical",
    },
    3306: {
        "description": (
            "MySQL — Widely used open-source relational database. "
            "Direct internet exposure of database servers is a critical misconfiguration "
            "that regularly leads to large-scale data breaches."
        ),
        "vulnerabilities": [
            "Brute force against root or application database accounts",
            "Unauthorized access to all database contents",
            "FILE privilege allows reading/writing server filesystem",
            "Historical MySQL CVEs with remote code execution potential",
        ],
        "attack_vectors": [
            "Brute force against root account or commonly used credentials",
            "Direct database access for complete data exfiltration",
            "FILE privilege exploitation to read sensitive server files",
            "Ransomware targeting exposed MySQL instances",
        ],
        "mitigations": [
            "Bind MySQL to 127.0.0.1 only (bind-address = 127.0.0.1 in my.cnf)",
            "Block port 3306 at perimeter firewall",
            "Disable remote root login (skip-networking or explicit grants)",
            "Use dedicated application accounts with minimal privileges",
            "Enable MySQL audit plugin for access monitoring",
            "Use SSL/TLS for encrypted connections",
        ],
        "open_risk": "critical",
    },
    3389: {
        "description": (
            "RDP — Remote Desktop Protocol. Provides full graphical Windows remote access. "
            "Directly exposed RDP is the #1 initial access vector for ransomware operators. "
            "It should never be internet-facing without additional security layers."
        ),
        "vulnerabilities": [
            "BlueKeep (CVE-2019-0708) — wormable pre-auth RCE on older Windows",
            "DejaBlue (CVE-2019-1181/1182) — RCE on newer Windows versions",
            "Credential brute force — automated tools scan for open RDP globally",
            "Pass-the-Hash attacks using captured NTLM credentials",
            "Primary ransomware delivery method in the wild",
        ],
        "attack_vectors": [
            "Automated brute force of RDP credentials (numerous exploit kits)",
            "BlueKeep wormable exploit for unauthenticated RCE",
            "Pass-the-Hash / Pass-the-Ticket lateral movement",
            "Ransomware operators gain access and manually deploy ransomware",
        ],
        "mitigations": [
            "NEVER expose RDP directly to the internet",
            "Require VPN authentication before RDP access (defense in depth)",
            "Enable Network Level Authentication (NLA) to require credentials before session",
            "Implement MFA on RDP access",
            "Apply all BlueKeep/DejaBlue patches",
            "Change RDP to a non-standard port (minor obscurity)",
            "Implement account lockout to prevent brute force",
            "Use RD Gateway with certificate authentication for controlled access",
        ],
        "open_risk": "critical",
    },
    5432: {
        "description": (
            "PostgreSQL — Advanced open-source relational database. "
            "Like all database servers, internet exposure significantly increases "
            "the risk of data breaches and unauthorized access."
        ),
        "vulnerabilities": [
            "Brute force against postgres superuser account",
            "COPY TO/FROM PROGRAM allows OS command execution if compromised",
            "Unrestricted database access if pg_hba.conf is misconfigured",
            "Historical CVEs with remote code execution impact",
        ],
        "attack_vectors": [
            "Superuser credential brute force",
            "OS command execution via COPY PROGRAM with superuser access",
            "Complete database exfiltration with any valid account",
            "Ransomware deployment via compromised database credentials",
        ],
        "mitigations": [
            "Bind to localhost only (listen_addresses = 'localhost')",
            "Block port 5432 at perimeter firewall",
            "Use pg_hba.conf to restrict access to application server IPs",
            "Disable superuser remote login",
            "Use dedicated application users with minimum required privileges",
            "Enable pgaudit for comprehensive access logging",
        ],
        "open_risk": "critical",
    },
    5900: {
        "description": (
            "VNC — Virtual Network Computing. Provides graphical remote desktop access "
            "to the target machine. VNC has weak or absent authentication by default and "
            "typically transmits traffic unencrypted."
        ),
        "vulnerabilities": [
            "No or weak authentication by default on many VNC implementations",
            "No encryption — full screen content transmitted in plaintext",
            "Credential brute force — simple 4-8 digit VNC passwords are easily broken",
            "Historical CVEs in LibVNCServer and other VNC implementations",
            "RFB protocol replay attacks",
        ],
        "attack_vectors": [
            "Direct unauthenticated access if no password is set",
            "Password brute force (short numeric passwords are common)",
            "Network capture to view entire desktop session",
            "RFB protocol exploitation on vulnerable VNC servers",
        ],
        "mitigations": [
            "Never expose VNC to the internet",
            "Access VNC exclusively through SSH tunneling",
            "Enforce a strong VNC password (not just numeric)",
            "Use VNC implementations with TLS support",
            "Consider replacing with RDP or modern remote desktop solutions",
        ],
        "open_risk": "critical",
    },
    6379: {
        "description": (
            "Redis — High-performance in-memory data store and cache. "
            "Redis has no authentication by default and is frequently misconfigured "
            "to be internet-accessible, leading to data theft and server compromise."
        ),
        "vulnerabilities": [
            "No authentication required by default — all data immediately accessible",
            "CONFIG SET allows writing arbitrary files to the server filesystem",
            "Can write SSH authorized_keys to gain OS shell access",
            "Can write cron jobs for persistent code execution",
            "SSRF-to-Redis attacks allow exploiting Redis via web application bugs",
        ],
        "attack_vectors": [
            "Direct unauthenticated access to read all stored data",
            "CONFIG SET dir + CONFIG SET dbfilename + SAVE to write SSH keys → RCE",
            "CONFIG SET to write webshells in web directories",
            "SSRF attacks from web applications that can reach Redis",
        ],
        "mitigations": [
            "Bind to 127.0.0.1 only (bind 127.0.0.1 in redis.conf)",
            "Set a strong requirepass in redis.conf",
            "Disable dangerous commands: CONFIG, SLAVEOF, DEBUG, FLUSHALL",
            "Use Redis ACL (Access Control Lists) in Redis 6+",
            "Block port 6379 at all firewall levels",
            "Run Redis as a non-privileged user",
        ],
        "open_risk": "critical",
    },
    8080: {
        "description": (
            "HTTP Alternate — Common secondary HTTP port used for web proxies, "
            "development/staging servers, admin panels, and application servers. "
            "Often less hardened than the primary port 80."
        ),
        "vulnerabilities": [
            "Admin panels and management interfaces may be exposed",
            "Development/staging servers often have weaker security than production",
            "Proxy misconfiguration may allow traffic interception",
            "Same cleartext issues as HTTP port 80",
        ],
        "attack_vectors": [
            "Access to admin panels or management interfaces",
            "Exploitation of development server vulnerabilities",
            "Proxy abuse to intercept or relay traffic",
        ],
        "mitigations": [
            "Restrict access if serving admin interfaces — whitelist known IPs",
            "Redirect to HTTPS equivalent (port 8443)",
            "Implement proper authentication on all management interfaces",
            "Remove development/staging servers from internet exposure",
        ],
        "open_risk": "medium",
    },
    8443: {
        "description": (
            "HTTPS Alternate — Common secondary HTTPS port used for admin panels, "
            "management interfaces, and secondary web services. "
            "TLS-encrypted equivalent of port 8080."
        ),
        "vulnerabilities": [
            "Admin panels exposed with weak authentication",
            "Outdated TLS configurations less likely to be hardened",
            "Self-signed certificates may indicate lack of operational security",
        ],
        "attack_vectors": [
            "Brute force against admin panel authentication",
            "Exploitation of vulnerabilities in admin/management software",
            "Weak TLS configuration exploitation",
        ],
        "mitigations": [
            "Restrict access to trusted IPs via firewall rules",
            "Implement MFA on all management interfaces",
            "Use TLS 1.2+ with strong cipher suites",
            "Keep management software (Tomcat, Jenkins, Kibana, etc.) updated",
        ],
        "open_risk": "medium",
    },
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_valid_target(target: str) -> bool:
    return bool(_IP_PATTERN.match(target) or _DOMAIN_PATTERN.match(target))


# ---------------------------------------------------------------------------
# IP geolocation / reputation (ipinfo.io free tier — no API key required)
# ---------------------------------------------------------------------------

# Subset of ISO 3166-1 alpha-2 → country name
_COUNTRY_NAMES: dict[str, str] = {
    "AF":"Afghanistan","AL":"Albania","DZ":"Algeria","AR":"Argentina","AU":"Australia",
    "AT":"Austria","BD":"Bangladesh","BE":"Belgium","BR":"Brazil","BG":"Bulgaria",
    "CA":"Canada","CL":"Chile","CN":"China","CO":"Colombia","HR":"Croatia",
    "CZ":"Czech Republic","DK":"Denmark","EG":"Egypt","FI":"Finland","FR":"France",
    "DE":"Germany","GH":"Ghana","GR":"Greece","HK":"Hong Kong","HU":"Hungary",
    "IN":"India","ID":"Indonesia","IR":"Iran","IQ":"Iraq","IE":"Ireland",
    "IL":"Israel","IT":"Italy","JP":"Japan","JO":"Jordan","KZ":"Kazakhstan",
    "KE":"Kenya","KR":"South Korea","KW":"Kuwait","LB":"Lebanon","MY":"Malaysia",
    "MX":"Mexico","MA":"Morocco","NL":"Netherlands","NZ":"New Zealand","NG":"Nigeria",
    "NO":"Norway","PK":"Pakistan","PE":"Peru","PH":"Philippines","PL":"Poland",
    "PT":"Portugal","QA":"Qatar","RO":"Romania","RU":"Russia","SA":"Saudi Arabia",
    "SG":"Singapore","ZA":"South Africa","ES":"Spain","SE":"Sweden","CH":"Switzerland",
    "TW":"Taiwan","TH":"Thailand","TN":"Tunisia","TR":"Turkey","UA":"Ukraine",
    "AE":"United Arab Emirates","GB":"United Kingdom","US":"United States",
    "VN":"Vietnam","YE":"Yemen",
}


def get_ip_info(ip: str) -> dict:
    """
    Fetch geolocation and organisation data from ipinfo.io (free tier).
    Falls back gracefully if the request fails or times out.
    """
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "PortScanner-RiskAnalyzer/2.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())

        country_code = data.get("country", "")
        country_name = _COUNTRY_NAMES.get(country_code, country_code or "Unknown")

        org_raw = data.get("org", "")          # e.g. "AS15169 Google LLC"
        # Strip leading ASN (e.g. "AS15169 ") for cleaner display
        org = " ".join(org_raw.split()[1:]) if org_raw else "Unknown"

        return {
            "country_code": country_code,
            "country": country_name,
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "org": org,
            "asn": org_raw.split()[0] if org_raw else "",
            "timezone": data.get("timezone", "Unknown"),
            "hostname": data.get("hostname", ""),
        }
    except Exception as exc:
        logger.warning("IP info lookup failed for %s: %s", ip, exc)
        return {
            "country_code": "", "country": "Unknown", "city": "Unknown",
            "region": "Unknown", "org": "Unknown", "asn": "",
            "timezone": "Unknown", "hostname": "",
        }


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

# Services that MUST send a greeting banner immediately after TCP connect.
# Absence of a banner after a successful handshake indicates a transparent
# proxy/firewall false positive and the port should be reported as filtered.
_BANNER_SERVICES: frozenset[int] = frozenset({
    21,   # FTP  — "220 ..."
    22,   # SSH  — "SSH-2.0-..."
    23,   # Telnet — escape sequences
    25,   # SMTP — "220 ..."
    110,  # POP3 — "+OK ..."
    143,  # IMAP — "* OK ..."
    587,  # SMTP submission — "220 ..."
    993,  # IMAPS — "* OK ..." (after TLS)
    995,  # POP3S — "+OK ..." (after TLS)
})


def scan_port(host: str, port: int) -> tuple[str, Optional[float]]:
    """
    Attempt a TCP connection to (host, port).

    Returns:
        ("open",     response_time_ms) — port is accepting connections
        ("closed",   None)             — connection actively refused (ECONNREFUSED)
        ("filtered", None)             — timed out, silently dropped, or banner-
                                         less connect on a known banner service
                                         (transparent proxy false-positive guard)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    start = time.monotonic()
    try:
        sock.connect((host, port))
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        # Banner-service verification: FTP/SSH/SMTP/POP3/IMAP etc. must send a
        # greeting within ~1 s of accepting the connection.  A TCP handshake that
        # succeeds but produces no banner almost always means a transparent proxy
        # or NAT device accepted the SYN/ACK on behalf of the real destination
        # (false positive).  Treat these as filtered (inconclusive) rather than open.
        if port in _BANNER_SERVICES:
            # Allow 2 s for the banner — SSH on high-latency links can take >1 s.
            # FTP/SMTP/POP3/IMAP send banners within milliseconds when genuinely open,
            # so a 2 s wait still reliably separates real services from transparent proxies.
            sock.settimeout(2.0)
            try:
                banner = sock.recv(512)
                if banner:
                    return "open", elapsed_ms     # confirmed by real service banner
                # Empty recv = server closed connection without sending any data
                return "closed", None
            except socket.timeout:
                # Connected but no banner in 2 s — transparent proxy false positive
                return "filtered", None
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                # RST after connect = transparent proxy / firewall rejected us
                return "closed", None

        return "open", elapsed_ms
    except socket.timeout:
        return "filtered", None
    except ConnectionRefusedError:
        return "closed", None
    except OSError:
        return "filtered", None
    finally:
        sock.close()


def analyze_port(port: int, service: str, status: str, response_time: Optional[float]) -> dict:
    """Build the security analysis record for a single port result."""
    intel = SECURITY_INTEL.get(port, {})

    if status == "open":
        risk_level = intel.get("open_risk", "medium")
        description = intel.get(
            "description",
            f"{service} service detected on port {port}.",
        )
        vulnerabilities: list[str] = intel.get(
            "vulnerabilities", ["Service is accessible; review security configuration"]
        )
        attack_vectors: list[str] = intel.get(
            "attack_vectors", ["Potential unauthorized access via this service"]
        )
        mitigations: list[str] = intel.get(
            "mitigations", ["Restrict access via firewall", "Review service configuration"]
        )
        brief = (
            f"Port OPEN — {service} service is responding. "
            f"{vulnerabilities[0] if vulnerabilities else 'Review configuration.'}"
        )

    elif status == "closed":
        risk_level = "low"
        description = (
            f"Port {port} ({service}) is CLOSED. The target actively refused the connection, "
            "meaning no service is currently listening on this port. Closed ports are significantly "
            "safer than open ports because there is no running service to exploit. However, the "
            "closed status itself is still visible to an attacker during reconnaissance — they know "
            "the host is alive and that this port exists but is not accepting connections."
        )
        vulnerabilities = []
        attack_vectors = []
        mitigations = [
            "Port is closed; no service exposure on this port",
            "Continue monitoring — services can start or port configurations can change",
        ]
        brief = description

    else:  # filtered
        risk_level = "low"
        description = (
            f"Port {port} ({service}) is FILTERED. No response was received within the timeout, "
            "indicating that a firewall, packet filter, or network device is silently dropping "
            "connection attempts. This result is INCONCLUSIVE: a service may or may not be running "
            "behind the filter. Filtered ports are generally preferable to open ports, as they "
            "reveal less information to an attacker. However, relying solely on firewall filtering "
            "without additional security measures is not sufficient."
        )
        vulnerabilities = []
        attack_vectors = []
        mitigations = [
            "Firewall filtering is active — verify rules are correctly configured",
            "Ensure filtering is comprehensive and not bypassable via other ports",
            "Implement defense-in-depth; do not rely solely on firewall filtering",
        ]
        brief = description

    return {
        "port": port,
        "service": service,
        "status": status,
        "risk_level": risk_level,
        "response_time_ms": response_time,
        "description": description,
        "vulnerabilities": vulnerabilities,
        "attack_vectors": attack_vectors,
        "mitigations": mitigations,
        "details": brief,
    }


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


def _calc_reputation_score(results: list[dict]) -> int:
    """
    Derive a reputation score (0-100) from the scan results.
    Starts at 100 and deducts points for each open risky port.
    """
    deductions = {"critical": 20, "high": 10, "medium": 4, "low": 0}
    score = 100
    for r in results:
        if r["status"] == "open":
            score -= deductions.get(r["risk_level"], 0)
    return max(0, score)


@app.get("/scan", tags=["Scanner"])
def scan_target(target: str = Query(..., min_length=1, max_length=253, description="IPv4 address or domain name to scan")):
    """
    Scan a target host for open ports and return a detailed security risk assessment.

    Only scan systems you own or have explicit authorization to test.
    """
    target = target.strip().lower()

    if not _is_valid_target(target):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid target. Must be a valid IPv4 address "
                "(e.g., 192.168.1.1) or domain name (e.g., example.com)."
            ),
        )

    # Resolve domain to IP
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resolve target hostname: {exc}",
        )

    logger.info("Starting scan: target=%s resolved_ip=%s ports=%d", target, resolved_ip, len(PORTS))
    scan_start = time.monotonic()

    # Run port scan and IP info lookup concurrently
    results: list[dict] = []
    ip_info: dict = {}

    with ThreadPoolExecutor(max_workers=30) as executor:
        # Submit port scans
        future_map = {
            executor.submit(scan_port, resolved_ip, port): (port, service)
            for port, service in PORTS.items()
        }
        # Submit IP info lookup in parallel
        ip_info_future = executor.submit(get_ip_info, resolved_ip)

        for future in as_completed(future_map):
            port, service = future_map[future]
            try:
                status, response_time = future.result()
            except Exception as exc:
                logger.warning("Port %d scan error: %s", port, exc)
                status, response_time = "filtered", None
            results.append(analyze_port(port, service, status, response_time))

        try:
            ip_info = ip_info_future.result(timeout=8)
        except Exception as exc:
            logger.warning("IP info future error: %s", exc)
            ip_info = {}

    # Sort by port number for consistent ordering
    results.sort(key=lambda r: r["port"])

    duration_s = round(time.monotonic() - scan_start, 2)
    open_count = sum(1 for r in results if r["status"] == "open")
    reputation_score = _calc_reputation_score(results)

    logger.info(
        "Scan complete: target=%s ip=%s duration=%.2fs open=%d/%d score=%d org=%s country=%s",
        target, resolved_ip, duration_s, open_count, len(PORTS),
        reputation_score, ip_info.get("org", "?"), ip_info.get("country", "?"),
    )

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration_s,
        "total_ports": len(PORTS),
        "results": results,
        "ip_info": {
            "country_code": ip_info.get("country_code", ""),
            "country": ip_info.get("country", "Unknown"),
            "city": ip_info.get("city", "Unknown"),
            "region": ip_info.get("region", "Unknown"),
            "org": ip_info.get("org", "Unknown"),
            "asn": ip_info.get("asn", ""),
            "timezone": ip_info.get("timezone", "Unknown"),
            "hostname": ip_info.get("hostname", ""),
            "reputation_score": reputation_score,
            "is_blacklisted": reputation_score < 40,
        },
    }
