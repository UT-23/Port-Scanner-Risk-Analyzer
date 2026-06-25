# Port Scanner & Risk Analyzer

A full-stack application that scans TCP ports on a target host and provides detailed security risk analysis with actionable mitigations.

> **Important:** Only scan systems you own or have explicit written authorization to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Architecture

```
Port-Scanner-Risk-Analyzer/
├── portscanner.py          # Python FastAPI backend
├── requirements.txt        # Python dependencies
├── .env.example            # Backend environment variables template
├── tests/
│   └── test_scanner.py     # Backend unit & integration tests
└── Frontend/               # React + TypeScript + Vite frontend
    ├── src/
    │   ├── components/scanner/   # Scanner UI components
    │   ├── lib/
    │   │   ├── api.ts            # API client (with mock fallback)
    │   │   └── mockData.ts       # Demo data generator
    │   ├── pages/Index.tsx       # Main application page
    │   └── types/scanner.ts      # TypeScript type definitions
    ├── vite.config.ts
    ├── tailwind.config.ts
    └── .env.example        # Frontend environment variables template
```

---

## Features

### Port Scanning
- Scans **28 common ports** concurrently via raw TCP sockets
- Detects port status: **Open**, **Closed**, or **Filtered**
- Measures **response time** (ms) for open ports
- Resolves domain names to IP addresses

### Security Analysis (per open port)
- Service description and context
- Known vulnerabilities (CVEs, protocol weaknesses)
- Attack vectors used by threat actors
- Recommended mitigations with specific steps
- **4-level risk rating:** Critical · High · Medium · Low

### Frontend
- Cybersecurity-themed dark UI built with React + Tailwind CSS
- Live backend connection with graceful demo-mode fallback
- Expandable port rows showing full security details
- Educational mode for non-technical explanations
- Scan history with quick re-scan
- Export reports as `.txt` or `.html`
- Responsive layout (mobile / tablet / desktop)

---

## Ports Scanned

| Port  | Service       | Open Risk  |
|-------|---------------|------------|
| 20    | FTP-Data      | High       |
| 21    | FTP           | **Critical**|
| 22    | SSH           | Medium     |
| 23    | Telnet        | **Critical**|
| 25    | SMTP          | Medium     |
| 53    | DNS           | Medium     |
| 80    | HTTP          | Medium     |
| 110   | POP3          | High       |
| 111   | RPCBind       | High       |
| 135   | MS-RPC        | **Critical**|
| 139   | NetBIOS       | **Critical**|
| 143   | IMAP          | High       |
| 443   | HTTPS         | Low        |
| 445   | SMB           | **Critical**|
| 587   | SMTP-TLS      | Medium     |
| 993   | IMAPS         | Low        |
| 995   | POP3S         | Low        |
| 1433  | MSSQL         | **Critical**|
| 1521  | Oracle-DB     | **Critical**|
| 1723  | PPTP          | **Critical**|
| 2049  | NFS           | **Critical**|
| 3306  | MySQL         | **Critical**|
| 3389  | RDP           | **Critical**|
| 5432  | PostgreSQL    | **Critical**|
| 5900  | VNC           | **Critical**|
| 6379  | Redis         | **Critical**|
| 8080  | HTTP-Alt      | Medium     |
| 8443  | HTTPS-Alt     | Medium     |

---

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Backend

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Copy and edit environment variables (optional)
copy .env.example .env

# Start the backend server
uvicorn portscanner:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

API documentation (auto-generated): `http://localhost:8000/docs`

### 2. Frontend

```bash
cd Frontend

# Install dependencies
npm install

# Copy and edit environment variables (optional)
copy .env.example .env

# Start the development server
npm run dev
```

The app will be available at `http://localhost:5173`.

### 3. Production Build

```bash
cd Frontend
npm run build
# Output is in Frontend/dist/
```

---

## API Endpoints

### `GET /health`
Returns server health status.

**Response:**
```json
{ "status": "ok", "timestamp": "2025-01-01T00:00:00+00:00" }
```

### `GET /scan?target=<ip_or_domain>`
Scans the target and returns security analysis.

**Parameters:**
- `target` (string, required) — IPv4 address or domain name

**Example:**
```bash
curl "http://localhost:8000/scan?target=192.168.1.1"
```

**Response:**
```json
{
  "target": "192.168.1.1",
  "resolved_ip": "192.168.1.1",
  "scanned_at": "2025-01-01T00:00:00+00:00",
  "duration_seconds": 1.23,
  "total_ports": 28,
  "results": [
    {
      "port": 22,
      "service": "SSH",
      "status": "open",
      "risk_level": "medium",
      "response_time_ms": 4.5,
      "description": "SSH — Secure Shell...",
      "vulnerabilities": ["Password authentication enables brute-force attacks"],
      "attack_vectors": ["Credential brute force / dictionary attacks"],
      "mitigations": ["Disable password authentication; use key-based auth only"],
      "details": "Port OPEN — SSH service is responding..."
    }
  ]
}
```

---

## Running Tests

```bash
# From the project root (not Frontend/)
pip install -r requirements.txt
pytest tests/ -v
```

---

## Demo Mode

If the backend is not running, the frontend automatically switches to **Demo Mode** — generating realistic (but randomized) scan results locally. A banner in the UI indicates when demo data is being displayed.

---

## Future Improvements

1. **IP Reputation API** — integrate AbuseIPDB, Shodan, or VirusTotal for real reputation scores
2. **Authentication** — add API key or JWT authentication for production use
3. **Rate limiting** — prevent abuse with per-IP request throttling
4. **UDP scanning** — detect UDP-based services (DNS, NTP, SNMP)
5. **Service version detection** — banner grabbing to identify software versions
6. **CVE lookup** — auto-lookup current CVEs for detected service versions
7. **Scheduled scans** — periodic monitoring with change alerts
8. **Database persistence** — store scan history in SQLite/PostgreSQL
9. **PDF reports** — export security reports as PDF

---

## Security Considerations

- **CORS**: The backend defaults to `ALLOWED_ORIGINS=*` for development. In production, set this to your frontend's domain.
- **Input validation**: The backend validates IP and domain format before scanning.
- **Authorization**: This tool performs TCP connection attempts. Only use it on systems you own or have explicit authorization to test.
- **Rate limiting**: No rate limiting is implemented by default — add middleware for production deployments.
