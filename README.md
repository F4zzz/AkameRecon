# AkameRecon

AkameRecon is a powerful reconnaissance tool for penetration testing that automates the process of domain reconnaissance to assist security assessments, including subdomain discovery, DNS resolution, port scanning, fingerprinting, and more.

## Features

- **Subdomain Enumeration**: Discover subdomains using passive techniques (crt.sh, subfinder, amass) and DNS bruteforce
- **DNS Resolution**: Resolve domains to IPs and collect various DNS records (A, AAAA, CNAME, MX, NS, TXT)
- **Port Scanning**: Identify open ports and services using nmap or naabu
- **Web Service Analysis**: Detect web technologies, take screenshots, and collect HTTP response data
- **Report Generation**: Create detailed reports in JSON and CSV formats
- **Vulnerability Scanning**: Integration with Nuclei for vulnerability detection

## Installation

```bash
# Clone the repository
git clone https://github.com/F4zzz/AkameRecon.git
cd AkameRecon

# Install requirements
pip install -r requirements.txt

# Make the script executable
chmod +x main.py
```

## Usage

Basic usage:

```bash
./main.py -d example.com [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (required) |
| `--full` | Perform full reconnaissance |
| `--passive` | Only passive techniques (OSINT) |
| `--active` | Only active techniques (DNS, ports) |
| `--report` | Generate detailed JSON/CSV report |
| `-o, --output` | Custom output directory |
| `-v, --verbose` | Verbose mode for more details |
| `--auto` | Automatic mode without user interaction |

### Examples

Basic passive reconnaissance:
```bash
./main.py -d example.com --passive
```

Full reconnaissance with automatic mode:
```bash
./main.py -d example.com --full --auto
```

Active reconnaissance with custom output directory:
```bash
./main.py -d example.com --active -o /path/to/output
```

## Configuration

You can customize the tool's behavior by editing the `config.yaml` file:

- DNS resolvers and record types
- Subdomain enumeration settings and wordlists
- Port scanning configuration
- Web scanning preferences
- Nuclei integration settings

## Docker Support

AkameRecon can be run inside a Docker container:

```bash
# Build the Docker image
docker build -t akamerecon .

# Run AkameRecon in a container
docker run -it --rm -v $(pwd)/output:/app/output akamerecon -d example.com --full
```

## Requirements

- Python 3.8+
- Subfinder
- Amass (optional)
- Nmap
- Nuclei (optional for vulnerability scanning)
