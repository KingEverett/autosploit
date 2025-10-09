# 🚗 Autosploit Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![UV](https://img.shields.io/badge/UV-package%20manager-green.svg)](https://github.com/astral-sh/uv)

**A comprehensive, modular framework for automotive security testing, diagnostics, and research.**

Inspired by Metasploit's architecture but purpose-built for the automotive domain, Autosploit provides a unified platform for working with CAN bus, OBD-II, ISO-TP, UDS, and other vehicle protocols. Unlike traditional penetration testing tools, Autosploit focuses on legitimate security research, diagnostics, performance tuning, and education.

---

## 🎯 Project Vision

Autosploit aims to be **the** professional toolkit for automotive security researchers, penetration testers, diagnosticians, and enthusiasts. We're building a framework that:

- **Democratizes automotive security research** - Makes sophisticated testing accessible
- **Standardizes methodology** - Provides consistent tooling across vehicle platforms
- **Prioritizes safety** - Built-in safeguards to prevent dangerous operations
- **Enables learning** - Comprehensive documentation and educational resources
- **Supports compliance** - Generate reports for ISO 21434, UNECE R155
- **Remains vendor-neutral** - Works across all manufacturers and protocols

---

## ✨ Key Features

### 🔧 **Modular Architecture**
- Plugin-based system inspired by Metasploit
- Easy to extend with custom modules
- Hardware abstraction layer for different CAN interfaces
- Organized by automotive domain (diagnostics, firmware, wireless, etc.)

### 🚙 **Protocol Support**
- **CAN Bus** - Full support for CAN 2.0A/B
- **OBD-II** - All standard modes and PIDs
- **ISO-TP** - Multi-frame message support
- **UDS** - Unified Diagnostic Services
- **KWP2000** - Keyword Protocol 2000
- **LIN** - Local Interconnect Network (planned)
- **FlexRay** - High-speed automotive protocol (planned)

### 🛠️ **Module Categories**

#### **Auxiliary** - Utilities and helpers
- Bus sniffers and analyzers
- Protocol parsers
- Traffic generators
- Fuzzing engines
- Data loggers

#### **Scanners** - Discovery and enumeration
- ECU discovery
- Service enumeration
- VIN decoding
- DTC reading
- Network mapping

#### **Diagnostic** - Official testing protocols
- OBD-II diagnostics
- UDS diagnostic services
- Manufacturer-specific modes
- DTC management
- ECU reset and programming

#### **Exploits** - Security testing (research only)
- Known CVE implementations
- Proof-of-concept attacks
- Vulnerability demonstrations
- **Safety-locked** - Requires explicit confirmation

#### **Firmware** - ECU software analysis
- Firmware extraction
- Binary analysis
- Bootloader detection
- Update mechanisms
- Tuning maps

#### **Wireless** - RF and V2X testing
- Key fob analysis
- TPMS testing
- Bluetooth/Wi-Fi auditing
- V2V/V2X simulation

#### **Payloads** - Post-exploitation actions
- Vehicle control demonstrations
- Data exfiltration
- Persistence mechanisms
- **Educational purposes only**

#### **Post** - After initial access
- Deeper reconnaissance
- Privilege escalation
- Lateral movement
- **Strictly for authorized testing**

#### **Encoders** - Data transformation
- Packet encoding/decoding
- Protocol conversion
- Data obfuscation
- Signature evasion

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** 
- **Linux** (recommended) or macOS
- **CAN hardware** - Virtual CAN (`vcan`) for testing, or real hardware:
  - SocketCAN-compatible adapters
  - CANable/CANtact
  - PCAN USB adapters
  - Kvaser devices
  - ValueCAN

### Installation

```bash
# Install UV (modern Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/yourusername/autosploit.git
cd autosploit

# Install dependencies
uv sync

# Verify installation
uv run autosploit --version
```

### First Run

```bash
# Set up virtual CAN for testing (Linux only)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Launch Autosploit
uv run autosploit

# Inside the framework
autosploit > show modules
autosploit > use auxiliary/sniffer/candump
autosploit (candump) > set CANINTERFACE vcan0
autosploit (candump) > run
```

---

## 📖 Usage Examples

### Example 1: Basic CAN Bus Sniffing

```bash
autosploit > use auxiliary/sniffer/candump
autosploit (candump) > show options

Module options (auxiliary/sniffer/candump):

   Name          Current   Required  Description
   ----          -------   --------  -----------
   CANINTERFACE            yes       CAN interface name
   DURATION      0         no        Capture duration (0=continuous)
   FILTER                  no        CAN ID filter

autosploit (candump) > set CANINTERFACE can0
autosploit (candump) > set DURATION 30
autosploit (candump) > run

[*] Starting CAN capture on can0 for 30 seconds...
[*] Press Ctrl+C to stop early

  Timestamp     ID      Data
  ---------     --      ----
  1696723450.1  0x201   00 14 32 00 00 E1 00 00
  1696723450.1  0x316   1A 2F 03 E8 00 00 00 00
  ...
```

### Example 2: OBD-II Vehicle Diagnostics

```bash
autosploit > use diagnostic/obdii/dtc_reader
autosploit (dtc_reader) > set CANINTERFACE can0
autosploit (dtc_reader) > run

[*] Querying vehicle for diagnostic trouble codes...
[+] Found 2 DTCs:

  Code     Status    Description
  ----     ------    -----------
  P0171    Pending   System Too Lean (Bank 1)
  P0420    Stored    Catalyst System Efficiency Below Threshold

[*] Would you like to clear these codes? [y/N]: n
```

### Example 3: ECU Discovery and Fingerprinting

```bash
autosploit > use scanner/can_discovery
autosploit (can_discovery) > set CANINTERFACE can0
autosploit (can_discovery) > set TIMEOUT 60
autosploit (can_discovery) > run

[*] Scanning CAN bus for 60 seconds...
[*] Collecting arbitration IDs...
[+] Discovered 47 unique IDs

[*] Analyzing patterns...
[+] Identified likely ECUs:

  ECU              Arb IDs          Services
  ---              -------          --------
  Engine Control   0x7E0, 0x7E8     UDS, OBD-II
  Transmission     0x7E1, 0x7E9     UDS
  ABS              0x760, 0x768     UDS
  Body Control     0x733, 0x73B     Custom
  
[*] Scan complete!
```

### Example 4: Firmware Analysis

```bash
autosploit > use firmware/extractor/uds_dump
autosploit (uds_dump) > set CANINTERFACE can0
autosploit (uds_dump) > set ECU_ID 0x7E0
autosploit (uds_dump) > set OUTPUT_FILE ecu_dump.bin
autosploit (uds_dump) > run

[*] Initiating diagnostic session...
[+] Session established
[*] Requesting security access...
[!] Security access required - attempting seed/key...
[+] Access granted
[*] Reading memory...
Progress: [████████████████████] 100% (2.5 MB/2.5 MB)
[+] Firmware dumped to: ecu_dump.bin
```

---

## 🏗️ Architecture

### Module Structure

```
autosploit/
├── core/                       # Framework core
│   ├── module_manager.py       # Module loading and management
│   ├── console.py              # Interactive CLI interface
│   ├── config.py               # Configuration management
│   └── database.py             # Vehicle/ECU database
│
├── lib/                        # Shared libraries
│   ├── hardware/               # Hardware abstraction
│   │   ├── can_interface.py   # CAN interface wrapper
│   │   ├── obd_adapter.py     # OBD-II adapter
│   │   └── sdr_radio.py       # Software-defined radio
│   ├── protocols/              # Protocol implementations
│   │   ├── can.py              # CAN protocol
│   │   ├── isotp.py            # ISO-TP protocol
│   │   ├── uds.py              # UDS services
│   │   └── obdii.py            # OBD-II modes
│   └── utilities/              # Helper functions
│       ├── packet_parser.py
│       ├── dtc_decoder.py
│       └── vin_decoder.py
│
├── modules/                    # All modules organized by type
│   ├── auxiliary/
│   ├── scanners/
│   ├── diagnostic/
│   ├── exploits/
│   ├── firmware/
│   ├── wireless/
│   ├── payloads/
│   ├── post/
│   └── encoders/
│
├── data/                       # Databases and resources
│   ├── vehicles.db             # Vehicle database
│   ├── dtc_codes.json          # DTC definitions
│   └── obd_pids.json           # OBD-II PIDs
│
└── docs/                       # Documentation
    ├── modules/                # Module documentation
    ├── protocols/              # Protocol references
    └── tutorials/              # Guides and tutorials
```

### Plugin System

Every module inherits from `ModuleBase` and implements:

```python
from autosploit.core.plugin_base import ModuleBase

class MyCoolModule(ModuleBase):
    def __init__(self):
        super().__init__()
        self.metadata = {
            'name': 'My Cool Module',
            'description': 'Does something cool',
            'author': 'Your Name',
            'category': 'auxiliary',
            'targets': ['All vehicles'],
            'references': []
        }
        
        self.options = {
            'CANINTERFACE': {
                'value': '',
                'required': True,
                'description': 'CAN interface name'
            }
        }
    
    def check(self):
        """Check if target is vulnerable/compatible"""
        return True
    
    def run(self):
        """Execute the module"""
        interface = self.options['CANINTERFACE']['value']
        # Your module logic here
        self.print_good("Module executed successfully!")
```

---

## 🛡️ Safety Features

Autosploit includes multiple safety mechanisms:

1. **Simulation Mode** - Test exploits in virtual environment
2. **Confirmation Prompts** - Dangerous operations require explicit approval
3. **Audit Logging** - All actions logged for accountability
4. **Hardware Checks** - Verify safe operation before execution
5. **Rate Limiting** - Prevent bus flooding and DoS
6. **Emergency Stop** - Ctrl+C always stops execution immediately

---

## 🧪 Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=autosploit --cov-report=html

# Run specific test file
uv run pytest tests/test_can_interface.py

# Run tests matching pattern
uv run pytest -k "test_isotp"
```

### Code Quality

```bash
# Format code with Black
uv run black .

# Lint with Ruff
uv run ruff check .

# Type checking with mypy
uv run mypy src/autosploit

# All quality checks
uv run black . && uv run ruff check . && uv run mypy src/autosploit
```

### Creating a New Module

```bash
# Generate module template
uv run autosploit-dev create-module \
    --type auxiliary \
    --name my_new_scanner \
    --author "Your Name"

# Edit the generated file
vim modules/auxiliary/scanner/my_new_scanner.py

# Test your module
uv run autosploit
> use auxiliary/scanner/my_new_scanner
> info
> run
```

---

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Getting Started Guide](docs/getting-started.md)** - Installation and first steps
- **[Module Development Guide](docs/module-development.md)** - Creating custom modules
- **[Protocol Reference](docs/protocols/)** - CAN, ISO-TP, UDS, OBD-II details
- **[Hardware Guide](docs/hardware.md)** - Supported interfaces and setup
- **[API Reference](docs/api/)** - Framework API documentation
- **[Tutorials](docs/tutorials/)** - Step-by-step guides

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas We Need Help With

- 🔌 **Hardware Support** - Adding new CAN interface drivers
- 📦 **Module Development** - Creating new scanners, diagnostics, tools
- 📖 **Documentation** - Improving guides and tutorials
- 🧪 **Testing** - Writing tests and reporting bugs
- 🌐 **Vehicle Database** - Adding vehicle-specific data
- 🛡️ **Security Research** - Responsible disclosure of findings

---

## ⚖️ Legal & Ethical Use

**IMPORTANT: Read this section carefully before using Autosploit.**

### Authorized Use Only

Autosploit is designed for:
- ✅ Security research on vehicles you own
- ✅ Authorized penetration testing with written permission
- ✅ Educational purposes in controlled environments
- ✅ Diagnostic and repair work
- ✅ Performance tuning on your own vehicles

### Prohibited Use

Autosploit must **NOT** be used for:
- ❌ Unauthorized access to vehicles
- ❌ Vehicle theft or aiding theft
- ❌ Malicious damage or sabotage
- ❌ Violating warranties without understanding consequences
- ❌ Any illegal activity

### Disclaimer

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** The authors and contributors are not responsible for any damages, legal consequences, or safety issues arising from use or misuse of this software. Vehicle hacking can be dangerous and may violate laws. Always obtain proper authorization and follow all applicable laws and regulations.

### Responsible Disclosure

If you discover vulnerabilities using Autosploit:
1. Do NOT disclose publicly until manufacturer has been notified
2. Contact manufacturer security teams directly
3. Allow reasonable time for patches (typically 90 days)
4. Consider coordinated disclosure programs
5. Follow ISO 21434 and UNECE R155 guidelines

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Autosploit Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

This project builds upon the work of many automotive security researchers and open-source projects:

- **[The Car Hacker's Handbook](https://nostarch.com/carhacking)** by Craig Smith - Primary inspiration and reference
- **[Metasploit Framework](https://www.metasploit.com/)** - Architecture inspiration
- **[python-can](https://python-can.readthedocs.io/)** - CAN interface library
- **[CANopen](https://github.com/christiansandberg/canopen)** - Protocol implementations
- **[ICSim](https://github.com/zombieCraig/ICSim)** - Instrument cluster simulator for testing
- **[SavvyCAN](https://www.savvycan.com/)** - Reverse engineering inspiration

Special thanks to the automotive security research community for sharing knowledge and advancing the field responsibly.

---

## 📞 Contact & Support

- **GitHub Issues** - [Report bugs or request features](https://github.com/kingeverett/autosploit/issues)
- **Discussions** - [Ask questions and share ideas](https://github.com/kingeverett/autosploit/discussions)
- **Twitter** - [@autosploit](https://twitter.com/saintprometheus) (updates and announcements)

---

## 🌟 Star History

If you find Autosploit useful, please consider giving us a star on GitHub! ⭐

---

**Happy (Ethical) Hacking! 🚗💻🔒**