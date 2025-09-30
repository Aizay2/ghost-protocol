# Ghost Protocol v2.0 - Enhanced

## Complete Anonymity Suite for Security and Privacy

Ghost Protocol is an advanced, all-in-one anonymity and security toolkit designed for privacy-conscious users, security researchers, and students in restricted network environments.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [School WiFi Guide](#school-wifi-guide)
- [Troubleshooting](#troubleshooting)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

### Core Anonymity Features
- **MAC Address Spoofing** - Change and reset network interface MAC addresses
- **Tor Routing** - Route traffic through the Tor network for anonymity
- **VPN Integration** - Connect to OpenVPN configurations
- **Kill Switch** - Emergency internet cutoff if VPN fails
- **System Cleaning** - Remove digital footprints and traces

### Network Tools
- **SSH Client** - Full terminal with password/key authentication
- **Port Scanner** - Network reconnaissance tool
- **DNS Leak Testing** - Verify anonymity setup
- **Network Monitoring** - Real-time connection status

### School-Specific Features
- **MAC Address Management** - Switch between registered and anonymous MACs
- **Auto Cleanup** - Remove evidence of usage
- **Network Bypass** - Access blocked educational resources
- **Stealth Mode** - Hide activities from network monitoring

---

## Installation

### Prerequisites
```bash
# Required dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip tor openvpn proxychains4 bleachbit iptables macchanger nmap
```

### Python Dependencies
```bash
pip install requests paramiko
```

### Running the Application
```bash
# Make executable
chmod +x ghost_protocol.py

# Run with sudo for network operations
sudo python3 ghost_protocol.py
```

---

## Quick Start

### 1. First Time Setup
1. Launch the application
2. Allow automatic installation of missing tools
3. Configure your network interface in Settings tab
4. Set up VPN configuration (optional)

### 2. Basic Usage Flow
```
Normal School Work → Ghost Mode → Anonymous Browsing → Back to Normal
      ↓                    ↓              ↓                 ↓
Registered MAC     → Random MAC   → Tor + VPN      → Registered MAC
Clean System      → Clean System → Kill Switch    → Clean System
```

---

## 📖 Detailed Usage

### Dashboard Tab
**Status Monitoring:**
- Real-time status of all services
- Network information display
- Quick access to common tests

**Quick Actions:**
- ** ACTIVATE GHOST MODE** - One-click full anonymity
- ** DEACTIVATE** - Return to normal operation
- ** Quick Tutorial** - Interactive guide

###  Tor Routing Tab
**Starting Tor:**
1. Click "Start Tor" button
2. Monitor Tor Log for connection status
3. Verify with "Test Tor" button

**Configuration:**
- **Exit Nodes**: Control which countries your traffic exits from
  - Format: `{us},{gb},{de}` (US, UK, Germany)
  - Examples: `{nl}` for Netherlands only
- **Strict Nodes**: Enforce exit node restrictions

**Usage:**
- Routes all traffic through 3+ encrypted relays
- Hides your IP address from websites
- Bypasses school content filters

### VPN Tab
**Setup:**
1. Click "Browse" to select OpenVPN config file (.ovpn)
2. Click "Connect VPN" to establish connection
3. Monitor VPN Status indicator

**Kill Switch:**
- **Purpose**: Blocks all internet if VPN disconnects unexpectedly
- **Activation**: Enable after VPN connection is established
- **Safety**: Prevents IP leaks during anonymous sessions

### Cleaner Tab
**What Gets Cleaned:**
- ✅ Browser history, cookies, and cache
- ✅ System temporary files
- ✅ Application and system logs
- ✅ DNS cache records

**Usage Options:**
- **Clean Now**: Immediate cleanup
- **Schedule Clean**: Set automatic intervals
- **Selective Cleaning**: Choose what to clean

### Network Tools Tab

#### SSH Client
**Authentication Methods:**
- **Password**: Traditional username/password
- **SSH Key**: More secure cryptographic keys
- **Auto**: Try both methods automatically

**Connecting:**
1. Enter Host, Username, and Port (default: 22)
2. Select authentication method
3. Click "Connect"
4. Use terminal for commands

**Key Management:**
- **Generate Key**: Create new SSH key pairs
- **Browse Key**: Select existing private key file
- **Supported**: RSA (4096-bit) and Ed25519 keys

#### Port Scanner
- **Target**: IP address or hostname to scan
- **Method**: TCP SYN stealth scanning
- **Usage**: Network reconnaissance and security testing

### MAC Changer Tab
**MAC Address Management:**
- **Original MAC**: Your registered school MAC address
- **Current MAC**: Currently active MAC address
- **Status Indicators**: Shows when MAC is spoofed

**Operations:**
- ** Generate Random MAC**: Creates random locally-administered MAC
- ** Change MAC Address**: Apply new MAC to interface
- ** Reset to Original**: Restore registered MAC for school WiFi

**Important**: Always reset to original MAC before accessing school WiFi!

### Settings Tab
**Configuration Options:**
- **Network Interface**: Select your active network interface
- **Auto-Start**: Configure automatic service startup
- **Logging Level**: Control verbosity of system logs
- **Save Settings**: Persist configuration changes

---

## School WiFi Guide

### Understanding Your Environment
- **MAC Filtering**: School registers your device's MAC address
- **Network Monitoring**: IT department can track activities
- **Content Filtering**: Certain websites and services blocked
- **Accountability**: Activities tied to your student account

### Safe Usage Pattern

#### For Anonymous Activities:
1. **Activate Ghost Mode**
   - MAC address changes to random value
   - Tor routing starts
   - VPN connects (if configured)
   - Kill switch enables
   - System cleans previous traces

2. **Browse Anonymously**
   - School sees encrypted Tor/VPN traffic only
   - Your real IP and activities are hidden
   - Access blocked educational resources

3. **Return to Normal**
   - **Deactivate Ghost Mode**
   - MAC resets to school-registered address
   - All services stop
   - System cleans current session traces

#### For School Work:
- Use normal connection with registered MAC
- Access school resources and WiFi
- No anonymity features active

### Recommended Workflow
```
School Day:
8:00 AM - Normal MAC → Attend classes, use school resources
12:00 PM - Ghost Mode → Private research during lunch
1:00 PM - Normal MAC → Back to school work
3:00 PM - Ghost Mode → Personal browsing after school
4:00 PM - Normal MAC → Ready for next school day
```

---

## Troubleshooting

### Common Issues

#### Tor Not Starting
```bash
# Check if Tor is installed
sudo systemctl status tor

# Start Tor manually
sudo systemctl start tor

# Check port 9050
telnet 127.0.0.1 9050
```

#### MAC Address Change Fails
- Ensure you have proper sudo permissions
- Check if network interface name is correct
- Verify macchanger is installed

#### SSH Connection Issues
**Password Authentication Failed:**
- Server may require SSH keys only
- Use "SSH Key" or "Auto" authentication method

**Key Authentication:**
1. Generate SSH key pair in the application
2. Copy public key to server: `ssh-copy-id user@host`
3. Use "SSH Key" authentication method

#### VPN Connection Problems
- Verify OpenVPN config file path is correct
- Check internet connection before connecting
- Ensure you have valid VPN credentials

### Emergency Recovery

#### Reset Everything:
1. Deactivate Ghost Mode
2. Stop all services manually
3. Reset MAC address
4. Restart application

#### Network Reset:
```bash
sudo systemctl restart networking
sudo dhclient -r
sudo dhclient
```

---

## ⚠️ Legal Disclaimer

### Important Notice
**Ghost Protocol is designed for:**
- Privacy protection and security research
- Educational purposes and learning
- Legal anonymity requirements
- Bypassing unreasonable censorship

### Prohibited Uses
❌ **Illegal activities** of any kind
❌ **Network attacks** or unauthorized access
❌ **Copyright infringement**
❌ **Bypassing legitimate security measures**

### School Usage Policy
- Only use during appropriate times (breaks, free periods)
- Respect school network policies
- Don't interfere with educational activities
- Be prepared to explain legitimate educational uses

### Responsibility
Users are solely responsible for:
- Compliance with local laws and regulations
- Adherence to institutional policies
- Ethical use of anonymity tools
- Consequences of misuse

---

## Support

### Getting Help
1. **Check Tutorial**: Use the built-in tutorial
2. **System Console**: Review error messages and logs
3. **Status Indicators**: Monitor service states
4. **Test Functions**: Verify individual components

### Common School Scenarios

#### "I need to research blocked educational content"
1. Activate Ghost Mode
2. Use Tor routing to access resources
3. Deactivate when done
4. Reset to school MAC

#### "I want private messaging during breaks"
1. Activate Ghost Mode
2. Use encrypted services
3. Clean system before returning to class
4. Reset MAC for school WiFi

#### "IT department monitors computer usage"
1. Always use Cleaner after sessions
2. Ghost Mode hides specific activities
3. Regular MAC reset maintains WiFi access

---

## Update Information

### Version 2.0 - Enhanced
- **Added**: SSH client with multiple authentication methods
- **Added**: MAC address management for school WiFi
- **Enhanced**: User interface and visual feedback
- **Improved**: Error handling and diagnostics
- **Expanded**: Documentation and tutorials

### Future Features
- [ ] Wireless network analysis
- [ ] Advanced traffic obfuscation
- [ ] Cross-platform support
- [ ] Mobile companion application

---

## Contact & Support

For issues, questions, or suggestions:
1. Check the built-in tutorial first
2. Review system console for error messages
3. Ensure all dependencies are installed
4. Verify network interface configuration

---

**Remember**: With great power comes great responsibility. Use Ghost Protocol ethically and legally!

---

*Ghost Protocol v2.0 - Your digital invisibility cloak for the modern age*

# also please request a pull request to help me on this, like the vpn part, also in other things you think we can add.
