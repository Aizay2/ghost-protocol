#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import time
import json
import socket
import requests
import re
import paramiko
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import webbrowser
import random

class AdvancedAnonymitySuite:
    def __init__(self, root):
        self.root = root
        self.root.title("Ghost Protocol v2.0 - Enhanced")
        self.root.geometry("1000x800")
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(True, True)
        
        # Configuration
        self.config_file = os.path.expanduser("~/.ghostprotocol.json")
        self.vpn_active = False
        self.tor_active = False
        self.killswitch_active = False
        self.cleaning_active = False
        self.ssh_active = False
        self.ghost_mode_active = False
        
        # MAC Address Management
        self.original_mac = None
        self.current_mac = None
        self.mac_changed = False
        
        # Load config
        self.load_config()
        
        # Network interface detection
        self.network_interface = self.detect_network_interface()
        
        # Get original MAC address
        self.get_original_mac()
        
        # Style configuration
        self.setup_styles()
        
        # Main UI
        self.setup_ui()
        
        # Start monitoring
        self.start_monitoring()
        
        # Check requirements
        self.check_requirements()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles
        self.style.configure('.', background='#0a0a0a', foreground='#00ff00')
        self.style.configure('TFrame', background='#0a0a0a')
        self.style.configure('TLabel', background='#0a0a0a', foreground='#00ff00', 
                          font=('Courier', 10))
        self.style.configure('TButton', background='#111', foreground='#00ff00', 
                           font=('Courier', 10), borderwidth=1, relief='raised')
        self.style.map('TButton', 
                      background=[('active', '#222'), ('pressed', '#000')],
                      foreground=[('active', '#00ff00'), ('pressed', '#00aa00')])
        self.style.configure('Red.TButton', foreground='#ff0000')
        self.style.configure('Green.TButton', foreground='#00ff00')
        self.style.configure('TEntry', fieldbackground='#111', foreground='#00ff00', 
                           insertcolor='#00ff00')
        self.style.configure('TCombobox', fieldbackground='#111', foreground='#00ff00')
        self.style.configure('Horizontal.TProgressbar', background='#00ff00', 
                           troughcolor='#0a0a0a')
        self.style.configure('TNotebook', background='#0a0a0a', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#111', foreground='#00ff00', 
                           padding=[10, 5], font=('Courier', 9))
        self.style.map('TNotebook.Tab', 
                      background=[('selected', '#0a0a0a')],
                      foreground=[('selected', '#00ff00')])

    def setup_ui(self):
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=X, pady=(0, 10))
        
        # Logo
        self.logo_label = Label(self.header_frame, text="GHOST PROTOCOL v2.0", 
                              font=('Courier', 18, 'bold'), fg='#00ff00', bg='#0a0a0a')
        self.logo_label.pack(side=LEFT)
        
        # Status label
        self.status_label = Label(self.header_frame, text="Initializing...", 
                                font=('Courier', 10), fg='#00ff00', bg='#0a0a0a', anchor='e')
        self.status_label.pack(side=RIGHT, fill=X, expand=True)
        
        # Tab control
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_tor_tab()
        self.create_vpn_tab()
        self.create_cleaner_tab()
        self.create_network_tab()
        self.create_mac_tab()
        self.create_settings_tab()
        
        # Console
        self.console_frame = ttk.LabelFrame(self.main_frame, text="System Console")
        self.console_frame.pack(fill=BOTH, expand=False, padx=5, pady=5)
        
        self.console = scrolledtext.ScrolledText(self.console_frame, height=8, bg='#111', 
                                              fg='#00ff00', insertbackground='#00ff00', 
                                              font=('Courier', 9))
        self.console.pack(fill=BOTH, expand=True)
        self.console.insert(END, "Ghost Protocol initialized\n")
        
        # Interactive welcome message
        self.show_welcome_message()
        
        # Start animation
        self.animate_logo()

    def show_welcome_message(self):
        """Show interactive welcome message"""
        welcome_msg = """
╔════════════════════════════════════════════════════════════════╗
║                   GHOST PROTOCOL v2.0 - Enhanced              ║
║                                                                ║
║  Welcome to your advanced anonymity suite!                    ║
║  Features:                                                    ║
║   • Tor Routing          • VPN Integration                    ║
║   • MAC Address Spoofing • System Cleaning                    ║
║   • SSH Client           • Network Tools                      ║
║   • Kill Switch          • Interactive Console                ║
║                                                                ║
║  Use responsibly and ethically!                               ║
╚════════════════════════════════════════════════════════════════╝
"""
        self.console.insert(END, welcome_msg)
        self.console.see(END)

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.vpn_config_path = config.get('vpn_config')
        except Exception as e:
            self.log(f"Error loading config: {str(e)}", "error")

    def save_config(self):
        try:
            config = {
                'vpn_config': self.vpn_config.get()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            self.log(f"Error saving config: {str(e)}", "error")

    def detect_network_interface(self):
        try:
            result = subprocess.run("ip route | grep default | awk '{print $5}'", 
                                  shell=True, check=True, stdout=subprocess.PIPE)
            return result.stdout.decode().strip()
        except:
            return "eth0"

    def get_original_mac(self):
        """Get the original MAC address of the network interface"""
        try:
            result = subprocess.run(f"cat /sys/class/net/{self.network_interface}/address", 
                                  shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                self.original_mac = result.stdout.strip().upper()
                self.current_mac = self.original_mac
            else:
                # Alternative method using ip command
                result = subprocess.run(f"ip link show {self.network_interface}", 
                                      shell=True, capture_output=True, text=True)
                match = re.search(r'link/ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', result.stdout)
                if match:
                    self.original_mac = match.group(1).upper()
                    self.current_mac = self.original_mac
        except Exception as e:
            self.log(f"Error getting original MAC: {str(e)}", "error")
            self.original_mac = "Unknown"
            self.current_mac = "Unknown"

    def check_requirements(self):
        required = {
            'tor': 'tor --version',
            'proxychains': 'proxychains4 --version',
            'openvpn': 'openvpn --version',
            'bleachbit': 'bleachbit --version',
            'iptables': 'iptables --version',
            'macchanger': 'macchanger --version'
        }
        
        missing = []
        
        for tool, cmd in required.items():
            try:
                subprocess.run(['which', tool], check=True, 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.log(f"{tool} is installed")
            except:
                missing.append(tool)
                self.log(f"{tool} is NOT installed", "warning")
        
        if missing:
            self.log(f"Missing tools: {', '.join(missing)}", "warning")
            answer = messagebox.askyesno("Missing Tools", 
                                        f"The following tools are missing: {', '.join(missing)}\n"
                                        "Would you like to install them now?")
            if answer:
                self.install_tools(missing)
        else:
            self.log("All required tools are installed", "success")
            self.update_status("Ready")
            self.start_btn.config(state=NORMAL)

    def install_tools(self, tools):
        install_cmds = {
            'tor': 'sudo apt-get install tor -y',
            'proxychains': 'sudo apt-get install proxychains4 -y',
            'openvpn': 'sudo apt-get install openvpn -y',
            'bleachbit': 'sudo apt-get install bleachbit -y',
            'iptables': 'sudo apt-get install iptables -y',
            'macchanger': 'sudo apt-get install macchanger -y'
        }
        
        progress_window = Toplevel(self.root)
        progress_window.title("Installing Tools")
        progress_window.geometry("500x300")
        progress_window.configure(bg='#0a0a0a')
        progress_window.grab_set()
        
        ttk.Label(progress_window, text="Installing missing tools...").pack(pady=10)
        
        progress = ttk.Progressbar(progress_window, orient=HORIZONTAL, length=400, 
                                 mode='determinate', maximum=len(tools))
        progress.pack(pady=10)
        
        log_text = scrolledtext.ScrolledText(progress_window, height=10, bg='#111', 
                                          fg='#00ff00', font=('Courier', 8))
        log_text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        def install_thread():
            for i, tool in enumerate(tools, 1):
                log_text.insert(END, f"Installing {tool}...\n")
                log_text.see(END)
                progress['value'] = i
                progress_window.update()
                
                try:
                    cmd = install_cmds.get(tool, '')
                    if cmd:
                        result = subprocess.run(cmd, shell=True, check=True, 
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              timeout=300)
                        log_text.insert(END, f"Successfully installed {tool}\n")
                        
                        # Verify installation
                        verify = subprocess.run(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if verify.returncode != 0:
                            log_text.insert(END, f"Warning: {tool} still not found after installation!\n")
                    else:
                        log_text.insert(END, f"No install command for {tool}\n", "error")
                except subprocess.TimeoutExpired:
                    log_text.insert(END, f"Timeout installing {tool}\n", "error")
                except subprocess.CalledProcessError as e:
                    log_text.insert(END, f"Failed to install {tool}: {e.stderr.decode()}\n", "error")
                
                log_text.see(END)
                progress_window.update()
            
            progress_window.after(1000, progress_window.destroy)
            self.log("Tool installation completed", "success")
            self.update_status("Ready")
            self.check_requirements()
        
        threading.Thread(target=install_thread, daemon=True).start()

    def create_dashboard_tab(self):
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text='Dashboard')
        
        # Status indicators
        status_frame = ttk.LabelFrame(self.dashboard_tab, text="Status Indicators")
        status_frame.pack(fill=X, padx=5, pady=5)
        
        # Status grid
        self.tor_status = self.create_status_row(status_frame, "Tor Routing:", "Inactive", 0)
        self.vpn_status = self.create_status_row(status_frame, "VPN Tunnel:", "Inactive", 1)
        self.killswitch_status = self.create_status_row(status_frame, "Kill Switch:", "Inactive", 2)
        self.clean_status = self.create_status_row(status_frame, "System Clean:", "Dirty", 3)
        self.mac_status = self.create_status_row(status_frame, "MAC Address:", "Original", 4)
        
        # Quick actions
        action_frame = ttk.LabelFrame(self.dashboard_tab, text="Quick Actions")
        action_frame.pack(fill=X, padx=5, pady=5)
        
        btn_frame = ttk.Frame(action_frame)
        btn_frame.pack(fill=X, pady=5)
        
        self.start_btn = ttk.Button(btn_frame, text="🚀 ACTIVATE GHOST MODE", 
                                  command=self.activate_ghost_mode, style='Green.TButton')
        self.start_btn.pack(side=LEFT, fill=X, expand=True, padx=2)
        
        self.stop_btn = ttk.Button(btn_frame, text="🛑 DEACTIVATE", 
                                 command=self.deactivate_ghost_mode, style='Red.TButton', state=DISABLED)
        self.stop_btn.pack(side=LEFT, fill=X, expand=True, padx=2)
        
        ttk.Button(btn_frame, text="❓ Quick Tutorial", command=self.show_tutorial).pack(side=LEFT, padx=2)
        
        # System info
        info_frame = ttk.LabelFrame(self.dashboard_tab, text="Network Information")
        info_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.ip_label = ttk.Label(info_frame, text="Public IP: Checking...")
        self.ip_label.pack(anchor=W)
        
        self.local_ip_label = ttk.Label(info_frame, text="Local IP: Checking...")
        self.local_ip_label.pack(anchor=W)
        
        self.interface_label = ttk.Label(info_frame, text=f"Interface: {self.network_interface}")
        self.interface_label.pack(anchor=W)
        
        self.mac_label = ttk.Label(info_frame, text=f"MAC Address: {self.current_mac}")
        self.mac_label.pack(anchor=W)
        
        # Test buttons
        test_frame = ttk.Frame(info_frame)
        test_frame.pack(fill=X, pady=5)
        
        ttk.Button(test_frame, text="🔍 Test Tor", command=self.test_tor).pack(side=LEFT, padx=2)
        ttk.Button(test_frame, text="🔍 Test VPN", command=self.test_vpn).pack(side=LEFT, padx=2)
        ttk.Button(test_frame, text="🔍 Test DNS Leak", command=self.test_dns_leak).pack(side=LEFT, padx=2)
        ttk.Button(test_frame, text="🔄 Refresh Info", command=self.update_network_info).pack(side=LEFT, padx=2)

    def create_tor_tab(self):
        self.tor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.tor_tab, text='Tor Routing')
        
        # Tor control frame
        control_frame = ttk.LabelFrame(self.tor_tab, text="Tor Control")
        control_frame.pack(fill=X, padx=5, pady=5)
        
        # Tor status
        ttk.Label(control_frame, text="Tor Status:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.tor_status_label = ttk.Label(control_frame, text="Checking...")
        self.tor_status_label.grid(row=0, column=1, sticky=W, padx=5, pady=2)
        
        # Tor actions
        action_frame = ttk.Frame(control_frame)
        action_frame.grid(row=1, column=0, columnspan=2, sticky=EW, pady=5)
        
        self.start_tor_btn = ttk.Button(action_frame, text="Start Tor", command=self.start_tor)
        self.start_tor_btn.pack(side=LEFT, padx=2)
        
        self.stop_tor_btn = ttk.Button(action_frame, text="Stop Tor", command=self.stop_tor, state=DISABLED)
        self.stop_tor_btn.pack(side=LEFT, padx=2)
        
        ttk.Button(action_frame, text="Test Tor", command=self.test_tor).pack(side=LEFT, padx=2)
        
        # Tor config
        config_frame = ttk.LabelFrame(self.tor_tab, text="Tor Configuration")
        config_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Exit Nodes:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.exit_nodes = ttk.Entry(config_frame)
        self.exit_nodes.grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        self.exit_nodes.insert(0, "{us},{gb},{de}")
        
        ttk.Label(config_frame, text="Strict Nodes:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.strict_nodes = ttk.Combobox(config_frame, values=["0", "1"])
        self.strict_nodes.grid(row=1, column=1, sticky=W, padx=5, pady=2)
        self.strict_nodes.current(1)
        
        # Tor log
        log_frame = ttk.LabelFrame(config_frame, text="Tor Log")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=EW, pady=5)
        
        self.tor_log = scrolledtext.ScrolledText(log_frame, height=8, bg='#111', fg='#00ff00', 
                                               insertbackground='#00ff00', font=('Courier', 8))
        self.tor_log.pack(fill=BOTH, expand=True)
        
        # Check Tor status
        self.check_tor_status()

    def create_vpn_tab(self):
        self.vpn_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.vpn_tab, text='VPN')
        
        # VPN control frame
        control_frame = ttk.LabelFrame(self.vpn_tab, text="VPN Control")
        control_frame.pack(fill=X, padx=5, pady=5)
        
        # VPN config selection
        ttk.Label(control_frame, text="VPN Config:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        
        config_frame = ttk.Frame(control_frame)
        config_frame.grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        
        self.vpn_config = ttk.Entry(config_frame)
        self.vpn_config.pack(side=LEFT, fill=X, expand=True)
        
        if hasattr(self, 'vpn_config_path') and self.vpn_config_path:
            self.vpn_config.insert(0, self.vpn_config_path)
        
        ttk.Button(config_frame, text="Browse", command=self.browse_vpn_config).pack(side=LEFT, padx=5)
        
        # VPN status
        ttk.Label(control_frame, text="VPN Status:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.vpn_status_label = ttk.Label(control_frame, text="Checking...")
        self.vpn_status_label.grid(row=1, column=1, sticky=W, padx=5, pady=2)
        
        # VPN actions
        action_frame = ttk.Frame(control_frame)
        action_frame.grid(row=2, column=0, columnspan=2, sticky=EW, pady=5)
        
        self.connect_vpn_btn = ttk.Button(action_frame, text="Connect VPN", command=self.connect_vpn)
        self.connect_vpn_btn.pack(side=LEFT, padx=2)
        
        self.disconnect_vpn_btn = ttk.Button(action_frame, text="Disconnect VPN", command=self.disconnect_vpn, state=DISABLED)
        self.disconnect_vpn_btn.pack(side=LEFT, padx=2)
        
        ttk.Button(action_frame, text="Test VPN", command=self.test_vpn).pack(side=LEFT, padx=2)
        
        # Kill switch
        killswitch_frame = ttk.Frame(control_frame)
        killswitch_frame.grid(row=3, column=0, columnspan=2, sticky=EW, pady=5)
        
        self.killswitch_btn = ttk.Button(killswitch_frame, text="Enable Kill Switch", 
                                       command=self.toggle_killswitch)
        self.killswitch_btn.pack(side=LEFT, padx=2)
        
        # VPN log
        log_frame = ttk.LabelFrame(self.vpn_tab, text="VPN Log")
        log_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.vpn_log = scrolledtext.ScrolledText(log_frame, height=8, bg='#111', fg='#00ff00', 
                                              insertbackground='#00ff00', font=('Courier', 8))
        self.vpn_log.pack(fill=BOTH, expand=True)
        
        # Check VPN status
        self.check_vpn_status()

    def create_cleaner_tab(self):
        self.cleaner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.cleaner_tab, text='Cleaner')
        
        # Cleaner control frame
        control_frame = ttk.LabelFrame(self.cleaner_tab, text="System Cleaner")
        control_frame.pack(fill=X, padx=5, pady=5)
        
        # Clean options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=X, pady=5)
        
        self.clean_browser_var = IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Browser Data", variable=self.clean_browser_var).pack(side=LEFT, padx=5)
        
        self.clean_temp_var = IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Temp Files", variable=self.clean_temp_var).pack(side=LEFT, padx=5)
        
        self.clean_logs_var = IntVar(value=1)
        ttk.Checkbutton(options_frame, text="System Logs", variable=self.clean_logs_var).pack(side=LEFT, padx=5)
        
        self.clean_dns_var = IntVar(value=1)
        ttk.Checkbutton(options_frame, text="DNS Cache", variable=self.clean_dns_var).pack(side=LEFT, padx=5)
        
        # Clean actions
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=X, pady=5)
        
        ttk.Button(action_frame, text="Clean Now", command=self.clean_system).pack(side=LEFT, padx=2)
        ttk.Button(action_frame, text="Schedule Clean", command=self.schedule_clean).pack(side=LEFT, padx=2)
        
        # Cleaner log
        log_frame = ttk.LabelFrame(self.cleaner_tab, text="Cleaner Log")
        log_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.cleaner_log = scrolledtext.ScrolledText(log_frame, height=8, bg='#111', fg='#00ff00', 
                                                   insertbackground='#00ff00', font=('Courier', 8))
        self.cleaner_log.pack(fill=BOTH, expand=True)

    def create_network_tab(self):
        self.network_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.network_tab, text='Network Tools')
        
        # Network tools frame
        tools_frame = ttk.LabelFrame(self.network_tab, text="Network Utilities")
        tools_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # SSH Connection Frame
        ssh_frame = ttk.LabelFrame(tools_frame, text="SSH Connection")
        ssh_frame.pack(fill=X, padx=5, pady=5)
        
        # SSH Connection Form
        ttk.Label(ssh_frame, text="Host:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.ssh_host = ttk.Entry(ssh_frame)
        self.ssh_host.grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        
        ttk.Label(ssh_frame, text="Username:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.ssh_user = ttk.Entry(ssh_frame)
        self.ssh_user.grid(row=1, column=1, sticky=EW, padx=5, pady=2)
        
        ttk.Label(ssh_frame, text="Port:").grid(row=2, column=0, sticky=W, padx=5, pady=2)
        self.ssh_port = ttk.Entry(ssh_frame)
        self.ssh_port.insert(0, "22")
        self.ssh_port.grid(row=2, column=1, sticky=W, padx=5, pady=2)
        
        # SSH Authentication Options
        auth_frame = ttk.Frame(ssh_frame)
        auth_frame.grid(row=3, column=0, columnspan=2, sticky=EW, pady=5)

        self.auth_method = StringVar(value="password")
        ttk.Radiobutton(auth_frame, text="Password", variable=self.auth_method, 
                        value="password").pack(side=LEFT, padx=5)
        ttk.Radiobutton(auth_frame, text="SSH Key", variable=self.auth_method, 
                        value="key").pack(side=LEFT, padx=5)
        ttk.Radiobutton(auth_frame, text="Auto (Try Both)", variable=self.auth_method, 
                        value="auto").pack(side=LEFT, padx=5)

        # SSH Key file selection
        key_frame = ttk.Frame(ssh_frame)
        key_frame.grid(row=4, column=0, columnspan=2, sticky=EW, pady=2)

        ttk.Label(key_frame, text="SSH Key File:").pack(side=LEFT, padx=5)
        self.ssh_key_file = ttk.Entry(key_frame, width=30)
        self.ssh_key_file.pack(side=LEFT, fill=X, expand=True, padx=5)
        ttk.Button(key_frame, text="Browse", command=self.browse_ssh_key).pack(side=LEFT, padx=5)
        
        # SSH Buttons
        btn_frame = ttk.Frame(ssh_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, sticky=EW, pady=5)
        
        self.ssh_connect_btn = ttk.Button(btn_frame, text="Connect", command=self.ssh_connect)
        self.ssh_connect_btn.pack(side=LEFT, padx=2)
        
        self.ssh_disconnect_btn = ttk.Button(btn_frame, text="Disconnect", 
                                        state=DISABLED, command=self.ssh_disconnect)
        self.ssh_disconnect_btn.pack(side=LEFT, padx=2)
        
        ttk.Button(btn_frame, text="🔑 Generate Key", 
                  command=self.generate_ssh_key).pack(side=LEFT, padx=2)
        
        # SSH Terminal Emulator
        self.ssh_terminal = scrolledtext.ScrolledText(tools_frame, height=15, bg='black', 
                                                    fg='white', insertbackground='white',
                                                    font=('Courier', 10))
        self.ssh_terminal.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.ssh_terminal.bind('<Return>', self.ssh_send_command)
        
        # Port scanner
        port_frame = ttk.LabelFrame(tools_frame, text="Port Scanner")
        port_frame.pack(fill=X, padx=5, pady=5)
        
        ttk.Label(port_frame, text="Target:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        
        scan_frame = ttk.Frame(port_frame)
        scan_frame.grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        
        self.scan_target = ttk.Entry(scan_frame)
        self.scan_target.pack(side=LEFT, fill=X, expand=True)
        self.scan_target.insert(0, "localhost")
        
        ttk.Button(scan_frame, text="Scan", command=self.scan_ports).pack(side=LEFT, padx=5)
        
        self.scan_results = scrolledtext.ScrolledText(port_frame, height=6, bg='#111', fg='#00ff00', 
                                                    insertbackground='#00ff00', font=('Courier', 8))
        self.scan_results.grid(row=1, column=0, columnspan=2, sticky=EW, padx=5, pady=5)

    def create_mac_tab(self):
        """Create MAC address changer tab"""
        self.mac_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.mac_tab, text='MAC Changer')
        
        # MAC Control Frame
        control_frame = ttk.LabelFrame(self.mac_tab, text="MAC Address Control")
        control_frame.pack(fill=X, padx=5, pady=5)
        
        # Current MAC info
        info_frame = ttk.Frame(control_frame)
        info_frame.pack(fill=X, pady=5)
        
        ttk.Label(info_frame, text="Original MAC:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.original_mac_label = ttk.Label(info_frame, text=self.original_mac or "Unknown")
        self.original_mac_label.grid(row=0, column=1, sticky=W, padx=5, pady=2)
        
        ttk.Label(info_frame, text="Current MAC:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.current_mac_label = ttk.Label(info_frame, text=self.current_mac or "Unknown", 
                                         font=('Courier', 10, 'bold'))
        self.current_mac_label.grid(row=1, column=1, sticky=W, padx=5, pady=2)
        
        ttk.Label(info_frame, text="Interface:").grid(row=2, column=0, sticky=W, padx=5, pady=2)
        self.mac_interface_label = ttk.Label(info_frame, text=self.network_interface)
        self.mac_interface_label.grid(row=2, column=1, sticky=W, padx=5, pady=2)
        
        # MAC Change Options
        options_frame = ttk.LabelFrame(control_frame, text="MAC Change Options")
        options_frame.pack(fill=X, pady=5)
        
        # Random MAC generation
        ttk.Button(options_frame, text="🎲 Generate Random MAC", 
                  command=self.generate_random_mac).pack(side=LEFT, padx=2, pady=2)
        
        # Custom MAC entry
        custom_frame = ttk.Frame(options_frame)
        custom_frame.pack(fill=X, pady=5)
        
        ttk.Label(custom_frame, text="Custom MAC:").pack(side=LEFT, padx=5)
        self.custom_mac_entry = ttk.Entry(custom_frame, width=17)
        self.custom_mac_entry.pack(side=LEFT, padx=5)
        self.custom_mac_entry.insert(0, "XX:XX:XX:XX:XX:XX")
        
        ttk.Button(custom_frame, text="Use Custom", 
                  command=self.use_custom_mac).pack(side=LEFT, padx=5)
        
        # MAC Actions
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=X, pady=10)
        
        self.change_mac_btn = ttk.Button(action_frame, text="🔀 Change MAC Address", 
                                       command=self.change_mac_address, style='Green.TButton')
        self.change_mac_btn.pack(side=LEFT, padx=2)
        
        self.reset_mac_btn = ttk.Button(action_frame, text="🔄 Reset to Original", 
                                      command=self.reset_mac_address, style='Red.TButton')
        self.reset_mac_btn.pack(side=LEFT, padx=2)
        
        # MAC Vendor database info
        vendor_frame = ttk.LabelFrame(control_frame, text="MAC Vendor Information")
        vendor_frame.pack(fill=X, pady=5)
        
        self.vendor_label = ttk.Label(vendor_frame, text="Vendor: Unknown")
        self.vendor_label.pack(anchor=W, padx=5, pady=2)
        
        # MAC Log
        log_frame = ttk.LabelFrame(self.mac_tab, text="MAC Change Log")
        log_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        self.mac_log = scrolledtext.ScrolledText(log_frame, height=10, bg='#111', fg='#00ff00', 
                                               insertbackground='#00ff00', font=('Courier', 8))
        self.mac_log.pack(fill=BOTH, expand=True)
        
        # Initialize MAC info
        self.update_mac_info()

    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text='Settings')
        
        # Settings frame
        settings_frame = ttk.LabelFrame(self.settings_tab, text="Configuration")
        settings_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # Network interface
        ttk.Label(settings_frame, text="Network Interface:").grid(row=0, column=0, sticky=W, padx=5, pady=2)
        self.interface_var = StringVar(value=self.network_interface)
        ttk.Entry(settings_frame, textvariable=self.interface_var).grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        
        # Auto-start
        ttk.Label(settings_frame, text="Auto-Start:").grid(row=1, column=0, sticky=W, padx=5, pady=2)
        self.autostart_var = IntVar(value=0)
        ttk.Checkbutton(settings_frame, variable=self.autostart_var).grid(row=1, column=1, sticky=W, padx=5, pady=2)
        
        # Save button
        ttk.Button(settings_frame, text="Save Settings", command=self.save_settings).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Logging level
        ttk.Label(settings_frame, text="Logging Level:").grid(row=3, column=0, sticky=W, padx=5, pady=2)
        self.log_level = ttk.Combobox(settings_frame, values=["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level.grid(row=3, column=1, sticky=W, padx=5, pady=2)
        self.log_level.current(1)

    def create_status_row(self, parent, label, value, row):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky=EW, padx=5, pady=2)
        
        ttk.Label(frame, text=label, width=15, anchor=W).pack(side=LEFT)
        status = ttk.Label(frame, text=value, font=('Courier', 10, 'bold'))
        status.pack(side=LEFT)
        
        return status

    def generate_random_mac(self):
        """Generate a random MAC address"""
        # Generate random MAC (locally administered, unicast)
        mac = [0x02, 0x00, 0x00]  # Locally administered, unicast
        mac += [random.randint(0x00, 0xff) for _ in range(3)]
        random_mac = ':'.join(map(lambda x: f"{x:02x}", mac)).upper()
        self.custom_mac_entry.delete(0, END)
        self.custom_mac_entry.insert(0, random_mac)
        self.log(f"Generated random MAC: {random_mac}")

    def use_custom_mac(self):
        """Use the custom MAC address from entry field"""
        custom_mac = self.custom_mac_entry.get().strip()
        if self.validate_mac_address(custom_mac):
            self.log(f"Custom MAC address validated: {custom_mac}")
        else:
            messagebox.showerror("Invalid MAC", "Please enter a valid MAC address in format: XX:XX:XX:XX:XX:XX")

    def validate_mac_address(self, mac):
        """Validate MAC address format"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(pattern, mac) is not None

    def change_mac_address(self, new_mac=None):
        """Change MAC address"""
        if not new_mac:
            new_mac = self.custom_mac_entry.get().strip()
        
        if not self.validate_mac_address(new_mac):
            messagebox.showerror("Invalid MAC", "Please enter a valid MAC address")
            return False
        
        try:
            # Bring interface down
            subprocess.run(f"sudo ip link set {self.network_interface} down", 
                          shell=True, check=True)
            
            # Change MAC address
            subprocess.run(f"sudo ip link set {self.network_interface} address {new_mac}", 
                          shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.network_interface} up", 
                          shell=True, check=True)
            
            # Wait for interface to come up
            time.sleep(2)
            
            # Update current MAC
            self.current_mac = new_mac.upper()
            self.mac_changed = True
            
            # Update UI
            self.update_mac_info()
            self.mac_status.config(text="Spoofed")
            
            self.log(f"MAC address changed to: {new_mac}", "success")
            messagebox.showinfo("Success", f"MAC address changed to:\n{new_mac}")
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to change MAC address: {str(e)}"
            self.log(error_msg, "error")
            messagebox.showerror("Error", error_msg)
            return False

    def reset_mac_address(self):
        """Reset MAC address to original"""
        if not self.original_mac or self.original_mac == "Unknown":
            messagebox.showerror("Error", "Original MAC address not available")
            return False
        
        try:
            # Bring interface down
            subprocess.run(f"sudo ip link set {self.network_interface} down", 
                          shell=True, check=True)
            
            # Reset MAC address
            subprocess.run(f"sudo ip link set {self.network_interface} address {self.original_mac}", 
                          shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.network_interface} up", 
                          shell=True, check=True)
            
            # Wait for interface to come up
            time.sleep(2)
            
            # Update current MAC
            self.current_mac = self.original_mac
            self.mac_changed = False
            
            # Update UI
            self.update_mac_info()
            self.mac_status.config(text="Original")
            
            self.log(f"MAC address reset to original: {self.original_mac}", "success")
            messagebox.showinfo("Success", f"MAC address reset to original:\n{self.original_mac}")
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to reset MAC address: {str(e)}"
            self.log(error_msg, "error")
            messagebox.showerror("Error", error_msg)
            return False

    def update_mac_info(self):
        """Update MAC information display"""
        if hasattr(self, 'current_mac_label'):
            self.current_mac_label.config(text=self.current_mac or "Unknown")
        if hasattr(self, 'original_mac_label'):
            self.original_mac_label.config(text=self.original_mac or "Unknown")
        if hasattr(self, 'mac_label'):
            self.mac_label.config(text=f"MAC Address: {self.current_mac or 'Unknown'}")

    def ssh_connect(self):
        """Enhanced SSH connection supporting both password and key authentication"""
        host = self.ssh_host.get().strip()
        user = self.ssh_user.get().strip()
        port = self.ssh_port.get().strip() or "22"
        auth_method = self.auth_method.get()
        
        if not host or not user:
            messagebox.showerror("Error", "Host and Username are required!")
            return
        
        try:
            # Create SSH client
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            def connect_thread():
                try:
                    self.ssh_terminal.insert(END, f"🔌 Connecting to {user}@{host}:{port}...\n")
                    self.ssh_terminal.see(END)
                    
                    # Determine authentication method
                    if auth_method == "password":
                        password = simpledialog.askstring("SSH Password", 
                                                        f"Enter password for {user}@{host}:", 
                                                        show='*', parent=self.root)
                        if password is None:
                            return
                        
                        self.ssh_client.connect(host, port=int(port), username=user, 
                                              password=password, timeout=10,
                                              look_for_keys=False, allow_agent=False)
                        
                    elif auth_method == "key":
                        key_file = self.ssh_key_file.get().strip()
                        if not key_file:
                            # Try default keys
                            self.ssh_client.connect(host, port=int(port), username=user,
                                                  look_for_keys=True, allow_agent=True,
                                                  timeout=10)
                        else:
                            # Use specific key file
                            key = paramiko.RSAKey.from_private_key_file(key_file)
                            self.ssh_client.connect(host, port=int(port), username=user,
                                                  pkey=key, timeout=10)
                    
                    else:  # auto - try both
                        password = simpledialog.askstring("SSH Authentication", 
                                                        f"Enter password for {user}@{host} (or leave empty for key auth):", 
                                                        show='*', parent=self.root)
                        if password:
                            self.ssh_client.connect(host, port=int(port), username=user,
                                                  password=password, timeout=10,
                                                  look_for_keys=False, allow_agent=False)
                        else:
                            key_file = self.ssh_key_file.get().strip()
                            if key_file:
                                key = paramiko.RSAKey.from_private_key_file(key_file)
                                self.ssh_client.connect(host, port=int(port), username=user,
                                                      pkey=key, timeout=10)
                            else:
                                self.ssh_client.connect(host, port=int(port), username=user,
                                                      look_for_keys=True, allow_agent=True,
                                                      timeout=10)
                    
                    # Start shell session
                    self.ssh_shell = self.ssh_client.invoke_shell()
                    self.ssh_shell.settimeout(0.1)
                    
                    # Update UI
                    self.root.after(0, lambda: [
                        self.ssh_connect_btn.config(state=DISABLED),
                        self.ssh_disconnect_btn.config(state=NORMAL),
                        self.ssh_terminal.insert(END, "✅ SSH Connection Established!\n"),
                        self.ssh_terminal.insert(END, f"{user}@{host}:~$ "),
                        self.ssh_terminal.see(END)
                    ])
                    
                    self.ssh_active = True
                    self.log(f"SSH connected to {user}@{host}:{port} using {auth_method}", "success")
                    
                    # Start thread to receive output
                    threading.Thread(target=self.ssh_receive_output, daemon=True).start()
                    
                except Exception as e:
                    error_msg = f"❌ Connection failed: {str(e)}\n"
                    self.root.after(0, lambda: [
                        self.ssh_terminal.insert(END, error_msg),
                        self.ssh_terminal.see(END),
                        self.log(f"SSH connection failed: {str(e)}", "error")
                    ])
            
            threading.Thread(target=connect_thread, daemon=True).start()
            
        except Exception as e:
            error_msg = f"❌ SSH Error: {str(e)}\n"
            self.ssh_terminal.insert(END, error_msg)
            self.ssh_terminal.see(END)
            self.log(f"SSH error: {str(e)}", "error")

    def generate_ssh_key(self):
        """Generate a new SSH key pair"""
        key_type = simpledialog.askstring("SSH Key Type", 
                                        "Enter key type (ed25519 or rsa):", 
                                        initialvalue="ed25519")
        if not key_type:
            return
        
        key_path = filedialog.asksaveasfilename(
            title="Save SSH Key As",
            defaultextension=".pem",
            filetypes=[("SSH Keys", "*.pem"), ("All files", "*.*")]
        )
        
        if key_path:
            try:
                if key_type.lower() == 'ed25519':
                    cmd = f'ssh-keygen -t ed25519 -f "{key_path}" -N ""'
                else:
                    cmd = f'ssh-keygen -t rsa -b 4096 -f "{key_path}" -N ""'
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log(f"SSH key generated: {key_path}", "success")
                    self.ssh_key_file.delete(0, END)
                    self.ssh_key_file.insert(0, key_path)
                    messagebox.showinfo("Success", f"SSH key generated at:\n{key_path}")
                else:
                    self.log(f"Failed to generate SSH key: {result.stderr}", "error")
            except Exception as e:
                self.log(f"Error generating SSH key: {str(e)}", "error")

    def browse_ssh_key(self):
        """Browse for SSH private key file"""
        filename = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("SSH Keys", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.ssh_key_file.delete(0, END)
            self.ssh_key_file.insert(0, filename)

    def ssh_disconnect(self):
        """Close SSH connection properly"""
        self.ssh_active = False
        if hasattr(self, 'ssh_client'):
            try:
                self.ssh_client.close()
                self.log("SSH connection closed", "success")
            except Exception as e:
                self.log(f"Error closing SSH: {str(e)}", "error")
        self.ssh_connect_btn.config(state=NORMAL)
        self.ssh_disconnect_btn.config(state=DISABLED)

    def ssh_send_command(self, event=None):
        """Send command through SSH with better handling"""
        if not hasattr(self, 'ssh_shell') or self.ssh_shell.closed:
            return
        
        # Get the current input line
        self.ssh_terminal.mark_set("insert", "end-1c")
        input_line = self.ssh_terminal.get("end-2c linestart", "end-1c")
        
        # Extract command (after the prompt)
        if "$ " in input_line:
            command = input_line.split("$ ")[-1]
        else:
            command = input_line.strip()
        
        if command.strip():
            try:
                self.ssh_shell.send(command + "\n")
                self.ssh_terminal.insert(END, "\n")
                self.ssh_terminal.see(END)
            except Exception as e:
                self.ssh_terminal.insert(END, f"\n❌ Error sending command: {str(e)}\n$ ")
                self.ssh_terminal.see(END)
        
        return "break"  # Prevent default Return behavior

    def ssh_receive_output(self):
        """Receive output from SSH shell with better handling"""
        while hasattr(self, 'ssh_shell') and not self.ssh_shell.closed and self.ssh_active:
            try:
                if self.ssh_shell.recv_ready():
                    output = self.ssh_shell.recv(4096).decode('utf-8', 'replace')
                    self.root.after(0, lambda: [
                        self.ssh_terminal.insert(END, output),
                        self.ssh_terminal.see(END)
                    ])
                time.sleep(0.1)
            except socket.timeout:
                continue
            except Exception:
                break
        
        # Connection closed
        if hasattr(self, 'ssh_shell') and self.ssh_shell.closed:
            self.root.after(0, lambda: [
                self.ssh_terminal.insert(END, "\n🔌 SSH Connection Closed\n"),
                self.ssh_terminal.see(END),
                self.ssh_connect_btn.config(state=NORMAL),
                self.ssh_disconnect_btn.config(state=DISABLED)
            ])
            self.ssh_active = False

    def show_tutorial(self):
        """Show interactive tutorial"""
        tutorial_text = """
QUICK TUTORIAL - Ghost Protocol v2.0

1. 🚀 ACTIVATE GHOST MODE: 
   - Changes MAC address (for school WiFi)
   - Starts Tor routing
   - Connects VPN (if configured)
   - Enables kill switch
   - Cleans system traces

2. 🛑 DEACTIVATE: 
   - Resets MAC to original
   - Stops all services
   - Restores normal network

3. 🔀 MAC Changer Tab:
   - Change MAC for school WiFi
   - Reset to registered MAC when done
   - Generate random MACs

4. 🔌 SSH Tab:
   - Connect to remote servers
   - Full terminal emulation
   - Password/Key authentication

5. ⚙️ Settings:
   - Configure network interface
   - Set auto-start options

Remember: Always reset your MAC address to the registered one when you need to use school WiFi!
"""
        tutorial_window = Toplevel(self.root)
        tutorial_window.title("Ghost Protocol Tutorial")
        tutorial_window.geometry("600x500")
        tutorial_window.configure(bg='#0a0a0a')
        
        text_widget = scrolledtext.ScrolledText(tutorial_window, bg='#111', fg='#00ff00',
                                              font=('Courier', 10), wrap=WORD)
        text_widget.pack(fill=BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(END, tutorial_text)
        text_widget.config(state=DISABLED)

    def activate_ghost_mode(self):
        """Activate full anonymity mode with MAC changing"""
        self.log("🚀 Activating Ghost Mode...")
        self.update_status("Activating Ghost Mode")
        
        # Disable start button, enable stop button
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        
        # Show progress dialog
        progress_window = self.create_progress_window("Activating Ghost Mode")
        
        # Start processes in sequence
        threading.Thread(target=self._activate_ghost_processes, args=(progress_window,), daemon=True).start()

    def _activate_ghost_processes(self, progress_window):
        try:
            steps = [
                ("Changing MAC Address...", self._change_mac_for_ghost),
                ("Starting Tor Service...", self.start_tor),
                ("Connecting VPN...", self._connect_vpn_for_ghost),
                ("Enabling Kill Switch...", self._enable_killswitch_for_ghost),
                ("Cleaning System Traces...", self.clean_system)
            ]
            
            for i, (step_name, step_func) in enumerate(steps, 1):
                progress_window['progress']['value'] = (i / len(steps)) * 100
                progress_window['label'].config(text=step_name)
                self.root.update()
                
                step_func()
                time.sleep(2)
            
            self.ghost_mode_active = True
            self.update_status("Ghost Mode Active")
            self.log("✅ Ghost Mode activation complete!", "success")
            
            # Show completion message
            self.root.after(0, lambda: [
                progress_window['window'].destroy(),
                messagebox.showinfo("Ghost Mode", "Ghost Mode activated successfully!\n\n"
                                    "• MAC Address changed\n"
                                    "• Tor routing active\n" 
                                    "• VPN connected\n"
                                    "• Kill switch enabled\n"
                                    "• System cleaned")
            ])
            
        except Exception as e:
            error_msg = f"Error activating Ghost Mode: {str(e)}"
            self.log(error_msg, "error")
            self.root.after(0, lambda: [
                progress_window['window'].destroy(),
                messagebox.showerror("Activation Error", error_msg),
                self.deactivate_ghost_mode()
            ])

    def _change_mac_for_ghost(self):
        """Change MAC address for Ghost Mode"""
        if not self.mac_changed:
            random_mac = self.generate_ghost_mac()
            success = self.change_mac_address(random_mac)
            if not success:
                raise Exception("Failed to change MAC address")

    def _connect_vpn_for_ghost(self):
        """Connect VPN for Ghost Mode"""
        if self.vpn_config.get() and not self.vpn_active:
            self.connect_vpn()
            # Wait for VPN connection
            for _ in range(10):
                if self.vpn_active:
                    break
                time.sleep(1)

    def _enable_killswitch_for_ghost(self):
        """Enable kill switch for Ghost Mode"""
        if self.vpn_active:
            self.enable_killswitch()

    def generate_ghost_mac(self):
        """Generate a random MAC address for Ghost Mode"""
        mac = [0x02, 0x00, 0x00]  # Locally administered, unicast
        mac += [random.randint(0x00, 0xff) for _ in range(3)]
        return ':'.join(map(lambda x: f"{x:02x}", mac)).upper()

    def deactivate_ghost_mode(self):
        """Deactivate anonymity mode and reset MAC"""
        self.log("🛑 Deactivating Ghost Mode...")
        self.update_status("Deactivating Ghost Mode")
        
        # Show progress dialog
        progress_window = self.create_progress_window("Deactivating Ghost Mode")
        
        # Stop processes in sequence
        threading.Thread(target=self._deactivate_ghost_processes, args=(progress_window,), daemon=True).start()

    def _deactivate_ghost_processes(self, progress_window):
        try:
            steps = [
                ("Disabling Kill Switch...", self.disable_killswitch),
                ("Disconnecting VPN...", self.disconnect_vpn),
                ("Stopping Tor...", self.stop_tor),
                ("Resetting MAC Address...", self.reset_mac_address)
            ]
            
            for i, (step_name, step_func) in enumerate(steps, 1):
                progress_window['progress']['value'] = (i / len(steps)) * 100
                progress_window['label'].config(text=step_name)
                self.root.update()
                
                step_func()
                time.sleep(2)
            
            self.ghost_mode_active = False
            
            # Update UI
            self.root.after(0, lambda: [
                self.stop_btn.config(state=DISABLED),
                self.start_btn.config(state=NORMAL),
                progress_window['window'].destroy()
            ])
            
            self.update_status("Ready")
            self.log("✅ Ghost Mode deactivated completely", "success")
            messagebox.showinfo("Ghost Mode", "Ghost Mode deactivated!\n\n"
                                "• MAC Address reset to original\n"
                                "• All services stopped\n"
                                "• Network restored to normal")
            
        except Exception as e:
            error_msg = f"Error deactivating Ghost Mode: {str(e)}"
            self.log(error_msg, "error")
            self.root.after(0, lambda: [
                progress_window['window'].destroy(),
                messagebox.showerror("Deactivation Error", error_msg)
            ])

    def create_progress_window(self, title):
        """Create a progress window for operations"""
        window = Toplevel(self.root)
        window.title(title)
        window.geometry("400x150")
        window.configure(bg='#0a0a0a')
        window.transient(self.root)
        window.grab_set()
        
        label = ttk.Label(window, text="Starting...", font=('Courier', 12))
        label.pack(pady=10)
        
        progress = ttk.Progressbar(window, orient=HORIZONTAL, length=350, mode='determinate')
        progress.pack(pady=10)
        
        return {'window': window, 'label': label, 'progress': progress}

    def check_tor_status(self):
        """Check if Tor is running"""
        try:
            result = subprocess.run("pgrep -x tor", shell=True, stdout=subprocess.PIPE)
            if result.returncode == 0:
                self.tor_active = True
                self.tor_status_label.config(text="Running")
                self.tor_status.config(text="Active")
                self.start_tor_btn.config(state=DISABLED)
                self.stop_tor_btn.config(state=NORMAL)
            else:
                self.tor_active = False
                self.tor_status_label.config(text="Stopped")
                self.tor_status.config(text="Inactive")
                self.start_tor_btn.config(state=NORMAL)
                self.stop_tor_btn.config(state=DISABLED)
        except:
            self.tor_active = False
            self.tor_status_label.config(text="Error")
            self.tor_status.config(text="Error")

    def start_tor(self):
        """Start Tor service"""
        self.log("Starting Tor service...")
        
        try:
            subprocess.run("sudo service tor start", shell=True, check=True)
            time.sleep(2)  # Give Tor time to start
            
            self.tor_log.insert(END, "Tor service started\n")
            self.check_tor_status()
            self.log("Tor started successfully", "success")
            
        except subprocess.CalledProcessError as e:
            self.tor_log.insert(END, f"Failed to start Tor: {e.stderr.decode()}\n")
            self.log("Failed to start Tor", "error")

    def stop_tor(self):
        """Stop Tor service"""
        self.log("Stopping Tor service...")
        
        try:
            subprocess.run("sudo service tor stop", shell=True, check=True)
            self.tor_log.insert(END, "Tor service stopped\n")
            self.check_tor_status()
            self.log("Tor stopped successfully", "success")
            
        except subprocess.CalledProcessError as e:
            self.tor_log.insert(END, f"Failed to stop Tor: {e.stderr.decode()}\n")
            self.log("Failed to stop Tor", "error")

    def test_tor(self):
        """Test Tor connection"""
        self.log("Testing Tor connection...")
        
        try:
            result = subprocess.run("curl --socks5 localhost:9050 -s https://check.torproject.org", 
                                  shell=True, check=True, stdout=subprocess.PIPE)
            output = result.stdout.decode()
            
            if "Congratulations" in output:
                ip_line = [line for line in output.split('\n') if "IP address" in line][0]
                self.log(f"Tor is working! {ip_line}", "success")
                messagebox.showinfo("Tor Test", "Tor connection is working properly!")
            else:
                self.log("Tor check failed - not using Tor", "warning")
                messagebox.showwarning("Tor Test", "Not connected via Tor!")
                
        except subprocess.CalledProcessError as e:
            self.log(f"Tor test failed: {str(e)}", "error")
            messagebox.showerror("Tor Test", "Failed to test Tor connection!")

    def check_vpn_status(self):
        """Check if VPN is connected"""
        try:
            result = subprocess.run("pgrep -x openvpn", shell=True, stdout=subprocess.PIPE)
            if result.returncode == 0:
                self.vpn_active = True
                self.vpn_status_label.config(text="Connected")
                self.vpn_status.config(text="Active")
                self.connect_vpn_btn.config(state=DISABLED)
                self.disconnect_vpn_btn.config(state=NORMAL)
                
                # Get VPN IP
                try:
                    ip = requests.get('https://api.ipify.org').text
                    self.vpn_log.insert(END, f"VPN IP: {ip}\n")
                except:
                    self.vpn_log.insert(END, "Could not get VPN IP\n")
            else:
                self.vpn_active = False
                self.vpn_status_label.config(text="Disconnected")
                self.vpn_status.config(text="Inactive")
                self.connect_vpn_btn.config(state=NORMAL)
                self.disconnect_vpn_btn.config(state=DISABLED)
        except:
            self.vpn_active = False
            self.vpn_status_label.config(text="Error")
            self.vpn_status.config(text="Error")

    def browse_vpn_config(self):
        """Browse for VPN config file"""
        filename = filedialog.askopenfilename(title="Select VPN Config", 
                                            filetypes=[("OVPN files", "*.ovpn"), ("All files", "*.*")])
        if filename:
            self.vpn_config.delete(0, END)
            self.vpn_config.insert(0, filename)
            self.save_config()

    def connect_vpn(self):
        """Connect to VPN"""
        config = self.vpn_config.get()
        if not config:
            messagebox.showerror("Error", "No VPN config selected!")
            return
        
        if not os.path.exists(config):
            messagebox.showerror("Error", "VPN config file does not exist!")
            return
        
        self.log(f"Connecting to VPN using {config}...")
        
        try:
            # Start OpenVPN in background
            subprocess.Popen(f"sudo openvpn --config {config}", shell=True)
            
            # Wait for connection
            time.sleep(5)
            self.check_vpn_status()
            
            if self.vpn_active:
                self.log("VPN connected successfully", "success")
            else:
                self.log("VPN connection failed", "error")
                
        except Exception as e:
            self.log(f"VPN connection error: {str(e)}", "error")

    def disconnect_vpn(self):
        """Disconnect from VPN"""
        self.log("Disconnecting VPN...")
        
        try:
            subprocess.run("sudo pkill openvpn", shell=True, check=True)
            time.sleep(2)
            self.check_vpn_status()
            self.log("VPN disconnected", "success")
            
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to disconnect VPN: {str(e)}", "error")

    def test_vpn(self):
        """Test VPN connection"""
        self.log("Testing VPN connection...")
        
        try:
            ip = requests.get('https://api.ipify.org').text
            self.log(f"Current external IP: {ip}", "info")
            messagebox.showinfo("VPN Test", f"Your external IP is: {ip}")
            
        except Exception as e:
            self.log(f"VPN test failed: {str(e)}", "error")
            messagebox.showerror("VPN Test", "Failed to test VPN connection!")

    def toggle_killswitch(self):
        """Toggle kill switch on/off"""
        if self.killswitch_active:
            self.disable_killswitch()
        else:
            self.enable_killswitch()

    def enable_killswitch(self):
        """Enable kill switch to block all non-VPN traffic"""
        if not self.vpn_active:
            messagebox.showwarning("Kill Switch", "VPN is not active! Enable VPN first.")
            return
        
        self.log("Enabling kill switch...")
        
        try:
            # Flush existing rules
            subprocess.run("sudo iptables -F", shell=True, check=True)
            subprocess.run("sudo iptables -X", shell=True, check=True)
            
            # Set default policies
            subprocess.run("sudo iptables -P INPUT DROP", shell=True, check=True)
            subprocess.run("sudo iptables -P OUTPUT DROP", shell=True, check=True)
            subprocess.run("sudo iptables -P FORWARD DROP", shell=True, check=True)
            
            # Allow loopback
            subprocess.run("sudo iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -A OUTPUT -o lo -j ACCEPT", shell=True, check=True)
            
            # Allow established connections
            subprocess.run("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", 
                          shell=True, check=True)
            
            # Allow VPN interface
            subprocess.run(f"sudo iptables -A OUTPUT -o {self.network_interface} -j ACCEPT", 
                          shell=True, check=True)
            
            self.killswitch_active = True
            self.killswitch_btn.config(text="Disable Kill Switch")
            self.killswitch_status.config(text="Active")
            self.log("Kill switch enabled", "success")
            
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to enable kill switch: {str(e)}", "error")

    def disable_killswitch(self):
        """Disable kill switch"""
        self.log("Disabling kill switch...")
        
        try:
            # Flush all rules
            subprocess.run("sudo iptables -F", shell=True, check=True)
            subprocess.run("sudo iptables -X", shell=True, check=True)
            
            # Set default policies to ACCEPT
            subprocess.run("sudo iptables -P INPUT ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True, check=True)
            subprocess.run("sudo iptables -P FORWARD ACCEPT", shell=True, check=True)
            
            self.killswitch_active = False
            self.killswitch_btn.config(text="Enable Kill Switch")
            self.killswitch_status.config(text="Inactive")
            self.log("Kill switch disabled", "success")
            
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to disable kill switch: {str(e)}", "error")

    def clean_system(self):
        """Clean system traces using BleachBit"""
        self.log("Starting system cleanup...")
        self.cleaning_active = True
        self.clean_status.config(text="Cleaning...")
        
        # Determine what to clean
        clean_commands = []
        
        if self.clean_browser_var.get():
            clean_commands.append("bleachbit -c firefox.chrome.cache firefox.cookies firefox.dom")
        
        if self.clean_temp_var.get():
            clean_commands.append("bleachbit -c system.tmp system.cache")
        
        if self.clean_logs_var.get():
            clean_commands.append("bleachbit -c system.logs")
        
        if self.clean_dns_var.get():
            clean_commands.append("sudo systemd-resolve --flush-caches")
        
        if not clean_commands:
            self.log("No cleanup options selected", "warning")
            return
        
        # Run cleanup in background
        threading.Thread(target=self._run_cleanup, args=(clean_commands,), daemon=True).start()

    def _run_cleanup(self, commands):
        """Run cleanup commands"""
        try:
            for cmd in commands:
                self.cleaner_log.insert(END, f"Running: {cmd}\n")
                self.cleaner_log.see(END)
                
                result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    self.cleaner_log.insert(END, "Cleanup successful\n")
                    self.log("System cleanup completed", "success")
                else:
                    self.cleaner_log.insert(END, f"Cleanup failed: {result.stderr.decode()}\n")
                    self.log("System cleanup failed", "error")
                
                self.cleaner_log.see(END)
            
            self.cleaning_active = False
            self.clean_status.config(text="Clean")
            
        except Exception as e:
            self.cleaner_log.insert(END, f"Cleanup error: {str(e)}\n")
            self.log(f"Cleanup error: {str(e)}", "error")
            self.cleaning_active = False
            self.clean_status.config(text="Error")

    def schedule_clean(self):
        """Schedule periodic cleaning"""
        interval = simpledialog.askinteger("Schedule Clean", 
                                          "Enter cleaning interval in minutes:", 
                                          minvalue=1, maxvalue=1440)
        if interval:
            self.log(f"Scheduled cleaning every {interval} minutes")
            # In a real app, you would set up a timer here

    def update_network_info(self):
        """Update network information display"""
        try:
            # Get public IP
            try:
                ip = requests.get('https://api.ipify.org').text
                self.ip_label.config(text=f"Public IP: {ip}")
            except:
                self.ip_label.config(text="Public IP: Unknown")
            
            # Get local IP
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
                self.local_ip_label.config(text=f"Local IP: {local_ip}")
            except:
                self.local_ip_label.config(text="Local IP: Unknown")
            
            # Update MAC info
            self.update_mac_info()
            
        except Exception as e:
            self.log(f"Error updating network info: {str(e)}", "error")

    def scan_ports(self):
        """Scan ports on target"""
        target = self.scan_target.get()
        if not target:
            messagebox.showwarning("Scan Error", "Please enter a target to scan")
            return
        
        self.log(f"Scanning ports on {target}...")
        
        try:
            result = subprocess.run(f"nmap -sS {target}", shell=True, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.scan_results.delete(1.0, END)
            self.scan_results.insert(END, result.stdout.decode())
            self.log(f"Port scan completed for {target}", "success")
            
        except subprocess.CalledProcessError as e:
            self.scan_results.delete(1.0, END)
            self.scan_results.insert(END, f"Scan failed: {e.stderr.decode()}")
            self.log(f"Port scan failed: {e.stderr.decode()}", "error")

    def test_dns_leak(self):
        """Test for DNS leaks"""
        self.log("Testing for DNS leaks...")
        
        try:
            webbrowser.open("https://dnsleaktest.com")
            self.log("DNS leak test opened in browser", "success")
        except Exception as e:
            self.log(f"Failed to open DNS leak test: {str(e)}", "error")

    def save_settings(self):
        """Save application settings"""
        self.network_interface = self.interface_var.get()
        self.interface_label.config(text=f"Interface: {self.network_interface}")
        
        self.save_config()
        self.log("Settings saved", "success")
        messagebox.showinfo("Settings", "Settings saved successfully!")

    def start_monitoring(self):
        """Start periodic system monitoring"""
        self.update_system_status()
        self.root.after(5000, self.start_monitoring)

    def update_system_status(self):
        """Update all system status indicators"""
        self.check_tor_status()
        self.check_vpn_status()
        self.update_network_info()
        
        # Update dashboard status
        if self.killswitch_active:
            self.killswitch_status.config(text="Active")
        else:
            self.killswitch_status.config(text="Inactive")
        
        if self.cleaning_active:
            self.clean_status.config(text="Cleaning...")
        else:
            self.clean_status.config(text="Clean")
        
        # Update MAC status
        if self.mac_changed:
            self.mac_status.config(text="Spoofed")
        else:
            self.mac_status.config(text="Original")

    def log(self, message, level="info"):
        """Add message to log console"""
        if level == "error":
            self.console.insert(END, f"[ERROR] {message}\n", "error")
            self.console.tag_config("error", foreground="red")
        elif level == "warning":
            self.console.insert(END, f"[WARN] {message}\n", "warning")
            self.console.tag_config("warning", foreground="yellow")
        elif level == "success":
            self.console.insert(END, f"[SUCCESS] {message}\n", "success")
            self.console.tag_config("success", foreground="#00ff00")
        else:
            self.console.insert(END, f"[INFO] {message}\n")
        
        self.console.see(END)

    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=f"Status: {message}")

    def animate_logo(self):
        """Animate the logo with color changes"""
        colors = ['#00ff00', '#00cc00', '#009900', '#00cc00']
        current = 0
        
        def cycle_colors():
            nonlocal current
            self.logo_label.config(fg=colors[current])
            current = (current + 1) % len(colors)
            self.root.after(500, cycle_colors)
        
        cycle_colors()

if __name__ == "__main__":
    root = Tk()
    app = AdvancedAnonymitySuite(root)
    root.mainloop()