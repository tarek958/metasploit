#!/usr/bin/env python3
"""
PICA - Automated Penetration Testing with Metasploit
This script demonstrates integrating Metasploit scanning into the PICA platform
"""

import sys
import os
import json
import time
import argparse
from datetime import datetime
from metasploit_api import MetasploitAPI


class PICAPenTester:
    """PICA Penetration Testing Module using Metasploit"""

    def __init__(self, msf_host="127.0.0.1", msf_port=55552, msf_user="msf", msf_password=""):
        """Initialize the PICA Penetration Testing Module

        Args:
            msf_host (str): Metasploit RPC host
            msf_port (int): Metasploit RPC port
            msf_user (str): Metasploit RPC username
            msf_password (str): Metasploit RPC password
        """
        self.msf_api = MetasploitAPI(
            host=msf_host,
            port=msf_port,
            username=msf_user,
            password=msf_password
        )
        self.scan_results = {}
        self.target = None

    def connect(self):
        """Connect to Metasploit RPC server

        Returns:
            bool: True if connected successfully
        """
        if not self.msf_api.login():
            print("[-] Failed to connect to Metasploit RPC server")
            return False

        print("[+] Connected to Metasploit RPC server")
        return self.msf_api.create_console() is not None

    def run_scan(self, target, scan_types=None):
        """Run scans against a target

        Args:
            target (str): Target IP, hostname, or network range
            scan_types (list): List of scan types to run (default: ["basic"])

        Returns:
            dict: Scan results
        """
        self.target = target
        if scan_types is None:
            scan_types = ["basic"]

        self.scan_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scans": {}
        }

        for scan_type in scan_types:
            print(f"[+] Running {scan_type} scan against {target}")
            start_time = time.time()
            output = self.msf_api.scan_network(target, scan_type)
            duration = time.time() - start_time
            
            self.scan_results["scans"][scan_type] = {
                "output": output,
                "duration": duration
            }
        
        return self.scan_results

    def run_vuln_scan(self, target):
        """Run vulnerability scans on a target

        Args:
            target (str): Target IP or hostname

        Returns:
            dict: Scan results
        """
        # First run a basic scan to identify services
        print(f"[+] Running initial service discovery on {target}")
        self.msf_api.run_command(f"db_nmap -sV -sS {target}")
        
        # Get discovered services
        services_output = self.msf_api.get_services()
        
        # Now run targeted vulnerability scans based on discovered services
        print(f"[+] Running targeted vulnerability scans on {target}")
        vuln_scanners = []
        
        # Check for SMB services
        if "microsoft-ds" in services_output or "netbios" in services_output:
            vuln_scanners.extend([
                "auxiliary/scanner/smb/smb_ms17_010",
                "auxiliary/scanner/smb/smb_enum_shares"
            ])
        
        # Check for web services
        if "http" in services_output or "https" in services_output:
            vuln_scanners.extend([
                "auxiliary/scanner/http/http_version",
                "auxiliary/scanner/http/dir_scanner",
                "auxiliary/scanner/http/apache_optionsbleed",
                "auxiliary/scanner/http/shellshock"
            ])
        
        # Check for SSH
        if "ssh" in services_output:
            vuln_scanners.append("auxiliary/scanner/ssh/ssh_login")
        
        # Check for database services
        if "mysql" in services_output:
            vuln_scanners.append("auxiliary/scanner/mysql/mysql_login")
        if "postgresql" in services_output:
            vuln_scanners.append("auxiliary/scanner/postgres/postgres_login")
        
        # Run all the selected vulnerability scanners
        results = {}
        for scanner in vuln_scanners:
            print(f"[+] Running {scanner}")
            options = {"RHOSTS": target}
            output = self.msf_api.run_scanner(scanner, options)
            results[scanner] = output
        
        return results

    def generate_report(self, output_file="pica_report.json"):
        """Generate a report from scan results

        Args:
            output_file (str): Output file path

        Returns:
            str: Path to generated report
        """
        if not self.scan_results:
            print("[-] No scan results to report")
            return None
        
        # First, get host and service information from Metasploit database
        host_info = self.msf_api.get_hosts()
        service_info = self.msf_api.get_services()
        vuln_info = self.msf_api.get_vulns()
        
        # Add this information to the scan results
        self.scan_results["metasploit_data"] = {
            "hosts": host_info,
            "services": service_info,
            "vulnerabilities": vuln_info
        }
        
        # Export report to file
        print(f"[+] Generating report: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        # Also export Metasploit's native report
        msf_report = f"msf_report_{int(time.time())}"
        self.msf_api.export_report(msf_report)
        
        return output_file

    def close(self):
        """Close connection to Metasploit RPC server"""
        self.msf_api.destroy_console()
        print("[+] Disconnected from Metasploit RPC server")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="PICA Automated Penetration Testing")
    parser.add_argument("--host", default="127.0.0.1", help="Metasploit RPC host")
    parser.add_argument("--port", type=int, default=55552, help="Metasploit RPC port")
    parser.add_argument("--username", default="msf", help="Metasploit RPC username")
    parser.add_argument("--password", required=True, help="Metasploit RPC password")
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--scan-types", nargs="+", default=["basic"],
                        choices=["basic", "comprehensive", "smb", "web"],
                        help="Scan types to run")
    parser.add_argument("--vuln-scan", action="store_true", help="Run vulnerability scans")
    parser.add_argument("--report", default="pica_report.json", help="Output report file")
    
    args = parser.parse_args()
    
    pica = PICAPenTester(
        msf_host=args.host,
        msf_port=args.port,
        msf_user=args.username,
        msf_password=args.password
    )
    
    if not pica.connect():
        sys.exit(1)
    
    # Run the specified scans
    pica.run_scan(args.target, args.scan_types)
    
    # Run additional vulnerability scans if requested
    if args.vuln_scan:
        vuln_results = pica.run_vuln_scan(args.target)
        pica.scan_results["vulnerability_scans"] = vuln_results
    
    # Generate report
    report_path = pica.generate_report(args.report)
    print(f"[+] Report generated: {report_path}")
    
    pica.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 