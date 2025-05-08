#!/usr/bin/env python3
"""
PICA - Metasploit API Integration Module
This module provides a Python interface to interact with Metasploit through its RPC API
"""

import time
import requests
import msgpack
import json
import sys
import os
from argparse import ArgumentParser


class MetasploitAPI:
    """Class to interact with the Metasploit RPC API"""

    def __init__(self, host="127.0.0.1", port=55552, username="msf", password="", ssl=False):
        """Initialize the MetasploitAPI object

        Args:
            host (str): RPC server host (default: "127.0.0.1")
            port (int): RPC server port (default: 55552)
            username (str): RPC username (default: "msf")
            password (str): RPC password
            ssl (bool): Use SSL/TLS (default: False)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.token = None
        self.uri = f"{'https' if ssl else 'http'}://{host}:{port}/api/1.0"
        self.headers = {"Content-Type": "binary/message-pack"}
        self.console_id = None

    def login(self):
        """Authenticate to the Metasploit RPC server

        Returns:
            bool: True if login successful
        """
        params = {
            "method": "auth.login",
            "params": [self.username, self.password],
        }

        resp = self._send_request(params)
        if resp and resp.get("result") == "success":
            self.token = resp.get("token")
            print(f"[+] Successfully authenticated to Metasploit RPC server")
            return True
        else:
            print(f"[-] Authentication failed")
            return False

    def create_console(self):
        """Create a new console

        Returns:
            str: Console ID if successful, None otherwise
        """
        params = {
            "method": "console.create",
            "params": [],
        }

        resp = self._send_request(params)
        if resp and "id" in resp:
            self.console_id = resp["id"]
            print(f"[+] Created console with ID: {self.console_id}")
            return self.console_id
        else:
            print(f"[-] Failed to create console")
            return None

    def destroy_console(self, console_id=None):
        """Destroy a console

        Args:
            console_id (str): Console ID to destroy (default: None, uses self.console_id)

        Returns:
            bool: True if successful
        """
        if console_id is None:
            console_id = self.console_id

        params = {
            "method": "console.destroy",
            "params": [console_id],
        }

        resp = self._send_request(params)
        if resp and resp.get("result") == "success":
            print(f"[+] Destroyed console {console_id}")
            if console_id == self.console_id:
                self.console_id = None
            return True
        else:
            print(f"[-] Failed to destroy console {console_id}")
            return False

    def console_write(self, command, console_id=None):
        """Write a command to the console

        Args:
            command (str): Command to execute
            console_id (str): Console ID (default: None, uses self.console_id)

        Returns:
            bool: True if successful
        """
        if console_id is None:
            console_id = self.console_id
            if console_id is None:
                self.create_console()
                console_id = self.console_id

        params = {
            "method": "console.write",
            "params": [console_id, command + "\n"],
        }

        resp = self._send_request(params)
        if resp and resp.get("wrote") > 0:
            print(f"[+] Wrote command to console: {command}")
            return True
        else:
            print(f"[-] Failed to write to console")
            return False

    def console_read(self, console_id=None):
        """Read output from the console

        Args:
            console_id (str): Console ID (default: None, uses self.console_id)

        Returns:
            dict: Console read response
        """
        if console_id is None:
            console_id = self.console_id

        params = {
            "method": "console.read",
            "params": [console_id],
        }

        resp = self._send_request(params)
        return resp

    def wait_for_output(self, console_id=None, timeout=120):
        """Wait for console output to be available

        Args:
            console_id (str): Console ID (default: None, uses self.console_id)
            timeout (int): Timeout in seconds (default: 120)

        Returns:
            str: Console output
        """
        if console_id is None:
            console_id = self.console_id

        start_time = time.time()
        output = ""
        busy = True

        while busy and (time.time() - start_time) < timeout:
            resp = self.console_read(console_id)
            if resp:
                output += resp.get("data", "")
                busy = resp.get("busy", False)
            
            if not busy:
                break
                
            time.sleep(1)

        if (time.time() - start_time) >= timeout:
            print(f"[-] Timeout waiting for console output")
        
        return output

    def run_command(self, command, console_id=None):
        """Run a command and get the output

        Args:
            command (str): Command to execute
            console_id (str): Console ID (default: None, uses self.console_id)

        Returns:
            str: Command output
        """
        if console_id is None:
            console_id = self.console_id
            if console_id is None:
                self.create_console()
                console_id = self.console_id
        
        self.console_write(command, console_id)
        return self.wait_for_output(console_id)

    def get_modules(self, module_type):
        """Get list of modules by type

        Args:
            module_type (str): Module type (exploit, auxiliary, post, payload, encoder, nop)

        Returns:
            list: List of modules
        """
        params = {
            "method": "module.exploits",
            "params": [],
        }

        if module_type == "exploit":
            params["method"] = "module.exploits"
        elif module_type == "auxiliary":
            params["method"] = "module.auxiliary"
        elif module_type == "post":
            params["method"] = "module.post"
        elif module_type == "payload":
            params["method"] = "module.payloads"
        elif module_type == "encoder":
            params["method"] = "module.encoders"
        elif module_type == "nop":
            params["method"] = "module.nops"
        else:
            print(f"[-] Invalid module type: {module_type}")
            return []

        resp = self._send_request(params)
        if resp:
            modules = resp.get("modules", [])
            print(f"[+] Found {len(modules)} {module_type} modules")
            return modules
        else:
            print(f"[-] Failed to get {module_type} modules")
            return []

    def get_module_info(self, module_type, module_name):
        """Get detailed information about a module

        Args:
            module_type (str): Module type
            module_name (str): Module name

        Returns:
            dict: Module information
        """
        params = {
            "method": "module.info",
            "params": [module_type, module_name],
        }

        resp = self._send_request(params)
        if resp:
            return resp
        else:
            print(f"[-] Failed to get info for {module_type}/{module_name}")
            return {}

    def get_module_options(self, module_type, module_name):
        """Get options for a module

        Args:
            module_type (str): Module type
            module_name (str): Module name

        Returns:
            dict: Module options
        """
        params = {
            "method": "module.options",
            "params": [module_type, module_name],
        }

        resp = self._send_request(params)
        if resp:
            return resp
        else:
            print(f"[-] Failed to get options for {module_type}/{module_name}")
            return {}

    def run_scanner(self, scanner_name, options):
        """Run a scanner module with options

        Args:
            scanner_name (str): Full scanner name (e.g., "auxiliary/scanner/smb/smb_version")
            options (dict): Scanner options

        Returns:
            str: Scanner output
        """
        module_type = scanner_name.split("/")[0]
        module_name = "/".join(scanner_name.split("/")[1:])
        
        # First, check if the console exists
        if self.console_id is None:
            self.create_console()
        
        # Set up the module
        cmd = f"use {scanner_name}\n"
        self.console_write(cmd)
        
        # Set options
        for option, value in options.items():
            cmd = f"set {option} {value}\n"
            self.console_write(cmd)
        
        # Run the scanner
        cmd = "run\n"
        self.console_write(cmd)
        
        # Wait for output
        return self.wait_for_output()

    def scan_network(self, target, scan_type="basic"):
        """Perform a network scan

        Args:
            target (str): Target IP, network range, or hostname
            scan_type (str): Type of scan (basic, comprehensive, smb, web)

        Returns:
            str: Scan output
        """
        if scan_type == "basic":
            # Basic port scan
            return self.run_command(f"db_nmap -sV -sS {target}")
        elif scan_type == "comprehensive":
            # Comprehensive scan
            return self.run_command(f"db_nmap -sV -sS -A -p- {target}")
        elif scan_type == "smb":
            # SMB-focused scan
            options = {
                "RHOSTS": target
            }
            output = ""
            scanners = [
                "auxiliary/scanner/smb/smb_version",
                "auxiliary/scanner/smb/smb_enumshares",
                "auxiliary/scanner/smb/smb_lookupsid",
                "auxiliary/scanner/smb/smb_ms17_010"
            ]
            
            for scanner in scanners:
                output += f"\n\n=== Running {scanner} ===\n"
                output += self.run_scanner(scanner, options)
            
            return output
        elif scan_type == "web":
            # Web application scan
            options = {
                "RHOSTS": target
            }
            output = ""
            scanners = [
                "auxiliary/scanner/http/http_version",
                "auxiliary/scanner/http/dir_scanner",
                "auxiliary/scanner/http/files_dir",
                "auxiliary/scanner/http/robots_txt"
            ]
            
            for scanner in scanners:
                output += f"\n\n=== Running {scanner} ===\n"
                output += self.run_scanner(scanner, options)
            
            return output
        else:
            print(f"[-] Invalid scan type: {scan_type}")
            return ""

    def get_hosts(self):
        """Get list of hosts from the database

        Returns:
            list: List of hosts
        """
        return self.run_command("hosts -c address,name,os_name,purpose")

    def get_services(self):
        """Get list of services from the database

        Returns:
            list: List of services
        """
        return self.run_command("services -c port,proto,name,state")

    def get_vulns(self):
        """Get list of vulnerabilities from the database

        Returns:
            list: List of vulnerabilities
        """
        return self.run_command("vulns -c host,name,refs,info")

    def import_scan(self, file_path):
        """Import scan results from a file

        Args:
            file_path (str): Path to scan results file

        Returns:
            str: Import output
        """
        return self.run_command(f"db_import {file_path}")

    def export_report(self, file_path, report_type="json"):
        """Export report to a file

        Args:
            file_path (str): Output file path
            report_type (str): Report type (json, xml, html)

        Returns:
            str: Export output
        """
        if not file_path.endswith(f".{report_type}"):
            file_path = f"{file_path}.{report_type}"
        
        return self.run_command(f"db_export -f {report_type} {file_path}")

    def _send_request(self, params):
        """Send a request to the Metasploit RPC server

        Args:
            params (dict): Request parameters

        Returns:
            dict: Response data or None if request failed
        """
        if self.token:
            params["token"] = self.token

        try:
            data = msgpack.packb(params)
            resp = requests.post(self.uri, data=data, headers=self.headers)
            
            if resp.status_code == 200:
                return msgpack.unpackb(resp.content, strict_map_key=False)
            else:
                print(f"[-] Request failed with status code {resp.status_code}")
                return None
        except Exception as e:
            print(f"[-] Error sending request: {str(e)}")
            return None


def main():
    """Main function"""
    parser = ArgumentParser(description="Metasploit API client")
    parser.add_argument("--host", default="127.0.0.1", help="Metasploit RPC host")
    parser.add_argument("--port", type=int, default=55552, help="Metasploit RPC port")
    parser.add_argument("--username", default="msf", help="Metasploit RPC username")
    parser.add_argument("--password", required=True, help="Metasploit RPC password")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--target", help="Target to scan")
    parser.add_argument("--scan-type", choices=["basic", "comprehensive", "smb", "web"], 
                        default="basic", help="Type of scan to perform")
    parser.add_argument("--report", help="Output report file path")
    parser.add_argument("--command", help="Run a custom Metasploit command")
    parser.add_argument("--list-modules", choices=["exploit", "auxiliary", "post", "payload", "encoder", "nop"],
                        help="List modules of specified type")
    
    args = parser.parse_args()
    
    api = MetasploitAPI(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        ssl=args.ssl
    )
    
    if not api.login():
        sys.exit(1)
    
    api.create_console()
    
    if args.list_modules:
        modules = api.get_modules(args.list_modules)
        for module in modules:
            print(module)
    
    if args.command:
        output = api.run_command(args.command)
        print(output)
    
    if args.target:
        print(f"[+] Scanning target: {args.target} (scan type: {args.scan_type})")
        output = api.scan_network(args.target, args.scan_type)
        print(output)
        
        if args.report:
            report_type = args.report.split(".")[-1] if "." in args.report else "json"
            api.export_report(args.report, report_type)
            print(f"[+] Report exported to {args.report}")
    
    api.destroy_console()
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 