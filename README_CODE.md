# PICA - Metasploit Python Code Documentation

This document provides a comprehensive explanation of the Python code that interfaces with Metasploit for the PICA (Plateforme Intégrée de Cybersécurité Automatisée) project. This code allows automated security testing using Metasploit's capabilities.

## Project Structure

The project consists of the following files:

- `metasploit_api.py`: Core API wrapper for Metasploit's RPC interface
- `pica_metasploit_scan.py`: Higher-level integration for the PICA platform
- `requirements.txt`: Python dependencies
- `README.md`: User guide for Metasploit usage

## Dependencies

The code requires the following Python packages:

```
requests>=2.28.0      # For HTTP communication with Metasploit API
msgpack>=1.0.4        # For MessagePack serialization format used by Metasploit API
Flask>=2.2.0          # For web application framework (used in PICA platform)
python-dateutil>=2.8.2 # For date/time handling
```

## `metasploit_api.py` - Detailed Code Explanation

This file contains the `MetasploitAPI` class which is a Python wrapper around Metasploit's RPC API. Here's a breakdown of its key components:

### Class Initialization

```python
def __init__(self, host="127.0.0.1", port=55552, username="msf", password="", ssl=False):
```

This method initializes the `MetasploitAPI` object with connection parameters:
- `host`: The hostname/IP where Metasploit RPC server is running (default: localhost)
- `port`: The port number for the RPC server (default: 55552)
- `username`: Username for authentication (default: "msf")
- `password`: Password for authentication
- `ssl`: Whether to use SSL encryption (default: False)

The method sets up:
- Connection parameters
- URI for the API endpoint
- Headers for HTTP requests
- Placeholder for authentication token
- Placeholder for console ID

### Authentication

```python
def login(self):
```

This method authenticates with the Metasploit RPC server:
1. Creates authentication parameters
2. Sends login request to the server
3. Stores the authentication token on success
4. Returns True/False indicating success/failure

### Console Management

```python
def create_console(self):
def destroy_console(self, console_id=None):
def console_write(self, command, console_id=None):
def console_read(self, console_id=None):
def wait_for_output(self, console_id=None, timeout=120):
def run_command(self, command, console_id=None):
```

These methods handle Metasploit console operations:
- `create_console()`: Creates a new Metasploit console session
- `destroy_console()`: Destroys a console session
- `console_write()`: Writes a command to the console
- `console_read()`: Reads the output from the console
- `wait_for_output()`: Waits until command execution completes (with timeout)
- `run_command()`: Convenience method that writes a command and waits for its output

### Module Management

```python
def get_modules(self, module_type):
def get_module_info(self, module_type, module_name):
def get_module_options(self, module_type, module_name):
```

These methods provide information about Metasploit modules:
- `get_modules()`: Lists available modules by type (exploit, auxiliary, post, etc.)
- `get_module_info()`: Gets detailed information about a specific module
- `get_module_options()`: Gets configuration options for a specific module

### Scanning Operations

```python
def run_scanner(self, scanner_name, options):
def scan_network(self, target, scan_type="basic"):
```

These methods handle network scanning operations:
- `run_scanner()`: Runs a specific scanner module with the provided options
- `scan_network()`: Performs different types of network scans:
  - "basic": Simple port scan with service detection
  - "comprehensive": Full-range port scan with OS detection
  - "smb": SMB-focused scan for Windows vulnerabilities
  - "web": Web application scanning

### Data Retrieval

```python
def get_hosts(self):
def get_services(self):
def get_vulns(self):
```

These methods retrieve information from the Metasploit database:
- `get_hosts()`: Lists discovered hosts
- `get_services()`: Lists discovered services
- `get_vulns()`: Lists discovered vulnerabilities

### Import/Export

```python
def import_scan(self, file_path):
def export_report(self, file_path, report_type="json"):
```

These methods handle importing and exporting data:
- `import_scan()`: Imports scan results from external tools
- `export_report()`: Exports findings to various report formats

### API Communication

```python
def _send_request(self, params):
```

This internal method handles low-level communication with the Metasploit API:
1. Adds authentication token to parameters
2. Serializes data using MessagePack
3. Sends HTTP POST request to API endpoint
4. Deserializes and returns the response

### Main Function

The file also includes a main function that demonstrates how to use the API:
1. Parses command line arguments
2. Creates an API instance
3. Authenticates with the server
4. Performs requested operations (module listing, command execution, scanning)
5. Generates reports if requested

## `pica_metasploit_scan.py` - Detailed Code Explanation

This file provides a higher-level interface for the PICA platform using the `MetasploitAPI` class. It consists of the `PICAPenTester` class and a main function.

### PICAPenTester Class

```python
class PICAPenTester:
```

This class provides automation features for penetration testing:

#### Initialization

```python
def __init__(self, msf_host="127.0.0.1", msf_port=55552, msf_user="msf", msf_password=""):
```

This method initializes the class:
- Creates a `MetasploitAPI` instance with connection parameters
- Initializes storage for scan results
- Sets up target placeholder

#### Connection

```python
def connect(self):
```

This method connects to the Metasploit RPC server:
1. Attempts to log in using the API
2. Creates a console session
3. Returns True/False indicating success/failure

#### Scanning

```python
def run_scan(self, target, scan_types=None):
```

This method orchestrates different types of scans:
1. Sets the target and initializes result storage
2. Iterates through requested scan types
3. Tracks timing information for each scan
4. Returns compiled results

#### Vulnerability Scanning

```python
def run_vuln_scan(self, target):
```

This method performs intelligent vulnerability scanning:
1. First discovers services on the target
2. Based on discovered services, selects appropriate vulnerability scanners
   - SMB scanners for Windows services
   - Web scanners for HTTP/HTTPS services
   - SSH scanners for SSH services
   - Database scanners for MySQL/PostgreSQL
3. Runs selected scanners and collects results

#### Reporting

```python
def generate_report(self, output_file="pica_report.json"):
```

This method generates comprehensive reports:
1. Retrieves host, service, and vulnerability information from Metasploit
2. Combines scan results with Metasploit database information
3. Writes a JSON report file
4. Also exports a native Metasploit report
5. Returns the path to the generated report

#### Cleanup

```python
def close(self):
```

This method properly closes the connection to the Metasploit server.

### Main Function

The main function in `pica_metasploit_scan.py`:
1. Parses command line arguments
2. Creates a `PICAPenTester` instance
3. Connects to Metasploit
4. Runs requested scans
5. Performs vulnerability scanning if requested
6. Generates a report
7. Closes the connection

## Usage Examples

### Basic API Usage

```python
from metasploit_api import MetasploitAPI

# Create API instance
api = MetasploitAPI(password="your_password")

# Connect and create console
api.login()
api.create_console()

# Run a basic scan
output = api.scan_network("192.168.1.100")
print(output)

# Clean up
api.destroy_console()
```

### PICA Platform Integration

```python
from pica_metasploit_scan import PICAPenTester

# Create pentester instance
pica = PICAPenTester(msf_password="your_password")

# Connect to Metasploit
if pica.connect():
    # Run scans
    pica.run_scan("192.168.1.100", ["basic", "web"])
    
    # Run vulnerability scans
    vuln_results = pica.run_vuln_scan("192.168.1.100")
    
    # Generate report
    report_path = pica.generate_report("report.json")
    
    # Clean up
    pica.close()
```

## Code Flow Diagrams

### MetasploitAPI Flow

```
Authentication → Console Creation → Command Execution → Module Selection → Scanning → Result Collection → Reporting
```

### PICAPenTester Flow

```
Connection → Service Discovery → Scanner Selection → Vulnerability Scanning → Result Collection → Report Generation
```

## Customization Points

The code can be extended in several ways:

1. **New Scan Types**: Add new scan types in the `scan_network` method
2. **Additional Vulnerability Scanners**: Add more vulnerability scanners in the `run_vuln_scan` method
3. **Enhanced Reporting**: Modify report formats or templates in `generate_report`
4. **Integration with Other Tools**: Add interfaces to other security tools

## Security Considerations

1. The code stores passwords in memory (unavoidable for API authentication)
2. SSL should be enabled in production environments
3. Restrict access to generated reports containing security findings
4. Always ensure proper authorization before testing systems

## Error Handling

The code includes basic error handling:
- Login failure detection
- Command execution timeouts
- Response validation
- Exception handling for API communication

## Performance Optimization

For scanning large networks:
1. Increase timeout values for large scans
2. Use more targeted scan types instead of comprehensive scans
3. Split large networks into smaller segments for scanning

## Troubleshooting

Common issues and solutions:
1. **Connection Failures**: Verify Metasploit RPC server is running (`msfrpcd`)
2. **Timeout Errors**: Increase timeout values for larger targets
3. **Database Issues**: Run `msfdb reinit` to reset Metasploit database
4. **Module Loading Issues**: Use `reload_all` in Metasploit console

## Future Enhancements

Potential improvements to consider:
1. Asynchronous scanning for better performance
2. More robust error handling and retries
3. Enhanced report visualization
4. Integration with threat intelligence feeds
5. Automated remediation suggestions 