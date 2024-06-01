# IP Scanner VT

This is a Python script that checks the reputation of an IP address on VirusTotal using the VirusTotal Public API.

## Prerequisites

- Python 3.x
- requests library

## Installation

1. Clone the repository or download the script file.
2. Install the requests library by running the following command:
    ```
    pip install requests
    ```

## Usage

1. Open a terminal or command prompt.
2. Navigate to the directory where the script is located.
3. Run the script using the following command:
    ```
    python scan_VT.py
    ```
4. Enter the IP address you want to check when prompted.
5. The script will display the IP address, country, and last analysis results for the given IP address.
6. If any analysis result is 'malicious', a warning message will be displayed.

## Configuration

Before running the script, make sure to replace `VT_API_KEY` with your own VirusTotal API key in the `api_key` variable.


## Disclaimer

This script is provided for educational and informational purposes only. Use it at your own risk.

