# Abandoned Link Scanner - Burp Suite Extension

The **Abandoned Link Scanner** is a Burp Suite extension designed to automate the process of identifying abandoned or misconfigured subdomains that could be exploited by attackers to take control of a domain.

This tool is particularly useful for penetration testers, bug bounty hunters, and security professionals who want to identify and mitigate subdomain takeover risks in their target environments.

## Installation

### Prerequisites
- **Burp Suite Professional**: The extension requires Burp Suite Professional.
- **Jython**: Ensure Jython is installed and configured in Burp Suite. You can download Jython from [here](https://www.jython.org/download).

### Steps
1. Download the `abandoned-link-scanner.py` file from this repository.
2. Open Burp Suite and navigate to the **Extender** tab.
3. Go to the **Extensions** section and click **Add**.
4. Set the **Extension Type** to **Python**.
5. Select the `abandoned-link-scanner.py` file.
6. Click **Next** and ensure the extension loads without errors.

## Usage

### Passive Scanning
The extension automatically performs passive scanning as you browse or proxy traffic through Burp Suite. It will identify potential subdomain takeover vulnerabilities and report them in the **Issues** tab.

### Manual Scanning
To manually scan a specific request/response:
1. Add the domain in scope.
2. Use Burp Suite's passive scanner. In case it finds domains that could be affected, it will highlight the results in the Issues tab.
3. Review the results in the **Issues** tab.

### Interpreting Results
- **Potential Vulnerabilities**: The extension will flag subdomains that may be abandoned and vulnerable to takeover.
- **Highlighted Responses**: The tool highlights specific parts of the response that indicate a potential vulnerability (e.g., "The specified bucket does not exist" for AWS S3).
- **Severity Levels**: Issues are categorized as **Medium** severity by default, but manual verification is recommended.

## Supported Services

The extension currently supports detection for the following services:
- **AWS S3**
- **Azure (Blob Storage, Web Apps)**
- **GitHub Pages**
- **Heroku**
- **Surge.sh**
- **ReadTheDocs**
- **WordPress**
- **Ngrok**
- **And more...**

You can extend the tool by adding new patterns to the `cloud_errors` dictionary in the code.

## License

This project is licensed under the **Apache License**.

Copyright 2016-2025, Blaze Information Security https://www.blazeinfosec.com

## Acknowledgments

- **EdOverflow**: For the inspiration from the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project.
- **Lauritz Holtmann**: For dead-domain-discovery [Chrome extension](https://github.com/lauritzh/dead-domain-discovery).

## Contact

For questions, feedback, or support, please open an issue in this repository or contact the maintainers directly.
