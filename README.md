
# Web Security Header Analyzer

A Python Flask-based web security assessment tool that analyzes HTTP response headers and identifies missing security configurations.

## Features

- HTTP security header analysis
- Content-Security-Policy (CSP) detection
- Strict-Transport-Security (HSTS) detection
- X-Content-Type-Options detection
- X-Frame-Options detection
- Referrer-Policy detection
- Permissions-Policy detection
- Security header presence score
- Vulnerability explanations
- Remediation recommendations
- Responsive dark-themed interface

## Technologies Used

- Python
- Flask
- Requests
- HTML5
- CSS3
- Jinja2

## Installation

Clone the repository:

git clone https://github.com/YOUR-USERNAME/web-security-header-analyzer.git

Navigate to the folder:

cd web-security-header-analyzer

Create a virtual environment:

python -m venv venv

Activate the environment on Windows:

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the application:

python app.py

Open in browser:

http://127.0.0.1:5000

## How It Works

1. Enter a public website URL.
2. The application sends an HTTP GET request.
3. The response headers are retrieved.
4. Selected security headers are checked.
5. Missing headers are identified.
6. A security score and remediation suggestions are displayed.

## Disclaimer

This project is intended for educational purposes.
Only analyze websites you own or have permission to assess.
The tool is not a complete VAPT scanner.
Do not expose the development server to untrusted users.
