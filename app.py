
from flask import Flask, render_template, request
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = Flask(__name__)

# ==========================================
# SECURITY HEADERS TO ANALYZE
# ==========================================

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Controls which resources a browser can load.",
        "recommendation": "Configure a suitable Content-Security-Policy."
    },

    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Enforces HTTPS connections in supported browsers.",
        "recommendation": "Configure Strict-Transport-Security on HTTPS websites."
    },

    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },

    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Helps protect against clickjacking.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },

    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information is shared.",
        "recommendation": "Configure a suitable Referrer-Policy."
    },

    "Permissions-Policy": {
        "severity": "Low",
        "description": "Controls access to browser features such as camera and microphone.",
        "recommendation": "Configure an appropriate Permissions-Policy."
    }
}


# ==========================================
# URL VALIDATION
# ==========================================

def validate_url(url):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    if parsed.port and parsed.port not in (80, 443):
        raise ValueError("Only standard HTTP and HTTPS ports are allowed.")

    hostname = parsed.hostname.lower()

    if hostname == "localhost" or hostname.endswith(".local"):
        raise ValueError("Local hostnames are not allowed.")

    try:

        addresses = socket.getaddrinfo(hostname, None)

        if not addresses:
            raise ValueError("Unable to resolve website hostname.")

        for address in addresses:

            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise ValueError(
                    "Private or reserved IP addresses are not allowed."
                )

    except socket.gaierror:
        raise ValueError("Unable to resolve website hostname.")

    return url


# ==========================================
# SECURITY HEADER ANALYSIS
# ==========================================

def analyze_headers(headers):

    findings = []
    present_count = 0

    for header, details in SECURITY_HEADERS.items():

        value = headers.get(header)

        if value:

            present_count += 1

            findings.append({

                "name": header,
                "status": "Present",
                "value": value,
                "severity": details["severity"],

                "description": details["description"],

                "recommendation": (
                    "Review the header value to ensure "
                    "it is correctly configured."
                )

            })

        else:

            findings.append({

                "name": header,
                "status": "Missing",
                "value": "",
                "severity": details["severity"],

                "description": details["description"],

                "recommendation": details["recommendation"]

            })

    total_count = len(SECURITY_HEADERS)

    score = round((present_count / total_count) * 100)

    return findings, score, present_count


# ==========================================
# HOME PAGE AND WEBSITE ANALYSIS
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():

    results = None
    error = None
    target = ""

    if request.method == "POST":

        target = request.form.get("url", "").strip()

        try:

            # Validate website URL
            safe_url = validate_url(target)

            # Send HTTP GET request
            response = requests.get(

                safe_url,

                timeout=10,

                allow_redirects=False,

                headers={
                    "User-Agent": "WebSecurityHeaderAnalyzer/1.0"
                },

                stream=True

            )

            try:

                # Analyze response headers
                findings, score, present_count = analyze_headers(
                    response.headers
                )

                # Store analysis results
                results = {

                    "url": safe_url,

                    "score": score,

                    "present_count": present_count,

                    "total_count": len(SECURITY_HEADERS),

                    "status_code": response.status_code,

                    "findings": findings

                }

            finally:
                response.close()

        except ValueError as e:

            error = str(e)

        except requests.Timeout:

            error = "The website request timed out. Please try again."

        except requests.RequestException:

            error = (
                "Unable to connect to the website. "
                "Check the URL or internet connection."
            )

        except Exception:

            error = "An unexpected error occurred during analysis."

    return render_template(

        "index.html",

        results=results,

        error=error,

        target=target

    )


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False

    )
