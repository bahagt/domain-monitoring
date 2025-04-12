import logging
import logging.handlers
import time
import functools
import os
from datetime import datetime
from flask import Flask, jsonify, request
import ssl
import socket
import yaml
import requests

# --- Load Configuration ---
with open('be_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

APP_NAME = config['app_name']
LOG_FILE = config['log_file']
LOG_LEVEL = config['log_level']
CERT_PATH = config['cert_path']
PORT = config['port']

SYSLOG_FORMAT = '[%(asctime)s | %(levelname)s | %(name)s(%(filename)s/%(funcName)s:%(lineno)d) | %(message)s]'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# --- Decorator for Measuring Execution Time ---
def measure_this(func):
    """Decorator to measure the execution time of a function."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        logger.info(f"Execution time of {func.__name__}: {execution_time:.4f} seconds")
        return result
    return wrapper

# --- Logging Setup ---
def setup_logger(log_file=LOG_FILE, log_level=LOG_LEVEL, syslog_format=SYSLOG_FORMAT, date_format=DATE_FORMAT, app_name=APP_NAME):
    """Sets up the logger with file and console handlers."""
    logger = logging.getLogger(app_name)
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % log_level)
    logger.setLevel(numeric_level)

    # Create formatters and handlers
    formatter = logging.Formatter(syslog_format, datefmt=date_format)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(numeric_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler (rotating file handler for log management)
    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5) # 10MB, 5 backups
    fh.setLevel(numeric_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger

logger = setup_logger()

app = Flask(__name__)
app.logger = logger

# --- Example Application Logic ---
class CertificateAnalyzer:
    def __init__(self, cert_path):
        self.cert_path = cert_path
        self.logger = logging.getLogger(APP_NAME + "." + self.__class__.__name__) # class specific logger

    @measure_this
    def analyze_certificate(self):
        """Simulates certificate analysis (time-consuming)."""
        self.logger.info(f"Starting certificate analysis for: {self.cert_path}") # Log full operation
        try:
            # Simulate reading the certificate file
            with open(self.cert_path, 'r') as f:
                cert_data = f.read()

            # Simulate some analysis
            time.sleep(2)  # Simulate a long-running analysis
            analysis_result = f"Analysis complete: Certificate valid until {datetime.now()}" # Dummy result
            self.logger.info(f"Certificate analysis completed successfully.") #Log full operation
            return analysis_result
        except FileNotFoundError:
            self.logger.error(f"Certificate file not found: {self.cert_path}") # Log full operation + error
            return None
        except Exception as e:
            self.logger.exception(f"Error during certificate analysis: {e}") # Log full operation + exception
            return None

@measure_this
def get_ssl_info(domain):
    """Retrieve SSL expiration and issuer information for a domain."""
    logger.debug(f"Getting SSL info for {domain}")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_expiration = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                ssl_issuer = dict(x[0] for x in cert['issuer'])
                result = {
                    "ssl_expiration": ssl_expiration.strftime("%Y-%m-%d"),
                    "ssl_issuer": ssl_issuer.get("organizationName", "Unknown")
                }
                logger.debug(f"SSL info for {domain}: {result}")
                return result
    except Exception as e:
        logger.exception(f"Error retrieving SSL info for {domain}: {e}")
        return {
            "ssl_expiration": "N/A",
            "ssl_issuer": "Unknown"
        }

@measure_this
def check_domain_status(domain):
    """Check if a domain is alive or down."""
    logger.debug(f"Checking status for {domain}")
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code == 200:
            logger.debug(f"Domain {domain} is up")
            return "Up"
        else:
            status = f"Down ({response.status_code})"
            logger.debug(f"Domain {domain} is down: {status}")
            return status
    except requests.RequestException as e:
        logger.debug(f"Domain {domain} is down: {e}")
        return "Down"
    except Exception as e:
        logger.exception(f"Unexpected error checking domain status for {domain}: {e}")
        return "Down"

# --- API Endpoints ---
@app.route("/api/domain_info")
def api_domain_info():
    """API endpoint to get domain status and SSL information."""
    domain = request.args.get("domain")
    if not domain:
        logger.warning("Received request to /api/domain_info without a domain parameter")
        return jsonify({"error": "Domain parameter is required"}), 400

    try:
        status = check_domain_status(domain)
        ssl_info = get_ssl_info(domain)

        result = {
            "status": status,
            "ssl_expiration": ssl_info["ssl_expiration"],
            "ssl_issuer": ssl_info["ssl_issuer"],
        }
        logger.info(f"Returning domain info for: {domain}")
        logger.debug(f"Domain info: {result}")
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error processing domain info request for {domain}: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
# --- DEV API endpoints ---
@app.route("/api/analyze_cert")
def api_analyze_cert():
  """DEV API endpoint to measure certificate analysis time."""
  logger.info("Received request to /api/analyze_cert")
  cert_analyzer = CertificateAnalyzer(CERT_PATH)
  analysis_result = cert_analyzer.analyze_certificate()

  if analysis_result:
      logger.info(f"Certificate Analysis Result: {analysis_result}")
      return jsonify({"result": analysis_result})
  else:
      logger.warning("Certificate analysis failed.")
      return jsonify({"error": "Certificate analysis failed"}), 500

# --- Main ---
if __name__ == "__main__":
    logger.info(f"Starting BE application: {APP_NAME}")
    try:
        with open(CERT_PATH, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nFake certificate data\n-----END CERTIFICATE-----")
    except Exception as e:
        logger.exception(f"Failed to create dummy certificate: {e}")
    app.run(debug=True, port=PORT, host='0.0.0.0')
    try:
        os.remove(CERT_PATH)
    except Exception as e:
        logger.exception(f"Failed to remove dummy certificate: {e}")