#!/bin/env python
#
# Handle Splunk alerts and forwards them to XLM's SOC.


import sys
import time
import socket
import logging
import logging.handlers
import tarfile


# Global variables.
# Please configure script behaviour from here.
LOG_FILE = "/opt/splunk/var/log/soc_alert_forwarder.log"
LOG_FMNT = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
LOG_HOST = "172.16.111.13"
LOG_PORT = 514


# Logging global handler.
logger = logging.getLogger()
logger.addHandler(logging.handlers.RotatingFileHandler(LOG_FILE, mode='a', maxBytes=1000000, backupCount=3))
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
for handler in logger.handlers:
    handler.setFormatter(LOG_FMNT)


def send_syslog(alert_xlm):
    """Send the processed alert to the EyeSight / ArcSight connector.

    Arguments:
        alert_xlm (str): Alert in suitable format.
    """
    logger.info("sending alert: {alert} -> {host}:{port}".format(alert=alert_xlm, host=LOG_HOST, port=LOG_PORT))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(alert_xlm.encode(), (LOG_HOST, LOG_PORT))
        logger.info("alert sent")
    except Exception as error:
        logger.warning("cannot send alert: {err}".format(err=str(error)))
        raise


def extract_fields(alert_csv):
    """Extract the alerts fields.

    Arguments:
        alert_csv (str): Path to alert's CSV file.
    """
    handler = tarfile.open(, "r:gz")
    srcfile = handler.extractfile(handler.getmembers()[0])
    alert_data = srcfile.read()



def format_alert(alert_name):
    """Format the alert string.

    Arguments:
        alert_name (str): Splunk E.S. alert name.
    """
    # Basic XLM syslog alert template.
    template = "<133>[qradar-offense] [{alert_desc}] [{alert_time}] [{alert_s_ip}] [{alert_t_ip}] [{alert_user}] [{alert_name}]"
    # Format and return.
    return template.format(alert_desc="Splunk Enterprise Security - Incident",
                           alert_time=time.strftime("%d/%b/%Y:%H:%M:%S", time.localtime()),
                           alert_s_ip="0.0.0.0",
                           alert_t_ip="0.0.0.0",
                           alert_user="N/A",
                           alert_name=alert_name)


def main():
    # Build alert.
    if len(sys.argv) < 5:
        alert = format_alert("ERROR - Alert name not returned by Splunk")
    else:
        fields = extract_fields(sys.argv[8])

        alert = format_alert(sys.argv[4])
    # Send alert.
    send_syslog(alert)


if __name__ == "__main__":
    main()
