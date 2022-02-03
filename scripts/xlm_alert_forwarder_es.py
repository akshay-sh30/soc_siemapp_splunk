#!/bin/env python
#
# Handle Splunk E.S. alerts and forwards them to XLM's SOC.
# Calling arguments:
# 0: sys.argv[0]: Script path
# 1: sys.argv[1]: Number of events
# 2: sys.argv[2]: Query
# 3: sys.argv[3]: Query
# 4: sys.argv[4]: Alert name
# 5: sys.argv[5]: Alert description
# 6: sys.argv[6]: REST path to alert results
# 7: sys.argv[7]: Empty
# 8: sys.argv[8]: File system path to alerts results


import sys
import time
import socket
import requests
import urllib
import logging
import logging.handlers


# Global variables.
# Please configure script behaviour from here.
LOG_FILE = "/opt/splunk/var/log/xlm_alert_forwarder_es.log"
LOG_FMNT = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
LOG_HOST = "172.16.111.13"
LOG_PORT = 514
SPLUNK_HOST = "https://127.0.0.1:8089"
SPLUNK_USER = "*****"
SPLUNK_PASSWD = "*****"


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


def get_alert_severity(alert_rest_path):
    """Extracts and returns the alert severity.
    """
    logger.info("extracting alert severity")
    try:
        # Extract alert SID from script arguments.
        alert_sid = alert_rest_path.split("?sid=")[1]
        logger.info("alert sid: {}".format(alert_sid))
        # Builds local Splunk E.S. query URL.
        url = "{splunk_host}/servicesNS/admin/search/search/jobs/export".format(splunk_host=SPLUNK_HOST)
        logger.info("request URL: {}".format(url))
        # Builds the search string.
        search_string = """
            search earliest=-2d@d latest=now `notable`\
            | search orig_sid={alert_sid} \
            | stats values(severity) as severity \
            | mvexpand severity\
        """.format(alert_sid=alert_sid)
        logger.info("search string: {}".format(search_string))
        # Defines the query parameters.
        params = {
            "search": search_string,
            "output_mode": "json"
        }
        # Exceute query.
        response = requests.get(url, auth=(SPLUNK_USER, SPLUNK_PASSWD), params=params, verify=False)
        # Log response.
        logger.info("response code: {}".format(response.status_code))
        logger.info("response JSON: {}".format(response.text))
    except Exception as error:
        logger.error("cannot retrieve alert security: {}".format(str(error)))
        logger.exception(error)


def format_alert(alert_name, alert_results):
    """Format the alert string.

    Arguments:
        alert_name (str): Splunk E.S. alert name.
        alert_results (str): Path to the alert results.
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
    if len(sys.argv) < 9:
        alert = format_alert("ERROR - No results available for alert")
    else:
        for pos, arg in enumerate(sys.argv):
            logger.info("sys.argv[{}]: {}".format(pos, arg))
        logger.info("alert name: {}".format(sys.argv[4]))
        logger.info("alert results: {}".format(sys.argv[8]))
        alert = format_alert(sys.argv[4], sys.argv[8])
        severity = get_alert_severity(sys.argv[6])
    # Send alert.
    # send_syslog(alert)


if __name__ == "__main__":
    main()
