import os
import sys
import json
import logging
import logging.handlers
import socket


PAYLOAD_TPL = "<133>[qradar-offense] [{alert_desc}] [{human_time}] [{attacker_ip}] [{target_ip}] [{target_user}] [{alert_name}]"


def format_payload(name, results):
    """Format a Splunk alerts results set into a suitable Syslog message.

    Arguments:
        name (str): Alert name.
        results (dict): Splunk alert results.
    """
    results["alert_name"] = name
    return PAYLOAD_TPL.format(**results)


def send_syslog(host, port, payload):
    """Send alert as a Syslog message.

    Arguments:
        host (str): Destination host address.
        port (int): Destination port.
        payload (str): Full syslog message.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(str(payload), (host, port))


def main():
    # Loads script payload.
    js = json.loads(sys.stdin.read())
    # Setup logfile.
    logfile = js.get("logfile", "{}.log".format(os.path.basename(sys.argv[0])))
    logger = logging.getLogger("arcsight_syslog")
    logger.addHandler(logging.handlers.RotatingFileHandler(logfile, mode='a', maxBytes=1000000, backupCount=1))
    logformatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(funcName)s() - %(message)s")
    for handler in logger.handlers:
        handler.setFormatter(logformatter)
    logger.setLevel(logging.INFO)
    # Run.
    logger.info("script executed with: {}".format(sys.argv))
    logger.info("json payload: {}".format(json.dumps(js, indent=2)))
    # Process alert.
    try:
        # Setup `send_syslog` parameters.
        logger.info("extracting syslog configuration")
        syslog_host = str(js["configuration"]["syslog_host"])
        syslog_port = int(js["configuration"]["syslog_port"])
        # Format and send alert.
        logger.info("formatting alert")
        payload = format_payload(name=js["search_name"], results=js["result"])
        logger.info("sending alert (host='{}', port={}, payload='{}')".format(syslog_host, syslog_port, payload))
        send_syslog(host=syslog_host, port=syslog_port, payload=payload)
    except Exception as error:
        logger.exception(error)



if __name__ == "__main__":
    main()
