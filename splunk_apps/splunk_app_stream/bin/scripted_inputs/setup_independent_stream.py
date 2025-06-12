import json
import logging.handlers
import os
import sys

from distutils.version import LooseVersion

import splunk
import splunk.appserver.mrsparkle.lib.util as app_util

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
INSTALLER_LOG_FILENAME = os.path.join(SPLUNK_HOME,'var','log','splunk','stream_installer.log')
logger = logging.getLogger('stream_installer')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(INSTALLER_LOG_FILENAME, maxBytes=1024000, backupCount=5)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

SERVER_INFO_URI = 'services/server/info'
HTTPINPUT_URI = 'services/data/inputs/http'
HTTPINPUT_STREAMFWD_URI = HTTPINPUT_URI + '/streamfwd'

# Return True if splunk support HEC
def is_hec_supported(token):
    # Check splunk version
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            app_util.make_url_internal(SERVER_INFO_URI + '?output_mode=json'),
            token,
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT
        )

        jsonResp = json.loads(serverContent)

        thisVersion = LooseVersion(jsonResp['generator']['version'])
        hecVersion = LooseVersion("6.3")

        return hecVersion <= thisVersion

    except Exception as e:
        logger.exception(e)

    return False

# Check if 'http://streamfwd' exists in HTTP input.
def input_streamfwd_exist(token):
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            app_util.make_url_internal(HTTPINPUT_STREAMFWD_URI + '?output_mode=json'),
            token,
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=True,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT
        )

        # Coulnd't find the resource, and get 404 Not Found
        if serverResponse['status'] == '404':
            return False
        # Some other exception, raise
        elif serverResponse['status'] != '200':
            raise splunk.RESTException(serverResponse.status, serverResponse.messages)

        return True

    except Exception as e:
        logger.exception(e)
    
    return False

# Create "streamfwd" HTTP input
def create_input_streamfwd(token):
    # Coulnd't find the resource, and get 404 Not Found
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            app_util.make_url_internal(HTTPINPUT_URI + '?output_mode=json'),
            token,
            postargs={"name":"streamfwd"},
            method='POST',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT
        )
        logger.info("Create HTTP input for stream forwarder")

    except Exception as e:
        logger.exception(e)


if __name__ == '__main__':

    token = sys.stdin.readlines()[0]
    token = token.strip()

    logger.info("Setting up HTTP input for Stream Forwarder...")

    if is_hec_supported(token):
        if input_streamfwd_exist(token):
            logger.info("HTTP input for Stream Forwarder already exists")
        else:
            create_input_streamfwd(token)
    else:
        logger.info("HTTP Event collector is not supported on this Splunk Version")






