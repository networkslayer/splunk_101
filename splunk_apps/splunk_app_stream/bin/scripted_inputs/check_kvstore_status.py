import logging.handlers
import os
import sys
import splunk

import splunk.appserver.mrsparkle.lib.util as app_util
import splunk_app_stream.utils.stream_kvstore_utils
import splunk_app_stream.utils.stream_utils


SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
CHECK_KVSTORE_STATUS_LOG_FILENAME = os.path.join(SPLUNK_HOME,'var','log','splunk','splunk_app_stream_check_kvstore_status.log')
STREAM_APP_RELOAD = '/services/apps/local/splunk_app_stream?refresh=true'
STREAM_URI='/en-US/custom/splunk_app_stream/streams'

logger = logging.getLogger('check_kvstore_status')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(CHECK_KVSTORE_STATUS_LOG_FILENAME, maxBytes=1024000, backupCount=5)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

def checkStreamsRESTCall(sessionToken):
    logger.info('check_kvstore_status:checkStreamsRESTCall')
    web_uri=splunk_app_stream.utils.stream_utils.get_web_uri()
    stream_uri=web_uri + STREAM_URI
    logger.info('check_kvstore_status: trying to get streams from Splunk App for Stream using  rest call  %s', stream_uri)
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            stream_uri,
            sessionToken,
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT)
        if serverResponse and 'status' in serverResponse:
            logger.info('check_kvstore_status::checkStreamsRESTCall: returned  %s', serverResponse['status'])
            return serverResponse['status'] == '200'
        return False
    except Exception as e:
        logger.exception("check_kvstore_status: failed to retrieve streams from Splunk App for Stream")
        return False

def reloadStreamApp(sessionToken):
    logger.info('check_kvstore_status: reloading Splunk App for Stream...')
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
              app_util.make_url_internal(STREAM_APP_RELOAD),
              sessionToken,
              postargs=None,
              method='GET',
              raiseAllErrors=True,
              proxyMode=False,
              rawResult=None,
              jsonargs=None,
              timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT)
    except Exception as e:
        logger.exception("check_kvstore_status: failed to reload Splunk App for Stream")

if __name__ == '__main__':
    logger.info('starting check_kvstore_status')
    session_key = sys.stdin.readlines()[0].strip()
    if session_key:
        try:
            cur_status=splunk_app_stream.utils.stream_kvstore_utils.get_kv_store_status(session_key)
            logger.info('check_kvstore_status:get_kv_store_status returned %s',cur_status)
            #if kvstore status has transitioned to ready and stream REST call fails, reload stream app 
            if cur_status=='ready' and not checkStreamsRESTCall(session_key):
               logger.info('check_kvstore_status: failed to get streams - need to reload stream_app')
               reloadStreamApp(session_key)
        except Exception as e:
            logger.exception(e)
