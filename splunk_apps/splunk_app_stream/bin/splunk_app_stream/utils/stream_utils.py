import json
import logging
import os
import time

from collections import OrderedDict
from xml.dom import minidom

try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

try:
    from ConfigParser import RawConfigParser
except ImportError:
    from configparser import RawConfigParser


import splunk
import splunk.clilib.cli_common
from splunk.clilib import cli_common as cli
import splunk.appserver.mrsparkle.lib.util as util


currentDir = os.path.dirname(__file__)
appsMetaFile = os.path.join(util.get_apps_dir(), 'splunk_app_stream', 'local') + os.sep + "apps"

pingUrl = '/en-US/custom/splunk_app_stream/ping?refresh=true'
webUri = None

def readAsJson(resourceLocation):
    try:
        f = open( resourceLocation, 'r' )
    except:
        return 'NotFound'
    else:
        data = f.read()
        jsonResource = json.loads(data, object_pairs_hook=OrderedDict)
        f.close()
        return jsonResource

def writeAsJson(resourceLocation, jsonData):
    try:
        f = open( resourceLocation, 'w+' )
    except:
        return 'NotFound'
    else:
        updateAppsMeta()
        #jsonData["updatedBy"] = request.user.username
        #jsonData["dateLastUpdated"] = time.asctime(time.gmtime(time.time()))
        f.write(json.dumps(jsonData, sort_keys=True, indent=2))
        f.close()
        return 'Found'

def writeListAsJson(resourceLocation, jsonData):
    try:
        f = open( resourceLocation, 'w+' )
    except:
        return 'NotFound'
    else:
        updateAppsMeta()
        f.write(json.dumps(jsonData, sort_keys=True, indent=2))
        f.close()
        return 'Found'

def updateField(jsonData, req_json_data, field):
    try:
        jsonData[field] = req_json_data[field]
    except:
        pass

def updateListDictField(jsonData, req_json_data_dict, field, listField, itemIndex):
    try:
        jsonData[listField][itemIndex][field] = req_json_data_dict[field]
    except:
        pass

def createDir(dirName):
    d = os.path.dirname(dirName)
    if not os.path.exists(d):
        logger.debug("create dir %s", dirName)
        os.makedirs(d)

def updateAppsMeta():
    try:
        f = open( appsMetaFile, 'w+' )
    except:
        return 'NotFound'
    else:
        # FIXME, this is really bad
        import splunk_app_stream.models.ping as ping

        jsonData = {}
        jsonData["dateLastUpdated"] = int(round(time.time() * 1000))
        jsonData["version"] = getAppVersion()
        f.write(json.dumps(jsonData, sort_keys=True, indent=2))
        # update the cached apps meta to avoid rest_handler access
        ping.Ping.update_cache(jsonData)
        f.close()
        return jsonData

def getAppVersion():
    appConf = os.path.join(util.get_apps_dir(), 'splunk_app_stream', 'default') + "/app.conf"
    ini_str = '[comments]\n' + open(appConf, 'r').read()
    ini_fp = StringIO(ini_str)
    config = RawConfigParser(allow_no_value=True)
    config.readfp(ini_fp)
    version = config.get('launcher', 'version')
    logger.debug("utils::getAppVersion:: %s", version)
    return version

def isCloudInstance():
    try:
        return cli.getConfStanza('cloud', 'deployment')
    except Exception as e:
        logger.exception(e)
    return False

'''
    Here we are looking for the cloud.conf file inside the splunk_app_stream/local directory, 
    if this file is found then we will try to read it and find hecEndpoint & serverFQDN inside it, 
    if both these things are found then it means that it is CO2 classic instance
'''
def isClassicCloudInstance():
    LOCAL_DIR = os.path.join(util.get_apps_dir(), 'splunk_app_stream', 'local')
    DEFAULT_DIR = os.path.join(util.get_apps_dir(), 'splunk_app_stream', 'default')
    try:
        if os.path.exists(LOCAL_DIR) or os.path.exists(DEFAULT_DIR):
            cloudConf = os.path.join(LOCAL_DIR, "cloud.conf")

            # Look into the default folder as well
            if not os.path.isfile(cloudConf):
                cloudConf = os.path.join(DEFAULT_DIR, "cloud.conf")

            try:
                if os.path.isfile(cloudConf):
                    file = open(cloudConf, 'r')
                    Lines = file.readlines()

                    count = 0
                    for line in Lines:
                        val = (line.strip()).split("=")[0].strip()
                        if "hecEndpoint" == val or "serverFQDN" == val:
                            count += 1

                    if count == 2:
                        return True
            except Exception as e:
                logger.exception(e)
            return False
        return False

    except Exception as e:
        logger.exception(e)
    return False   

def get_username(sessionKey):
    try:
        uri = 'authentication/current-context?output_mode=json'
        serverResponse, serverContent = splunk.rest.simpleRequest(
            util.make_url(uri, translate=False, relative=True, encode=False),
            sessionKey,
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT
        )

        jsonResp = json.loads(serverContent)
        user_name = jsonResp["entry"][0]["content"]["username"]
        logger.debug("User Name :: %s", user_name)
        return user_name
    except Exception as e:
        logger.exception("failed to get user name")
        return None


def setup_rotating_log_file():
    try:
        SPLUNK_HOME_LOG_PATH = util.make_splunkhome_path(["var", "log", "splunk"])
        LOG_FILENAME = ''
        # check to see if the SPLUNK_HOME based log path exists
        if not os.path.exists(SPLUNK_HOME_LOG_PATH):
            # check to see if the relative path based log path exists
            SPLUNK_BASE = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', '..', '..', '..'))
            SPLUNK_BASE_LOG_PATH = os.path.join(SPLUNK_BASE, 'var', 'log', 'splunk')
            if not os.path.exists(SPLUNK_BASE_LOG_PATH):
                # disable logging with noop handler
                logger.addHandler(logging.NullHandler())
                return logger
            else:
                LOG_FILENAME = os.path.join(SPLUNK_BASE_LOG_PATH, 'splunk_app_stream.log')
        else:
            LOG_FILENAME = os.path.join(SPLUNK_HOME_LOG_PATH, 'splunk_app_stream.log')

        # valid log file path exists and rotate at 10 MB
        file_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=10240000, backupCount=10)
        LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(name)s:%(lineno)d - %(message)s"
        file_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        return file_handler
    except:
        # disable logging with noop handler
        return logging.NullHandler()

def setup_logger(modulename):
    logger = logging.getLogger(modulename)
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(logging.INFO)
    logger.addHandler(rotating_log_file)
    return logger

def prettify(xml_elem):
    rough_string = ET.tostring(xml_elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="\t")

def get_stream_app_name():
    apps_dir = util.get_apps_dir()
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.basename(os.path.split(curr_dir.replace(apps_dir, ''))[0])

def get_stream_ids(dir):
    if os.path.exists(dir):
        return filter(lambda x: not x.startswith('.'), next(os.walk(dir))[2])
    else:
        return None

def is_file_modified(file_name, app_last_updated_time):
    if os.path.exists(file_name):
        file_modified_time = int(round(os.stat(file_name).st_mtime * 1000))
        logger.debug("file %s mod_time %s app_last_updated_time %s " % (file_name, file_modified_time, app_last_updated_time))
        if file_modified_time > app_last_updated_time:
            return True
        else:
            return False
    else:
        return False

# copied the gist of this function from gebWebUri() in cli_common.py 
def get_splunk_server():
    splunk_server = "localhost"
    if( "SPLUNK_BINDIP" in os.environ ):
        splunk_server = os.environ["SPLUNK_BINDIP"]
        if splunk_server.find(":") >= 0:
            splunk_server = "[" + splunk_server + "]"
    return splunk_server

def get_web_uri():
    try:
        web_configs = util.splunk_to_cherry_cfg('web','settings')
        
        is_ssl_enabled = web_configs['enableSplunkWebSSL']
        splunk_port_number = web_configs['httpport']
        splunk_protocol = "http://"
        if is_ssl_enabled:
            splunk_protocol = "https://"
        
        web_uri = splunk_protocol + get_splunk_server() + ':' + str(splunk_port_number)
        
        return web_uri
    
    except Exception:
        logger.exception("Failed to get the web configs")
    return None

# to update the chached apps meta in cherrypy controller when there is chane made via rest_handler
def refresh_ping_cache():
    global webUri, pingUrl
    if webUri == None:
        # Call getWebUri to get the current Splunk web settings  (http/https, url, and port)
        webUri = get_web_uri()
        if not webUri:
            logger.error("Unable to retrieve webUri")
            return None
    uri = webUri + pingUrl
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            uri,
            '',
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT
        )
        return json.loads(serverContent)
    except Exception as e:
        logger.exception("failed to refresh ping cache")
        return None

# sort dict and list for object comparison
def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

def validate_streamfwd_auth(header_auth_key):
    uri = "/services/splunk_app_stream/validatestreamfwdauth" 
    try:
        serverResponse, serverContent = splunk.rest.simpleRequest(
            util.make_url_internal(uri),
            getargs={'auth_key':header_auth_key, 'output_mode':'json'},
            sessionKey='',
            postargs=None,
            method='GET',
            raiseAllErrors=True,
            proxyMode=False,
            rawResult=None,
            jsonargs=None,
            timeout=splunk.rest.SPLUNKD_CONNECTION_TIMEOUT - 1
        )
        jsonResp = json.loads(serverContent)
        auth_success = jsonResp["entry"][0]["content"]
        return auth_success
    except Exception as e:
        logger.exception("Error getting the streamfwd auth, return streamfwd auth is disabled")
        return True
        
def extract_auth_key(request, args):
    # check for auth key
    auth_key = None
    if 'systemAuth' in request:
        auth_key_string = 'X-SPLUNK-APP-STREAM-KEY'
        if auth_key_string.lower() in request['headers']:
            auth_key = request['headers'][auth_key_string.lower()]
        elif auth_key_string in args:
            auth_key = args[auth_key_string]
    return auth_key


# Initialize the rotating log file which we will use for multiple loggers.
rotating_log_file = setup_rotating_log_file()

# Initialize the first such logger.
logger = setup_logger('streams_utils')
