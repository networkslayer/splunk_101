
import ta_tenable_import_declare

import splunk.admin as admin
from splunktaucclib.rest_handler import validator
import re
from splunktaucclib.rest_handler import base, normaliser
from splunktalib.common import util

util.remove_http_proxy_env_vars()
class CheckValidation(validator.Validator):
    msg = "Url format is incorrect or does not start with https."
    def validate(self, value, data):
        if not value or not re.match(r"^https\://[\w\-\./%\&\?]+(?::\d{1,5})?$", value):
            return False
        return True

class Servers(base.BaseModel):
    """REST Endpoint of Server in Splunk Add-on UI Framework.
    """
    rest_prefix = 'ta_tenable'
    endpoint = "configs/conf-tenable_sc_servers"
    requiredArgs = {'url', 'username', 'password'}
    optionalArgs = {'release_session', 'ingest_only_completed_scans'}
    defaultVals = {'release_session': 0, 'ingest_only_completed_scans': False}
    encryptedArgs = {'password'}
    cap4endpoint = ''
    cap4get_cred = ''
    url_validation_object = CheckValidation()
    validators = {'url': url_validation_object}


if __name__ == "__main__":
    admin.init(base.ResourceHandler(Servers), admin.CONTEXT_APP_AND_USER)
