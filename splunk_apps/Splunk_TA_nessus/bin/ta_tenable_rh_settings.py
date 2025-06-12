"""Test global setting REST handler
"""

import ta_tenable_import_declare

import splunk.admin as admin
from splunk import ResourceNotFound

from splunktaucclib.rest_handler import base, multimodel, normaliser, validator
from splunktaucclib.rest_handler.cred_mgmt import CredMgmt
from splunktaucclib.rest_handler.error_ctl import RestHandlerError as RH_Err
from splunktalib.common import util

util.remove_http_proxy_env_vars()


class NessusCredMgmt(CredMgmt):
    def context(self, stanzaName, data=None):
        return ('Splunk_TA_nessus', '__Splunk_TA_nessus_proxy__', '', )


class NessusSettingsHandler(multimodel.MultiModelRestHandler):
    def decode(self, name, ent):
        """Decode data before return it.

        :param name:
        :param ent:
        :return:
        """
        import copy
        ent_cred = copy.deepcopy(ent)
        try:
            ent_cred = self._cred_mgmt.decrypt(self._makeStanzaName(name), ent_cred)
        except ResourceNotFound:
            RH_Err.ctl(1021,
                       msgx='endpoint=%s, item=%s' % (self.endpoint, name),
                       shouldPrint=False,
                       shouldRaise=False)
        # Automatically encrypt credential information
        # It is for manually edited *.conf file
        ent = self._auto_encrypt(name, ent, ent_cred)

        # decrypt
        if self.callerArgs.data.get('--get-clear-credential--') == ['1']:
            ent = ent_cred
        else:
            ent = {key: val for key, val in ent.iteritems()
                   if key not in self.encryptedArgs}

        # Adverse Key Mapping
        ent = {k: v for k, v in ent.iteritems()}
        keyMapAdv = {v: k for k, v in self.keyMap.items()}
        ent_new = {keyMapAdv[k]: vs for k, vs in ent.items() if k in keyMapAdv}
        ent.update(ent_new)

        # Adverse Value Mapping
        valMapAdv = {k: {y: x for x, y in m.items()}
                     for k, m in self.valMap.items()}
        ent = {k: (([(valMapAdv[k].get(v) or v) for v in vs]
                    if isinstance(vs, list) else (valMapAdv[k].get(vs) or vs))
                   if k in valMapAdv else vs)
               for k, vs in ent.items()}

        # normalize
        ent = self.normalize(ent)

        # filter undesired arguments & handle none value
        return {k: ((str(v).lower() if isinstance(v, bool) else v)
                    if (v is not None and str(v).strip()) else '')
                for k, v in ent.iteritems()
                if k not in self.transientArgs and (
                    self.allowExtra or
                    k in self.requiredArgs or
                    k in self.optionalArgs or
                    k in self.outputExtraFields)
                }

    def _need_encrypt(self, key, ent, ent_cred):
        val = ent.get(key, '')
        if key not in self.encryptedArgs or val == CredMgmt.PASSWORD_MASK:
            return False
        val_cred = ent_cred.get(key, '')
        if (val == '' or val is None) and (val_cred == '' or val_cred is None):
            return False
        return True

    def _auto_encrypt(self, name, ent, ent_cred):
        cred_data = {key: val for key, val in ent.iteritems()
                     if self._need_encrypt(key, ent, ent_cred)}
        if cred_data:
            ent = self._cred_mgmt.encrypt(self._makeStanzaName(name), ent)
            args = {key: val for key, val in ent.iteritems()
                    if key in self.encryptedArgs and
                    cred_data.get(key, '')}
            self.update(name, **args)
        return ent

    def setModel(self, name):
        """Get data model for specified object.
        """
        # get model for object
        if name not in self.modelMap:
            RH_Err.ctl(404,
                       msgx='object={name}'
                       .format(name=name,
                               handler=self.__class__.__name__))
        self.model = self.modelMap[name]

        # load attributes from model
        obj = self.model()
        attrs = {attr: getattr(obj, attr, None)
                 for attr in dir(obj)
                 if not attr.startswith('__') and attr not in
                 ('endpoint', 'rest_prefix', 'cap4endpoint', 'cap4get_cred')}
        self.__dict__.update(attrs)

        # credential fields
        self.encryptedArgs = set([(self.keyMap.get(arg) or arg)
                                  for arg in self.encryptedArgs])
        user, app = self.user_app()
        self._cred_mgmt = NessusCredMgmt(sessionKey=self.getSessionKey(),
                                         user=user,
                                         app=app,
                                         endpoint=self.endpoint,
                                         encryptedArgs=self.encryptedArgs, )
        return


class Logging(base.BaseModel):
    requiredArgs = {'loglevel'}
    defaultVals = {'loglevel': 'INFO'}
    validators = {'loglevel': validator.Enum(('DEBUG','WARN', 'INFO', 'ERROR'))}
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName')


class Proxy(base.BaseModel):
    requiredArgs = {'proxy_enabled', }
    optionalArgs = {'proxy_url', 'proxy_port', 'proxy_username',
                    'proxy_password', 'proxy_rdns', 'proxy_type'}
    encryptedArgs = {'proxy_username', 'proxy_password'}
    defaultVals = {
        'proxy_enabled': 'false',
        'proxy_rdns': 'false',
        'proxy_type': 'http',
    }
    validators = {
        'proxy_enabled': validator.RequiredIf(
            ('proxy_url', 'proxy_port'), ('1', 'true', 'yes')),
        'proxy_url': validator.AllOf(validator.Host(),
                                     validator.RequiredIf(('proxy_port', ))),
        'proxy_port': validator.AllOf(validator.Port(),
                                      validator.RequiredIf(('proxy_url', ))),
        'proxy_type':
        validator.Enum(("socks4", "socks5", "http", "http_no_tunnel")),
    }
    normalisers = {'proxy_enabled': normaliser.Boolean(), }
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName')


class TenableScSettings(base.BaseModel):
    defaultVals = {'disable_ssl_certificate_validation': '0', }
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName', 'disable_ssl_certificate_validation')


class Setting(multimodel.MultiModel):
    endpoint = "configs/conf-nessus"
    modelMap = {
        'nessus_loglevel': Logging,
        'nessus_proxy': Proxy,
        'tenable_sc_settings': TenableScSettings
    }
    cap4endpoint = ''
    cap4get_cred = ''


if __name__ == "__main__":
    admin.init(
        multimodel.ResourceHandler(Setting,
                                   handler=NessusSettingsHandler),
        admin.CONTEXT_APP_AND_USER, )
