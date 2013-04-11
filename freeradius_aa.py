#! /usr/bin/env python
#
# Copyright 2011 Roland Hedberg <roland.hedberg@adm.umu.se>
#
# $Id$

__author__ = 'rolandh'

import radiusd
import sys
import traceback
from saml2 import soap
from saml2.client import Saml2Client
from saml2.s_utils import sid
from saml2.response import attribute_response
from saml2.sigver import pre_signature_part

# Where's the configuration
CONFIG_DIR = "/usr/local/etc/moonshot"
sys.path.insert(0, CONFIG_DIR)

import config

# Globals
CLIENT = None
HTTP = None
MAX_STRING_LENGTH = 247

def eq_len_parts(str, delta=250):
    res = []
    n = 0
    strlen = len(str)
    while n <= strlen:
        m = n + delta
        res.append("".join(str[n:m]))
        n = m
    return res

def exception_trace(tag, exc, log):
    message = traceback.format_exception(*sys.exc_info())
    log.error("[%s] ExcList: %s" % (tag, "".join(message),))
    log.error("[%s] Exception: %s" % (tag, exc))

def log(level, s):
    """Log function."""
    radiusd.radlog(level, 'freeradius_aa.py: ' + s)


class LOG(object):
    def info(self, txt):
        log(radiusd.L_INFO, txt)

    def error(self, txt):
        log(radiusd.L_ERR, txt)

    def debug(self, txt):
        log(radiusd.L_DBG, txt)

    def warning(self, txt):
        log(radiusd.L_ERR, txt) # Not absolutely correct just an approximation

#noinspection PyUnusedLocal
def instantiate(p):
    """Module Instantiation.  0 for success, -1 for failure.
    p is a dummy variable here.
    """
    global CLIENT
    global HTTP

    try:
        CLIENT = Saml2Client(debug=config.DEBUG,
                             identity_cache=config.IDENTITY_CACHE,
                             state_cache=config.STATE_CACHE,
                             config_file=config.CONFIG)
        if not CLIENT.logger:
            CLIENT.logger = LOG()
        _log = CLIENT.logger
    except Exception, err:
        # Report the error and return -1 for failure.
        # xxx A more advanced module would retry the database.
        exception_trace("instantiate SAML2Client", err, LOG())
        return -1

    try:
        _certs = CLIENT.config.ca_certs
        if _certs:
            _disable = False
        else:
            _disable = True
    except (KeyError, AttributeError):
        _certs = ""
        _disable = True

    log(radiusd.L_INFO, 'SAML Client initialized')
    try:
        HTTP = soap.SOAPClient("", # No default URL
                               log=_log,
                               ca_certs=_certs,
                               disable_ssl_certificate_validation=_disable)
    except Exception, err:
        exception_trace("instantiate SOAPClient", err, _log)
        return -1

    log(radiusd.L_INFO, 'SP initialized')

    return 0


def attribute_query(cls, subject_id, destination, issuer_id=None,
                    attribute=None, sp_name_qualifier=None, name_qualifier=None,
                    nameid_format=None, log=None, sign=False):
    """ Does a attribute request to an attribute authority, this is
    by default done over SOAP. Other bindings could be used but are not
    supported right now.

    :param subject_id: The identifier of the subject
    :param destination: To whom the query should be sent
    :param issuer_id: Who is sending this query
    :param attribute: A dictionary of attributes and values that is asked for
    :param sp_name_qualifier: The unique identifier of the
        service provider or affiliation of providers for whom the
        identifier was generated.
    :param name_qualifier: The unique identifier of the identity
        provider that generated the identifier.
    :param nameid_format: The format of the name ID
    :param log: Function to use for logging
    :param sign: Whether the request should be signed or not
    :return: The Assertion
    """

    if log is None:
        log = cls.logger

    session_id = sid()
    issuer = cls.issuer(issuer_id)

    if not name_qualifier and not sp_name_qualifier:
        sp_name_qualifier = cls.config.entityid

    request = cls.create_attribute_query(session_id, subject_id,
                                         destination, issuer, attribute,
                                         sp_name_qualifier,
                                         name_qualifier,
                                         nameid_format=nameid_format)

    #    soapclient = HTTP.send(destination, cls.config.key_file,
    #                           cls.config.cert_file)

    if sign:
        request.signature= pre_signature_part(request.id, cls.sec.my_cert, 1)

    try:
        if sign:
            response = HTTP.send(request, path=destination, sign=True,
                                 sec=cls.sec)
        else:
            response = HTTP.send(request, path=destination)
    except Exception, exc:
        exception_trace("SoapClient exception", exc, log)
        return None

    if response:
        try:
            # synchronous operation
            return_addr = cls.config.endpoint('assertion_consumer_service')[0]
            aresp = attribute_response(cls.config, return_addr, log=log)
            aresp.allow_unsolicited = True
            aresp.asynchop = False
            #aresp.debug = True
        except Exception, exc:
            exception_trace("response error", exc, log)
            return None

        try:
            _resp = aresp.loads(response, False, HTTP.response).verify()
        except Exception, exc:
            exception_trace("response parsing error", exc, log)
            return None
        if _resp is None:
            if log:
                log.error("Didn't like the response")
            return None

        return _resp.assertion
    else:
        return None


def only_allowed_attributes(client, assertion, allowed):
    res = []
    _aconvs = client.config.attribute_converters

    for statement in assertion.attribute_statement:
        for attribute in statement.attribute:
            if attribute.friendly_name:
                fname = attribute.friendly_name
            else:
                fname = ""
                for acv in _aconvs:
                    if acv.name_form == attribute.name_form:
                        fname = acv._fro[attribute.name]

            if fname in allowed:
                res.append(attribute)

    return assertion


def post_auth(authData):
    """ Attribute aggregation after authentication
    This is the function that is accessible from the freeradius server core.
    
    :return: A 3-tuple
    """

    global CLIENT
    global HTTP

    # Extract the data we need.
    userName = None
    serviceName = ""
    hostName = ""
    #userPasswd = None

    for t in authData:
        if t[0] == 'User-Name':
            userName = t[1][1:-1]
        elif t[0] == "GSS-Acceptor-Service-Name":
            serviceName = t[1][1:-1]
        elif t[0] == "GSS-Acceptor-Host-Name":
            hostName = t[1][1:-1]

    _srv = "%s:%s" % (serviceName, hostName)
    log(radiusd.L_DBG, "Working on behalf of: %s" % _srv)


    # Find the endpoint to use
    location = CLIENT.config.attribute_services(
        config.ATTRIBUTE_AUTHORITY)[0].location
    log(radiusd.L_DBG, "location: %s" % location)

    # Build and send the attribute query
    sp_name_qualifier = config.SP_NAME_QUALIFIER
    name_qualifier = config.NAME_QUALIFIER
    nameid_format = config.NAMEID_FORMAT

    log(radiusd.L_DBG, "SP_NAME_QUALIFIER: %s" % sp_name_qualifier)
    log(radiusd.L_DBG, "NAME_QUALIFIER: %s" % name_qualifier)
    log(radiusd.L_DBG, "NAMEID_FORMAT: %s" % nameid_format)

    _attribute_assertion = attribute_query(CLIENT,
                                           userName,
                                           location,
                                           sp_name_qualifier=sp_name_qualifier,
                                           name_qualifier=name_qualifier,
                                           nameid_format=nameid_format,
                                           issuer_id=CLIENT.issuer(),
                                           log=LOG(),
                                           sign=config.SIGN)

    if _attribute_assertion is None:
        return radiusd.RLM_MODULE_FAIL

    if _attribute_assertion is False:
        log(radiusd.L_DBG, "IdP returned: %s" % HTTP.server.error_description)
        return radiusd.RLM_MODULE_FAIL

    # remove the subject confirmation if there is one
    _attribute_assertion.subject.subject_confirmation = []
    # Only allow attributes that the service should have
    try:
        _attribute_assertion = only_allowed_attributes(CLIENT,
                                                       _attribute_assertion,
                                                       config.ATTRIBUTE_FILTER[
                                                       _srv])
    except KeyError:
        pass

    log(radiusd.L_DBG, "Assertion: %s" % _attribute_assertion)

    # Log the success
    log(radiusd.L_DBG, 'user accepted: %s' % (userName, ))

    # We are adding to the RADIUS packet
    # We need to set an Auth-Type.

    # UKERNA, 25622; attribute ID is 132
    attr = "SAML-AAA-Assertion"
    #attr = "UKERNA-Attr-%d" % 132
    #attr = "Vendor-%d-Attr-%d" % (25622, 132)
    restup = (tuple([(attr, x) for x in eq_len_parts(
        "%s" % _attribute_assertion, MAX_STRING_LENGTH)]))

    return radiusd.RLM_MODULE_UPDATED, restup, None


# Test the modules
if __name__ == '__main__':
    instantiate(None)
    #    print authorize((('User-Name', '"map"'), ('User-Password', '"abc"')))
    print post_auth((('User-Name', '"roland"'), ('User-Password', '"one"')))
