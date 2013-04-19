#! /usr/bin/env python
#
# Copyright 2011 Roland Hedberg <roland.hedberg@adm.umu.se>
#
# $Id$
from saml2 import BINDING_SOAP

__author__ = 'rolandh'

import radiusd
import sys
import traceback
from saml2.client import Saml2Client
from saml2.s_utils import sid
from saml2.response import attribute_response

# Where's the configuration
#CONFIG_DIR = "/usr/local/etc/moonshot"
#sys.path.insert(0, CONFIG_DIR)

import config

# Globals
CLIENT = None
MAX_STRING_LENGTH = 247


def eq_len_parts(txt, delta=250):
    res = []
    n = 0
    strlen = len(txt)
    while n <= strlen:
        m = n + delta
        res.append("".join(txt[n:m]))
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
        log(radiusd.L_ERR, txt)  # Not absolutely correct just an approximation


#noinspection PyUnusedLocal
def instantiate(p):
    """Module Instantiation.  0 for success, -1 for failure.
    p is a dummy variable here.
    """
    global CLIENT

    log = LOG()
    try:
        CLIENT = Saml2Client(identity_cache=config.IDENTITY_CACHE,
                             state_cache=config.STATE_CACHE,
                             config_file=config.CONFIG)
    except Exception, err:
        # Report the error and return -1 for failure.
        # xxx A more advanced module would retry the database.
        exception_trace("instantiate SAML2Client", err, LOG())
        return -1

    log.info('SAML Client initialized')
    log.info('SP initialized')

    return 0


def attribute_query(cls, subject_id, destination, attribute=None, name_id=None,
                    sp_name_qualifier=None, name_qualifier=None,
                    nameid_format=None, sign=False):
    """ Does a attribute request to an attribute authority, this is
    by default done over SOAP. Other bindings could be used but are not
    supported right now.

    :param subject_id: The identifier of the subject
    :param destination: To whom the query should be sent
    :param attribute: A dictionary of attributes and values that is asked for
    :param name_id: A NameID instance that describes the entity the information
        is asked for.
    :param sp_name_qualifier: The unique identifier of the
        service provider or affiliation of providers for whom the
        identifier was generated.
    :param name_qualifier: The unique identifier of the identity
        provider that generated the identifier.
    :param nameid_format: The format of the name ID
    :param sign: Whether the request should be signed or not
    :return: The Assertion
    """

    global CLIENT

    logger = LOG()
    session_id = sid()

    if not name_id:
        args = {
            "subject_id": subject_id,
            "sp_name_qualifier": sp_name_qualifier,
            "format": nameid_format,
            "name_qualifier": name_qualifier
        }
        if not name_qualifier and not sp_name_qualifier:
            args["sp_name_qualifier"] = cls.config.entityid
    else:
        args = {"name_id": name_id}

    if sign:
        args["sign_prepare"] = True

    request = cls.create_attribute_query(destination,
                                         attribute=attribute,
                                         message_id=session_id,
                                         **args)

    try:
        args = CLIENT.use_soap(request, destination, sign=sign)
        response = CLIENT.send(**args)
    except Exception, exc:
        exception_trace("SoapClient exception", exc, logger)
        return None

    if response:
        try:
            _resp = CLIENT.parse_attribute_query_response(response.text,
                                                          BINDING_SOAP)
        except Exception, exc:
            exception_trace("response error", exc, logger)
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
    logger = LOG()

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
    logger.debug("Working on behalf of: %s" % _srv)

    # Find the endpoint to use
    _binding, location = CLIENT.pick_binding(
        "attribute_service", [BINDING_SOAP], "attribute_authority",
        entity_id=config.ATTRIBUTE_AUTHORITY)

    logger.debug("location: %s" % location)

    # Build and send the attribute query
    _attribute_assertion = attribute_query(
        CLIENT, userName, location, sp_name_qualifier=config.SP_NAME_QUALIFIER,
        name_qualifier=config.NAME_QUALIFIER,
        nameid_format=config.NAMEID_FORMAT, sign=config.SIGN)

    if _attribute_assertion is None:
        return radiusd.RLM_MODULE_FAIL

    if _attribute_assertion is False:
        logger.debug("IdP returned: %s" % CLIENT.server.error_description)
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

    logger.debug("Assertion: %s" % _attribute_assertion)

    # Log the success
    logger.debug('user accepted: %s' % (userName, ))

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
    print post_auth((('User-Name', '"roland"'), ('User-Password', '"dianakra"')))
