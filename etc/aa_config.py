# You shouldn't change these three lines unless you know what you are doing
CONFIG = 'pysaml_config'                # PySAML2 Configuration file name
IDENTITY_CACHE = "identity_cache"
STATE_CACHE = "state_cache"
METADATA_FILE = "/usr/local/etc/moonshot/metadata.xml"

DEBUG = 0

# Should the SP sign the request
SIGN = False

# This depends on the AA configuration
SP_NAME_QUALIFIER = ""
NAME_QUALIFIER = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

# This is necessary to pick information about the right AA from the metadata
# file. This must be the entity ID of the AA not the endpoint
ATTRIBUTE_AUTHORITY = "http://localhost:8088/"

# Attribute filters per service@hostname
# the key are GSS-Acceptor-Service-Name+':'+GSS-Acceptor-Host-Name
# and the attribute names are the so called friendly-names

ATTRIBUTE_FILTER = {
    "ldap:example.com": ["email", "givenName", "surname"],
}
