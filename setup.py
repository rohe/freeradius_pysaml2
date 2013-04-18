#!/usr/bin/env python

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__author__ = 'rolandh'


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(  # Distribution meta-data
    name="freeradius_pysaml2",
    version="0.1.0",
    description="FreeRadius python modules to be used in Moonshot",
    author="Roland Hedberg",
    author_email="roland.hedberg@adm.umu.se",
    license="MIT License",
    py_modules=['freeradius_aa', 'radiusd', "freeradius_ecp"],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    long_description=read('README'),
    data_files=[
        ('/usr/local/etc/moonshot',
         ['etc/config.py', 'etc/metadata.xml', "etc/pysaml_config.py"]),
        ('/usr/local/etc/moonshot/attributemaps',
         ['attributemaps/basic.py', 'attributemaps/saml_uri.py',
          'attributemaps/shibboleth_uri.py']),
        ('/usr/local/etc/moonshot/pki', ['pki/ssl.cert', 'pki/ssl.key'])],
    zip_safe=False,
    package_data={"etc": ["*.py", "*.xml"]},
    include_package_data=True
#    install_requires=[
#        'pysaml2'
#    ]
)
