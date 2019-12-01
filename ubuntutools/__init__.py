# -*- coding: utf-8 -*-
#
# Ubuntu Development Tools
# https://launchpad.net/ubuntu-dev-tools

import logging


def _loggingBasicConfig(**kwargs):
    '''Set log level to INFO and define log format to use.'''
    if 'level' not in kwargs:
        kwargs['level'] = logging.INFO
    if 'format' not in kwargs:
        kwargs['format'] = '%(message)s'
    logging.basicConfig(**kwargs)


def getLogger(name=None):
    '''Get standard Python logging.Logger with some ubuntutools defaults.'''
    _loggingBasicConfig()
    return logging.getLogger(name)
