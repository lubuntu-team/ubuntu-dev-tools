# -*- coding: utf-8 -*-
#
# Ubuntu Development Tools
# https://launchpad.net/ubuntu-dev-tools

import logging
import sys


def getLogger():
    ''' Get the logger instance for this module

    Quick guide for using this or not: if you want to call ubuntutools
    module code and have its output print to stdout/stderr ONLY, you can
    use the logger this creates. You can also log directly to this logger
    from your own code to send output to stdout/stderr.

    This creates the ubuntutools module-level logger, and sets some default
    values for formatting and levels, and directs INFO-level logs messages to
    stdout and logs higher than INFO to stderr. The logger's level may be
    adjusted to show more logs (e.g. DEBUG) or less (e.g. WARNING, to suppress
    all INFO messages).

    Without calling this module, the ubuntutools logs will propagate up to
    higher level loggers (possibly the root logger) and be handled by them.
    Note that the default for python logging is to print WARNING and above
    logs to stderr.

    Note if any code calls this method, the ubuntutools module-level logger
    will no longer propagate ubuntutools log message up to higher level
    loggers.

    This should only be used by runnable scripts provided by the
    ubuntu-dev-tools package, or other runnable scripts that want the behavior
    described above.
    '''
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    fmt = logging.Formatter('%(message)s')

    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(fmt)
    stdout_handler.addFilter(lambda r: r.levelno <= logging.INFO)
    logger.addHandler(stdout_handler)

    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    stdout_handler.setFormatter(fmt)
    stderr_handler.setLevel(logging.INFO+1)
    logger.addHandler(stderr_handler)

    return logger
