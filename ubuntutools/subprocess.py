"""Drop-in replacement for subprocess with better defaults

This is an API-compatible replacement for the built-in subprocess
module whose defaults better line up with our tastes.

In particular, it:
 - Adds support for the restore_signals flag if subprocess itself
   doesn't support it
 - Adds support for the encoding flag if subprocess itself doesn't
   support it
 - Defaults close_fds to True
"""


from __future__ import absolute_import

import inspect
import codecs
import signal
import subprocess
import sys

from subprocess import PIPE, STDOUT, CalledProcessError

__all__ = ['Popen', 'call', 'check_call', 'check_output', 'CalledProcessError',
           'PIPE', 'STDOUT']


class Popen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('close_fds', True)
        if sys.version_info[0] >= 3:
            getargs = inspect.getfullargspec
            encoding = None
        else:
            getargs = inspect.getargspec
            encoding = kwargs.pop('encoding', None)

        if 'restore_signals' not in getargs(subprocess.Popen.__init__)[0]:
            given_preexec_fn = kwargs.pop('preexec_fn', None)
            restore_signals = kwargs.pop('restore_signals', True)

            def preexec_fn():
                if restore_signals:
                    for sig in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
                        if hasattr(signal, sig):
                            signal.signal(getattr(signal, sig),
                                          signal.SIG_DFL)

                if given_preexec_fn:
                    given_preexec_fn()
            kwargs['preexec_fn'] = preexec_fn

        subprocess.Popen.__init__(self, *args, **kwargs)
        if encoding is not None:
            for channel in ('stdin', 'stdout', 'stderr'):
                fd = getattr(self, channel)
                if fd is not None:
                    setattr(self, channel, codecs.EncodedFile(fd, encoding))


# call, check_call, and check_output are copied directly from the
# subprocess module shipped with Python 2.7.1-5ubuntu2


def call(*popenargs, **kwargs):
    """Run command with arguments.  Wait for command to complete, then
    return the returncode attribute.

    The arguments are the same as for the Popen constructor.  Example:

    retcode = call(["ls", "-l"])
    """
    return Popen(*popenargs, **kwargs).wait()


def check_call(*popenargs, **kwargs):
    """Run command with arguments.  Wait for command to complete.  If
    the exit code was zero then return, otherwise raise
    CalledProcessError.  The CalledProcessError object will have the
    return code in the returncode attribute.

    The arguments are the same as for the Popen constructor.  Example:

    check_call(["ls", "-l"])
    """
    retcode = call(*popenargs, **kwargs)
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise CalledProcessError(retcode, cmd)
    return 0


def check_output(*popenargs, **kwargs):
    r"""Run command with arguments and return its output as a byte string.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> check_output(["ls", "-l", "/dev/null"])
    'crw-rw-rw- 1 root root 1, 3 Oct 18  2007 /dev/null\n'

    The stdout argument is not allowed as it is used internally.
    To capture standard error in the result, use stderr=STDOUT.

    >>> check_output(["/bin/sh", "-c",
    ...               "ls -l non_existent_file ; exit 0"],
    ...              stderr=STDOUT)
    'ls: non_existent_file: No such file or directory\n'
    """
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = Popen(stdout=PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise CalledProcessError(retcode, cmd, output=output)
    return output
