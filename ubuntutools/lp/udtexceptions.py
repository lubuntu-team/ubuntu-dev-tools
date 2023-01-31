class PackageNotFoundException(BaseException):
    """Thrown when a package is not found"""


class SeriesNotFoundException(BaseException):
    """Thrown when a distroseries is not found"""


class PocketDoesNotExistError(Exception):
    """Raised when a invalid pocket is used."""


class ArchiveNotFoundException(BaseException):
    """Thrown when an archive for a distibution is not found"""


class AlreadyLoggedInError(Exception):
    """Raised when a second login is attempted."""


class ArchSeriesNotFoundException(BaseException):
    """Thrown when a distroarchseries is not found."""


class InvalidDistroValueError(ValueError):
    """Thrown when distro value is invalid"""
