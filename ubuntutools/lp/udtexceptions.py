class PackageNotFoundException(BaseException):
    """Thrown when a package is not found"""

    pass


class SeriesNotFoundException(BaseException):
    """Thrown when a distroseries is not found"""

    pass


class PocketDoesNotExistError(Exception):
    """Raised when a invalid pocket is used."""

    pass


class ArchiveNotFoundException(BaseException):
    """Thrown when an archive for a distibution is not found"""

    pass


class AlreadyLoggedInError(Exception):
    """Raised when a second login is attempted."""

    pass


class ArchSeriesNotFoundException(BaseException):
    """Thrown when a distroarchseries is not found."""

    pass


class InvalidDistroValueError(ValueError):
    """Thrown when distro value is invalid"""

    pass
