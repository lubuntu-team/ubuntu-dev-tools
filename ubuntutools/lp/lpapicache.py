# -*- coding: utf-8 -*-
#
#   lpapicache.py - wrapper classes around the LP API implementing caching
#                   for usage in the ubuntu-dev-tools package
#
#   Copyright © 2009-2010 Michael Bienia <geser@ubuntu.com>
#               2011      Stefano Rivera <stefanor@ubuntu.com>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; either version 3
#   of the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   Please see the /usr/share/common-licenses/GPL file for the full text
#   of the GNU General Public License license.
#
#   Based on code written by Jonathan Davies <jpds@ubuntu.com>

import collections
import logging
import os
import re
from copy import copy
from urllib.error import URLError
from urllib.parse import urlparse

from debian.changelog import Changelog
from launchpadlib.errors import HTTPError
from launchpadlib.launchpad import Launchpad as LP
from lazr.restfulclient.resource import Entry

from ubuntutools.lp import api_version, service
from ubuntutools.lp.udtexceptions import (
    AlreadyLoggedInError,
    ArchiveNotFoundException,
    ArchSeriesNotFoundException,
    PackageNotFoundException,
    PocketDoesNotExistError,
    SeriesNotFoundException,
)
from ubuntutools.misc import (
    DEFAULT_POCKETS,
    DEFAULT_STATUSES,
    POCKETS,
    STATUSES,
    download_text,
    host_architecture,
)
from ubuntutools.version import Version

Logger = logging.getLogger(__name__)


__all__ = [
    "Archive",
    "BinaryPackagePublishingHistory",
    "Build",
    "Distribution",
    "DistributionSourcePackage",
    "DistroSeries",
    "DistroArchSeries",
    "Launchpad",
    "PackageUpload",
    "PersonTeam",
    "Project",
    "ProjectSeries",
    "SourcePackagePublishingHistory",
]


class _Launchpad(object):
    """Singleton for LP API access."""

    def login(self, service=service, api_version=api_version):
        """Enforce a non-anonymous login."""
        if not self.logged_in:
            self.__lp = LP.login_with("ubuntu-dev-tools", service, version=api_version)
            # Unfortunately launchpadlib may 'login' using cached
            # credentials, without actually verifying if the credentials
            # are valid; which can lead to this 'login' not actually
            # logging in.
            # So, this forces actual LP access here, to force actual login.
            self.__lp.me
        else:
            raise AlreadyLoggedInError("Already logged in to Launchpad.")

    def login_anonymously(self, service=service, api_version=api_version):
        """Enforce an anonymous login."""
        if not self.logged_in:
            self.__lp = LP.login_anonymously("ubuntu-dev-tools", service, version=api_version)
        else:
            raise AlreadyLoggedInError("Already logged in to Launchpad.")

    def login_existing(self, lp):
        """Use an already logged in Launchpad object"""
        if not self.logged_in:
            self.__lp = lp
        else:
            raise AlreadyLoggedInError("Already logged in to Launchpad.")

    @property
    def logged_in(self):
        """Are we logged in?"""
        return "_Launchpad__lp" in self.__dict__

    def __getattr__(self, attr):
        if not self.logged_in:
            self.login_anonymously()
        return getattr(self.__lp, attr)

    def __call__(self):
        return self


Launchpad = _Launchpad()


class MetaWrapper(type):
    """
    A meta class used for wrapping LP API objects.
    """

    def __init__(cls, name, bases, attrd):
        super(MetaWrapper, cls).__init__(name, bases, attrd)
        if "resource_type" not in attrd:
            raise TypeError('Class "%s" needs an associated resource type' % name)
        cls._cache = dict()


class BaseWrapper(object, metaclass=MetaWrapper):
    """
    A base class from which other wrapper classes are derived.
    """

    resource_type = None  # it's a base class after all

    def __new__(cls, data):
        if isinstance(data, str) and data.startswith(str(Launchpad._root_uri)):
            # looks like a LP API URL
            # check if it's already cached
            cached = cls._cache.get(data)
            if cached:
                return cached

            # not cached, so try to get it
            try:
                data = Launchpad.load(data)
            except HTTPError:
                # didn't work
                pass

        if isinstance(data, Entry):
            (service_root, resource_type) = data.resource_type_link.split("#")
            if service_root == str(Launchpad._root_uri) and resource_type in cls.resource_type:
                # check if it's already cached
                cached = cls._cache.get(data.self_link)
                if not cached:
                    # create a new instance
                    cached = object.__new__(cls)
                    cached._lpobject = data
                    # and add it to our cache
                    cls._cache[data.self_link] = cached
                    Logger.debug("%s: %s" % (cls.__name__, data.self_link))
                    # add additional class specific caching (if available)
                    cache = getattr(cls, "cache", None)
                    if isinstance(cache, collections.abc.Callable):
                        cache(cached)
                return cached
            else:
                raise TypeError("'%s' is not a '%s' object" % (str(data), str(cls.resource_type)))
        else:
            # not a LP API representation, let the specific class handle it
            fetch = getattr(cls, "fetch", None)
            if isinstance(fetch, collections.abc.Callable):
                return fetch(data)
            else:
                raise NotImplementedError("Don't know how to fetch '%s' from LP" % str(data))

    def __call__(self):
        return self._lpobject

    def __getattr__(self, attr):
        return getattr(self._lpobject, attr)

    def __repr__(self):
        if hasattr(str, "format"):
            return "<{0}: {1!r}>".format(self.__class__.__name__, self._lpobject)
        else:
            return "<%s: %r>" % (self.__class__.__name__, self._lpobject)


class Distribution(BaseWrapper):
    """
    Wrapper class around a LP distribution object.
    """

    resource_type = "distribution"

    def __init__(self, *args):
        self._archives = dict()
        self._series_by_name = dict()
        self._series = dict()
        self._dev_series = None
        self._have_all_series = False

    def cache(self):
        self._cache[self.name] = self

    def _cache_series(self, series):
        """
        Add the DistroSeries to the cache if needed.
        """
        if series.version not in self._series:
            self._series_by_name[series.name] = series
            self._series[series.version] = series

    @classmethod
    def fetch(cls, dist):
        """
        Fetch the distribution object identified by 'dist' from LP.
        """
        if not isinstance(dist, str):
            raise TypeError("Don't know what do with '%r'" % dist)
        cached = cls._cache.get(dist)
        if not cached:
            cached = Distribution(Launchpad.distributions[dist])
        return cached

    def getArchive(self, archive=None):
        """
        Returns an Archive object for the requested archive.
        Raises a ArchiveNotFoundException if the archive doesn't exist.

        If 'archive' is None, return the main archive.
        """
        if archive:
            res = self._archives.get(archive)

            if not res:
                for a in self.archives:
                    if a.name == archive:
                        res = Archive(a)
                        self._archives[res.name] = res
                        break

            if res:
                return res
            else:
                message = "The Archive '%s' doesn't exist in %s" % (archive, self.display_name)
                raise ArchiveNotFoundException(message)
        else:
            if "_main_archive" not in self.__dict__:
                self._main_archive = Archive(self.main_archive_link)
            return self._main_archive

    def getSeries(self, name_or_version):
        """
        Returns a DistroSeries object for a series passed by name
        (e.g. 'karmic') or version (e.g. '9.10').
        If the series is not found: raise SeriesNotFoundException
        """
        if name_or_version in self._series:
            return self._series[name_or_version]
        if name_or_version in self._series_by_name:
            return self._series_by_name[name_or_version]

        try:
            series = DistroSeries(self().getSeries(name_or_version=name_or_version))
        except HTTPError:
            message = "Release '%s' is unknown in '%s'." % (name_or_version, self.display_name)
            raise SeriesNotFoundException(message)

        self._cache_series(series)
        return series

    def getDevelopmentSeries(self):
        """
        Returns a DistroSeries object of the current development series.
        """
        if not self._dev_series:
            series = DistroSeries(self.current_series_link)
            self._cache_series(series)
            self._dev_series = series
        return self._dev_series

    def getAllSeries(self, active=True):
        """
        Returns a list of all DistroSeries objects.
        """
        if not self._have_all_series:
            for s in Launchpad.load(self.series_collection_link).entries:
                series = DistroSeries(s["self_link"])
                self._cache_series(series)
            self._have_all_series = True

        allseries = filter(lambda s: s.active, self._series.values())
        allseries = sorted(allseries, key=lambda s: float(s.version), reverse=True)
        Logger.debug(
            "Found series: %s"
            % ", ".join(map(lambda s: "%s (%s)" % (s.name, s.version), allseries))
        )
        return collections.OrderedDict((s.name, s) for s in allseries)


class DistroArchSeries(BaseWrapper):
    """
    Wrapper class around a LP distro arch series object.
    """

    resource_type = "distro_arch_series"

    def getSeries(self):
        """
        Get DistroSeries for this.
        """
        return DistroSeries(self._lpobject.distroseries_link)


class DistroSeries(BaseWrapper):
    """
    Wrapper class around a LP distro series object.
    """

    resource_type = "distro_series"

    def __init__(self, *args):
        if "_architectures" not in self.__dict__:
            self._architectures = dict()

    def getArchSeries(self, archtag=None):
        """
        Returns a DistroArchSeries object for an architecture passed by name
        (e.g. 'amd64').
        If arch is not specified, get the DistroArchSeries for the system arch.
        The special archtag 'all' will get the system arch.
        If the architecture is not found: raise ArchSeriesNotFoundException.
        """
        if not archtag or archtag == "all":
            archtag = host_architecture()
        if archtag not in self._architectures:
            try:
                architecture = DistroArchSeries(self().getDistroArchSeries(archtag=archtag))
                self._architectures[architecture.architecture_tag] = architecture
            except HTTPError:
                message = "Architecture %s is unknown." % archtag
                raise ArchSeriesNotFoundException(message)
        return self._architectures[archtag]

    def getPackageUploads(self, name=None, pocket=None, version=None, status="Unapproved"):
        """Returns a list of PackageUploads for this series."""
        params = {"exact_match": True}
        if name:
            params["name"] = name
        if pocket:
            params["pocket"] = pocket
        if version:
            params["version"] = version
        if status:
            params["status"] = status
        return [PackageUpload(p) for p in self._lpobject.getPackageUploads(**params)]


class PackageUpload(BaseWrapper):
    """
    Wrapper class around a LP package_upload object.
    """

    resource_type = "package_upload"

    def __init__(self, *args):
        self._custom_urls = None
        self._source_urls = None
        self._binary_urls = None
        self._binary_properties = None
        self._binary_prop_dict = None

    def getArchive(self):
        return Archive(self._lpobject.archive_link)

    def getSourceArchive(self):
        if self._lpobject.copy_source_archive_link:
            return Archive(self._lpobject.copy_source_archive_link)
        return None

    def getDistroSeries(self):
        return DistroSeries(self._lpobject.distroseries_link)

    def changesFileUrl(self):
        return self._lpobject.changes_file_url

    def customFileUrls(self):
        if not self._custom_urls:
            self._custom_urls = self._lpobject.customFileUrls()
        return copy(self._custom_urls)

    def sourceFileUrls(self):
        if not self._source_urls:
            self._source_urls = self._lpobject.sourceFileUrls()
        return copy(self._source_urls)

    def binaryFileUrls(self):
        if not self._binary_urls:
            self._binary_urls = self._lpobject.binaryFileUrls()
        return copy(self._binary_urls)

    def getBinaryProperties(self):
        if not self._binary_properties:
            self._binary_properties = self._lpobject.getBinaryProperties()
        return copy(self._binary_properties)

    def binaryFileProperties(self, filename_or_url):
        if not self._binary_prop_dict:
            urls = self.binaryFileUrls()
            props = self.getBinaryProperties()
            self._binary_prop_dict = dict(zip(urls, props))
            for (k, v) in copy(self._binary_prop_dict).items():
                filename = os.path.basename(urlparse(k).path)
                self._binary_prop_dict[filename] = v
        return self._binary_prop_dict.get(filename_or_url, {})


class Archive(BaseWrapper):
    """
    Wrapper class around a LP archive object.
    """

    resource_type = "archive"

    def __init__(self, *args):
        self._binpkgs = {}
        self._srcpkgs = {}
        self._pkg_uploaders = {}
        self._pkgset_uploaders = {}
        self._component_uploaders = {}

    def getSourcePackage(
        self,
        name,
        series=None,
        pocket=None,
        version=None,
        status=None,
        wrapper=None,
        search_all_series=False,
    ):
        """
        Returns a SourcePackagePublishingHistory object for the most
        recent source package in the distribution 'dist', series and
        pocket.

        series defaults to the current development series if not specified.
        series must be either a series name string, or DistroSeries object.

        version may be specified to get only the exact version requested.

        pocket may be a string or a list.  If no version is provided, it
        defaults to all pockets except 'Backports'; if searching for a
        specific version, it defaults to all pockets.  Pocket strings must
        be capitalized.

        status may be a string or a list.  If no version is provided, it
        defaults to only 'Pending' and 'Published'; if searching for a
        specific version, it defaults to all statuses.  Status strings must
        be capitalized.

        wrapper is the class to return an instance of; defaults to
        SourcePackagePublishingHistory.

        search_all_series is used if series is None.  If False, this will
        search only the latest devel series, and if True all series
        will be searched, in reverse order, starting with the latest
        devel series.  Defaults to False.

        If the requested source package doesn't exist a
        PackageNotFoundException is raised.
        """
        return self._getPublishedItem(
            name,
            series,
            pocket,
            cache=self._srcpkgs,
            function="getPublishedSources",
            name_key="source_name",
            wrapper=wrapper or SourcePackagePublishingHistory,
            version=version,
            status=status,
            search_all_series=search_all_series,
            binary=False,
        )

    def getBinaryPackage(
        self,
        name,
        archtag=None,
        series=None,
        pocket=None,
        version=None,
        status=None,
        wrapper=None,
        search_all_series=False,
    ):
        """
        Returns a BinaryPackagePublishingHistory object for the most
        recent source package in the distribution 'dist', architecture
        'archtag', series and pocket.

        series defaults to the current development series if not specified.
        series must be either a series name string, or DistroArchSeries object.
        series may be omitted if version is specified.

        version may be specified to get only the exact version requested.

        pocket may be a string or a list.  If no version is provided, it
        defaults to all pockets except 'Backports'; if searching for a
        specific version, it defaults to all pockets.  Pocket strings must
        be capitalized.

        status may be a string or a list.  If no version is provided, it
        defaults to only 'Pending' and 'Published'; if searching for a
        specific version, it defaults to all statuses.  Status strings must
        be capitalized.

        wrapper is the class to return an instance of; defaults to
        BinaryPackagePublishingHistory.

        search_all_series is used if series is None.  If False, this will
        search only the latest devel series, and if True all series
        will be searched, in reverse order, starting with the latest
        devel series.  Defaults to False.

        If the requested binary package doesn't exist a
        PackageNotFoundException is raised.
        """
        return self._getPublishedItem(
            name,
            series,
            pocket,
            archtag=archtag,
            cache=self._binpkgs,
            function="getPublishedBinaries",
            name_key="binary_name",
            wrapper=wrapper or BinaryPackagePublishingHistory,
            version=version,
            status=status,
            search_all_series=search_all_series,
            binary=True,
        )

    def _getPublishedItem(
        self,
        name,
        series,
        pocket,
        cache,
        function,
        name_key,
        wrapper,
        archtag=None,
        version=None,
        status=None,
        search_all_series=False,
        binary=False,
    ):
        """
        Common code between getSourcePackage and getBinaryPackage.

        Don't use this directly.
        """
        if not pocket:
            if version and not series:
                # check ALL pockets if specific version in any series
                pockets = POCKETS
            else:
                # otherwise, check all pockets EXCEPT 'Backports'
                pockets = DEFAULT_POCKETS
        elif isinstance(pocket, str):
            pockets = (pocket,)
        else:
            pockets = tuple(pocket)

        for p in pockets:
            if p not in POCKETS:
                raise PocketDoesNotExistError("Pocket '%s' does not exist." % p)

        if not status:
            if version:
                # check ALL statuses if specific version
                statuses = STATUSES
            else:
                # otherwise, only check 'Pending' and 'Published'
                statuses = DEFAULT_STATUSES
        elif isinstance(status, str):
            statuses = (status,)
        else:
            statuses = tuple(status)

        for s in statuses:
            if s not in STATUSES:
                raise ValueError("Status '%s' is not valid." % s)

        dist = Distribution(self.distribution_link)

        # please don't pass DistroArchSeries as archtag!
        # but, the code was like that before so keep
        # backwards compatibility.
        if isinstance(archtag, DistroArchSeries):
            series = archtag
            archtag = None

        series_to_check = [series]
        if not version and not series:
            # if neither version or series are specified, use either the
            # devel series or search all series
            if search_all_series:
                series_to_check = dist.getAllSeries().values()
            else:
                series_to_check = [dist.getDevelopmentSeries()]

        # check each series - if only version was provided, series will be None
        for series in series_to_check:
            arch_series = None

            if isinstance(series, DistroArchSeries):
                arch_series = series
                series = series.getSeries()
            elif isinstance(series, DistroSeries):
                pass
            elif series:
                series = dist.getSeries(series)

            if binary:
                if arch_series is None and series:
                    arch_series = series.getArchSeries(archtag=archtag)
                if archtag is None and arch_series:
                    archtag = arch_series.architecture_tag
                if archtag is None:
                    archtag = host_architecture()

            index = (name, getattr(series, "name", None), archtag, pockets, statuses, version)

            if index in cache:
                return cache[index]

            params = {name_key: name, "exact_match": True}

            if arch_series:
                params["distro_arch_series"] = arch_series()
            elif series:
                params["distro_series"] = series()

            if len(pockets) == 1:
                params["pocket"] = pockets[0]

            if len(statuses) == 1:
                params["status"] = statuses[0]

            if version:
                params["version"] = version

            Logger.debug(
                "Calling %s(%s)"
                % (function, ", ".join(["%s=%s" % (k, v) for (k, v) in params.items()]))
            )
            records = getattr(self, function)(**params)

            err_msg = "does not exist in the %s %s archive" % (dist.display_name, self.name)

            for record in records:
                if binary:
                    rversion = getattr(record, "binary_package_version", None)
                else:
                    rversion = getattr(record, "source_package_version", None)
                skipmsg = "Skipping version %s: " % rversion

                if record.pocket not in pockets:
                    err_msg = "pocket %s not in (%s)" % (record.pocket, ",".join(pockets))
                    Logger.debug(skipmsg + err_msg)
                    continue
                if record.status not in statuses:
                    err_msg = "status %s not in (%s)" % (record.status, ",".join(statuses))
                    Logger.debug(skipmsg + err_msg)
                    continue
                r = wrapper(record)
                if binary and archtag and archtag != r.arch:
                    err_msg = "arch %s does not match requested arch %s" % (r.arch, archtag)
                    Logger.debug(skipmsg + err_msg)
                    continue
                # results are ordered so first is latest
                cache[index] = r
                return r

        version_with_epoch = None
        if version and version == Version(version).strip_epoch() and len(records) == 0:
            # a specific version was asked for, but we found none;
            # check if one exists with an epoch to give a hint in error msg
            for epoch in range(1, 9):
                v = Version(version)
                v.epoch = epoch
                params["version"] = v.full_version
                if len(getattr(self, function)(**params)) > 0:
                    version_with_epoch = v.full_version
                    Logger.debug("Found version with epoch %s" % version_with_epoch)
                    break

        if name_key == "binary_name":
            package_type = "binary package"
        elif name_key == "source_name":
            package_type = "source package"
        else:
            package_type = "package"
        msg = "The %s '%s' " % (package_type, name)
        if version:
            msg += "version %s " % version
        msg += err_msg
        if binary and archtag:
            msg += " for architecture %s" % archtag
        if len(series_to_check) > 1:
            msg += " in any release"
            if len(pockets) == 1:
                msg += " for pocket %s" % pockets[0]
            elif len(pockets) != len(POCKETS):
                msg += " for pockets " + ", ".join(pockets)
        elif series:
            msg += " in %s" % series.name
            if len(pockets) == 1:
                msg += "-%s" % pockets[0]
            elif len(pockets) != len(POCKETS):
                msg += " for pockets " + ", ".join(pockets)
        if len(statuses) == 1:
            msg += " with status %s" % statuses[0]
        elif len(statuses) != len(STATUSES):
            msg += " with status in " + ", ".join(statuses)
        if version_with_epoch:
            msg += " (did you forget the epoch? try %s)" % version_with_epoch
        raise PackageNotFoundException(msg)

    def copyPackage(
        self,
        source_name,
        version,
        from_archive,
        to_pocket,
        to_series=None,
        sponsored=None,
        include_binaries=False,
    ):
        """Copy a single named source into this archive.

        Asynchronously copy a specific version of a named source to the
        destination archive if necessary.  Calls to this method will return
        immediately if the copy passes basic security checks and the copy
        will happen sometime later with full checking.
        """

        if isinstance(sponsored, PersonTeam):
            sponsored = sponsored._lpobject

        self._lpobject.copyPackage(
            source_name=source_name,
            version=version,
            from_archive=from_archive._lpobject,
            to_pocket=to_pocket,
            to_series=to_series,
            sponsored=sponsored,
            include_binaries=include_binaries,
        )

    def getUploadersForComponent(self, component_name):
        """Get the list of PersonTeams who can upload packages in the
        specified component.
        [Note: the permission records, themselves, aren't exposed]
        """
        if component_name not in self._component_uploaders:
            self._component_uploaders[component_name] = sorted(
                set(
                    PersonTeam(permission.person_link)
                    for permission in self._lpobject.getUploadersForComponent(
                        component_name=component_name
                    )
                )
            )
        return self._component_uploaders[component_name]

    def getUploadersForPackage(self, source_package_name):
        """Get the list of PersonTeams who can upload source_package_name)
        [Note: the permission records, themselves, aren't exposed]
        """
        if source_package_name not in self._pkg_uploaders:
            self._pkg_uploaders[source_package_name] = sorted(
                set(
                    PersonTeam(permission.person_link)
                    for permission in self._lpobject.getUploadersForPackage(
                        source_package_name=source_package_name
                    )
                ),
                key=lambda s: s.name,
            )
        return self._pkg_uploaders[source_package_name]

    def getUploadersForPackageset(self, packageset, direct_permissions=False):
        """Get the list of PersonTeams who can upload packages in packageset
        [Note: the permission records, themselves, aren't exposed]
        """
        key = (packageset, direct_permissions)
        if key not in self._pkgset_uploaders:
            self._pkgset_uploaders[key] = sorted(
                set(
                    PersonTeam(permission.person_link)
                    for permission in self._lpobject.getUploadersForPackageset(
                        packageset=packageset._lpobject, direct_permissions=direct_permissions
                    )
                )
            )
        return self._pkgset_uploaders[key]

    def getMySubscriptionURL(self):
        """Get the "subscription URL" for the logged in user

        If this is a private archive (i.e. private PPA), this returns
        the "subscription URL" including authentication; otherwise
        this returns None.
        """
        if self.private:
            return PersonTeam.me.getArchiveSubscriptionURL(archive=self._lpobject)
        return None


class SourcePackagePublishingHistory(BaseWrapper):
    """
    Wrapper class around a LP source package object.
    """

    resource_type = "source_package_publishing_history"

    def __init__(self, *args):
        self._archive = None
        self._changelog = None
        self._binaries = {}
        self._distro_series = None
        self._source_urls = None
        # Don't share _builds between different
        # SourcePackagePublishingHistory objects
        if "_builds" not in self.__dict__:
            self._builds = dict()

    def getDistroSeries(self):
        """
        Return the DistroSeries.
        """
        if not self._distro_series:
            self._distro_series = DistroSeries(self._lpobject.distro_series_link)
        return self._distro_series

    def getPackageName(self):
        """
        Returns the source package name.
        """
        return self._lpobject.source_package_name

    def getVersion(self):
        """
        Returns the version of the source package.
        """
        return self._lpobject.source_package_version

    def getComponent(self):
        """
        Returns the component of the source package.
        """
        return self._lpobject.component_name

    def getSeriesName(self):
        """
        Returns the series

        Named getSeriesName() to avoid confusion with
        getDistroSeries()
        """
        return self.getDistroSeries().name

    def getSeriesAndPocket(self):
        """
        Returns a human-readable release-pocket
        """
        release = self.getSeriesName()
        if self.pocket != "Release":
            release += "-" + self.pocket.lower()
        return release

    def getArchive(self):
        """
        Get this SPPH's archive.
        """
        if not self._archive:
            self._archive = Archive(self._lpobject.archive_link)

        return self._archive

    def getChangelog(self, since_version=None):
        """
        Return the changelog, optionally since a particular version
        May return None if the changelog isn't available
        Only available in the devel API, not 1.0
        """
        if self._changelog is None:
            url = self._lpobject.changelogUrl()
            if url is None:
                Logger.error(
                    "No changelog available for %s %s" % (self.getPackageName(), self.getVersion())
                )
                return None

            try:
                self._changelog = download_text(url)
            except URLError as e:
                Logger.error(f"Exception while downloading '{url}': {e}")
                return None

        if since_version is None:
            return self._changelog

        if isinstance(since_version, str):
            since_version = Version(since_version)

        new_entries = []
        for block in Changelog(self._changelog):
            if block.version <= since_version:
                break
            new_entries.append(str(block))
        return "".join(new_entries)

    def sourceFileUrls(self, include_meta=False):
        """
        Return the URL for this source publication's files.

        The include_meta param changes the return value;
        when it is False (the default), an array of url strings is
        returned.  When include_meta is True, an array is returned
        with dicts, containing the entries:
          url: the url string
          sha1: the SHA1 checksum of the source file (if provided)
          sha256: the SHA256 checksum of the source file
          size: the size of the source file
        Also, this function adds a 'filename' field:
          filename: the filename parsed from the url path
        Note that while all the keys will be in the dict, their values
        may be None.
        """
        if not self._source_urls:
            urls = self._lpobject.sourceFileUrls(include_meta=True)
            if not urls:
                Logger.warning(
                    "SPPH %s_%s has no sourceFileUrls" % (self.getPackageName(), self.getVersion())
                )
            for u in urls:
                # make sure mandatory fields are present
                for field in ["url", "sha1", "sha256", "size"]:
                    if field not in u:
                        u[field] = None
                u["filename"] = os.path.basename(urlparse(u["url"]).path)
            self._source_urls = urls

        if include_meta:
            return list(self._source_urls)
        return [f["url"] for f in self._source_urls]

    def sourceFileUrl(self, filename):
        """
        Returns the URL for the specified source filename.

        If the filename is not found in the sourceFileUrls(), this returns None.
        """
        for f in self.sourceFileUrls(include_meta=True):
            if filename == f["filename"]:
                return f["url"]
        return None

    def sourceFileSha1(self, url_or_filename):
        """
        Returns the SHA1 checksum for the specified source file url.

        If the url is not found in the sourceFileUrls(), this returns None.

        The url may be specified as a filename.
        """
        for f in self.sourceFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return f["sha1"]
        return None

    def sourceFileSha256(self, url_or_filename):
        """
        Returns the SHA256 checksum for the specified source file url.

        If the url is not found in the sourceFileUrls(), this returns None.

        The url may be specified as a filename.
        """
        for f in self.sourceFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return f["sha256"]
        return None

    def sourceFileSize(self, url_or_filename):
        """
        Returns the size for the specified source file url.

        If the url is not found in the sourceFileUrls(), this returns 0.

        The url may be specified as a filename.
        """
        for f in self.sourceFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return int(f["size"])
        return 0

    def getBinaries(self, arch=None, name=None, ext=None):
        """
        Returns the resulting BinaryPackagePublishingHistorys.
        If arch is specified, it returns binaries for only that arch,
        plus any binaries with arch 'all'.  If arch is not specified, or
        if arch is specified as 'all', all archs are returned.

        If name is specified, only returns BPPH matching that (regex) name.

        If ext is specified, only returns BPPH matching that (regex) ext.
        """
        if arch == "all":
            arch = None

        if self.status in ["Pending", "Published"]:
            # Published, great!  Directly query the list of binaries
            binaries = map(BinaryPackagePublishingHistory, self._lpobject.getPublishedBinaries())
            for b in binaries:
                a = b.arch
                if a not in self._binaries:
                    self._binaries[a] = {}
                self._binaries[a][b.binary_package_name] = b
        else:
            # we have to go the long way :(
            Logger.info("Please wait, this may take some time...")
            archive = self.getArchive()
            urls = self.binaryFileUrls()
            for url in urls:
                # strip out the URL leading text.
                filename = os.path.basename(urlparse(url).path)
                # strip the file suffix
                (pkgname, _, e) = filename.rpartition(".")
                # split into name, version, arch
                (n, v, a) = pkgname.rsplit("_", 2)
                # arch 'all' has separate bpph for each real arch,
                # but all point to the same binary url
                if a == "all":
                    a = arch or host_architecture()
                # Only check the arch requested - saves time
                if arch and arch != a:
                    continue
                # Only check the name requested - saves time
                if name and not re.match(name, n):
                    continue
                # Only check the ext requested - saves time
                if ext and not re.match(ext, e):
                    continue
                # If we already have this BPPH, keep going
                if a in self._binaries and n in self._binaries[a]:
                    continue
                # we ignore the version, as it may be missing epoch
                # also we can't use series, as some package versions
                # span multiple series! (e.g. for different archs)
                params = {"name": n, "archtag": a, "version": self.getVersion()}
                try:
                    bpph = archive.getBinaryPackage(**params)
                except PackageNotFoundException:
                    Logger.debug("Could not find pkg in archive: %s" % filename)
                    continue
                if a not in self._binaries:
                    self._binaries[a] = {}
                self._binaries[a][n] = bpph

        if not arch:
            bpphs = [b for a in self._binaries.values() for b in a.values()]
        elif arch in self._binaries:
            bpphs = list(self._binaries[arch].values())
        else:
            return []

        if name:
            bpphs = [b for b in bpphs if re.match(name, b.binary_package_name)]

        if ext:
            bpphs = [b for b in bpphs if re.match(ext, b.getFileExt())]

        return bpphs

    def _fetch_builds(self):
        """Populate self._builds with the build records."""
        builds = self.getBuilds()
        for build in builds:
            self._builds[build.arch_tag] = Build(build)

    def getBuildStates(self, archs):
        res = list()

        if not self._builds:
            self._fetch_builds()

        for arch in archs:
            build = self._builds.get(arch)
            if build:
                res.append("  %s" % build)
        return "Build state(s) for '%s':\n%s" % (self.getPackageName(), "\n".join(res))

    def rescoreBuilds(self, archs, score):
        res = list()

        if not self._builds:
            self._fetch_builds()

        for arch in archs:
            build = self._builds.get(arch)
            if build:
                if build.rescore(score):
                    res.append("  %s: done" % arch)
                else:
                    res.append("  %s: failed" % arch)
        return "Rescoring builds of '%s' to %i:\n%s" % (
            self.getPackageName(),
            score,
            "\n".join(res),
        )

    def retryBuilds(self, archs):
        res = list()

        if not self._builds:
            self._fetch_builds()

        for arch in archs:
            build = self._builds.get(arch)
            if build:
                if build.retry():
                    res.append("  %s: done" % arch)
                else:
                    res.append("  %s: failed" % arch)
        return "Retrying builds of '%s':\n%s" % (self.getPackageName(), "\n".join(res))


class BinaryPackagePublishingHistory(BaseWrapper):
    """
    Wrapper class around a LP binary package object.
    """

    resource_type = "binary_package_publishing_history"

    def __init__(self, *args):
        self._arch = None
        self._ext = None
        self._binary_urls = None

    @property
    def arch(self):
        if not self._arch:
            das = DistroArchSeries(self._lpobject.distro_arch_series_link)
            self._arch = das.architecture_tag
        return self._arch

    def getSourcePackageName(self):
        """
        Returns the source package name.
        """
        return self.getBuild().source_package_name

    def getPackageName(self):
        """
        Returns the binary package name.
        """
        return self._lpobject.binary_package_name

    def getVersion(self):
        """
        Returns the version of the binary package.
        """
        return self._lpobject.binary_package_version

    def getComponent(self):
        """
        Returns the component of the binary package.
        """
        return self._lpobject.component_name

    def binaryFileUrls(self, include_meta=False):
        """
        Return the URL for this binary publication's files.
        Only available in the devel API, not 1.0

        The include_meta param changes the return value;
        when it is False (the default), an array of url strings is
        returned (but typically there is only a single url in the array).
        When include_meta is True, an array (again, with typically only one
        entry) is returned with dicts, containing the entries:
          url: the url string
          sha1: the SHA1 checksum of the binary file
          sha256: the SHA256 checksum of the binary file
          size: the size of the binary file
        Also, this function adds a 'filename' field:
          filename: the filename parsed from the url path
        Note that while all the keys will be in the dict, their values
        may be None.
        """
        if not self._binary_urls:
            try:
                urls = self._lpobject.binaryFileUrls(include_meta=True)
            except AttributeError:
                raise AttributeError(
                    "binaryFileUrls can only be found in lpapi "
                    "devel, not 1.0. Login using devel to have it."
                )
            if not urls:
                Logger.warning(
                    "BPPH %s_%s has no binaryFileUrls" % (self.getPackageName(), self.getVersion())
                )
            for u in urls:
                # make sure mandatory fields are present
                for field in ["url", "sha1", "sha256", "size"]:
                    if field not in u:
                        u[field] = None
                u["filename"] = os.path.basename(urlparse(u["url"]).path)
            self._binary_urls = urls

        if include_meta:
            return list(self._binary_urls)
        return [f["url"] for f in self._binary_urls]

    def binaryFileUrl(self, filename):
        """
        Returns the URL for the specified binary filename.

        If the filename is not found in the binaryFileUrls(), this returns None.
        """
        for f in self.binaryFileUrls(include_meta=True):
            if filename == f["filename"]:
                return f["url"]
        return None

    def binaryFileSha1(self, url_or_filename):
        """
        Returns the SHA1 checksum for the specified binary file url.

        If the url is not found in the binaryFileUrls(), this returns None.

        The url may be specified as a filename.
        """
        for f in self.binaryFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return f["sha1"]
        return None

    def binaryFileSha256(self, url_or_filename):
        """
        Returns the SHA256 checksum for the specified binary file url.

        If the url is not found in the binaryFileUrls(), this returns None.

        The url may be specified as a filename.
        """
        for f in self.binaryFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return f["sha256"]
        return None

    def binaryFileSize(self, url_or_filename):
        """
        Returns the size for the specified binary file url.

        If the url is not found in the binaryFileUrls(), this returns 0.

        The url may be specified as a filename.
        """
        for f in self.binaryFileUrls(include_meta=True):
            if url_or_filename in [f["url"], f["filename"]]:
                return int(f["size"])
        return 0

    def getBuild(self):
        """
        Returns the original build of the binary package.
        """
        return Build(self._lpobject.build_link)

    def getUrl(self):
        """
        Returns the original build URL of the binary package.
        """
        return "{build}/+files/{filename}".format(
            build=self.getBuild().getUrl(), filename=self.getFileName()
        )

    def getFileVersion(self):
        """
        Returns the file version, which is the package version without the epoch
        """
        return Version(self.getVersion()).strip_epoch()

    def getFileArch(self):
        """
        Returns the file arch, which is 'all' if not arch-specific
        """
        if bool(self._lpobject.architecture_specific):
            return self.arch
        else:
            return "all"

    def getFileExt(self):
        """
        Returns the file extension; "deb", "ddeb", or "udeb".
        """
        if not self._ext:
            self._ext = self._getFileExt()

        return self._ext

    def _getFileExt(self):
        try:
            # this is the best way, from the actual URL filename
            return self.binaryFileUrls()[0].rpartition(".")[2]
        except (AttributeError, IndexError):
            Logger.debug("Could not get file ext from url, trying to guess...")

        # is_debug should be reliable way of detecting ddeb...?
        try:
            if self.is_debug:
                return "ddeb"
        except AttributeError:
            # is_debug only available with api version 'devel'
            if self.getPackageName().endswith("-dbgsym"):
                return "ddeb"

        # is this reliable?
        if self.getPackageName().endswith("-di") or self.getPackageName().endswith("-udeb"):
            return "udeb"

        # everything else - assume regular deb
        return "deb"

    def getFileName(self):
        """
        Returns the filename for this binary package.
        """
        return "{name}_{version}_{arch}.{ext}".format(
            name=self.getPackageName(),
            version=self.getFileVersion(),
            arch=self.getFileArch(),
            ext=self.getFileExt(),
        )


class MetaPersonTeam(MetaWrapper):
    @property
    def me(cls):
        """The PersonTeam object of the currently authenticated LP user or
        None when anonymously logged in.
        """
        if "_me" not in cls.__dict__:
            try:
                # We have to use me.self_link due to LP: #504297
                cls._me = PersonTeam(Launchpad.me.self_link)
            except HTTPError as error:
                if error.response.status == 401:
                    # Anonymous login
                    cls._me = None
                else:
                    raise
        return cls._me


class PersonTeam(BaseWrapper, metaclass=MetaPersonTeam):
    """
    Wrapper class around a LP person or team object.
    """

    resource_type = ("person", "team")

    def __init__(self, *args):
        # Don't share _upload between different PersonTeams
        self._ppas = None
        if "_upload" not in self.__dict__:
            self._upload = dict()

    def __str__(self):
        return "%s (%s)" % (self.display_name, self.name)

    def cache(self):
        self._cache[self.name] = self

    @classmethod
    def fetch(cls, person_or_team):
        """
        Fetch the person or team object identified by 'url' from LP.
        """
        if not isinstance(person_or_team, str):
            raise TypeError("Don't know what do with '%r'" % person_or_team)
        cached = cls._cache.get(person_or_team)
        if not cached:
            cached = PersonTeam(Launchpad.people[person_or_team])
        return cached

    def isLpTeamMember(self, team):
        """
        Checks if the user is a member of a certain team on Launchpad.

        Returns True if the user is a member of the team otherwise False.
        """
        return any(t.name == team for t in self.super_teams)

    def canUploadPackage(self, archive, distroseries, package, component, pocket="Release"):
        """Check if the person or team has upload rights for the source
        package to the specified 'archive' and 'distrorelease'.

        A source package name and a component have to be specified.
        'archive' has to be a Archive object.
        'distroseries' has to be an DistroSeries object.
        """
        if not isinstance(archive, Archive):
            raise TypeError("'%r' is not an Archive object." % archive)
        if not isinstance(distroseries, DistroSeries):
            raise TypeError("'%r' is not a DistroSeries object." % distroseries)
        if package is not None and not isinstance(package, str):
            raise TypeError("A source package name expected.")
        if component is not None and not isinstance(component, str):
            raise TypeError("A component name expected.")
        if package is None and component is None:
            raise ValueError("Either a source package name or a component has to be specified.")
        if pocket not in POCKETS:
            raise PocketDoesNotExistError("Pocket '%s' does not exist." % pocket)

        canUpload = self._upload.get((archive, distroseries, pocket, package, component))

        if canUpload is None:
            # checkUpload() throws an exception if the person can't upload
            try:
                archive.checkUpload(
                    component=component,
                    distroseries=distroseries(),
                    person=self(),
                    pocket=pocket,
                    sourcepackagename=package,
                )
                canUpload = True
            except HTTPError as e:
                if e.response.status == 403:
                    canUpload = False
                else:
                    raise e
            index = (archive, distroseries, pocket, package, component)
            self._upload[index] = canUpload

        return canUpload

    def getPPAs(self):
        if self._ppas is None:
            ppas = [
                Archive(ppa["self_link"])
                for ppa in Launchpad.load(self._lpobject.ppas_collection_link).entries
            ]
            self._ppas = {ppa.name: ppa for ppa in ppas}
        return self._ppas

    def getPPAByName(self, name):
        return Archive(self._lpobject.getPPAByName(name=name))


class Project(BaseWrapper):
    """
    Wrapper class around a LP project object.
    """

    resource_type = "project"

    def __init__(self, *args):
        self._series = None

    @property
    def series(self):
        """Get a list of all ProjectSeries

        The list will be sorted by date_created, in descending order.
        """
        if not self._series:
            series = [
                ProjectSeries(s["self_link"])
                for s in Launchpad.load(self._lpobject.series_collection_link).entries
            ]
            self._series = sorted(series, key=lambda s: s.date_created, reverse=True)
        return self._series.copy()

    @classmethod
    def fetch(cls, project):
        """
        Fetch the project object identified by 'project' from LP.
        """
        if not isinstance(project, str):
            raise TypeError("Don't know what do with '%r'" % project)
        return Project(Launchpad.projects(project))


class ProjectSeries(BaseWrapper):
    """
    Wrapper class around a LP project_series object.
    """

    resource_type = "project_series"


class Build(BaseWrapper):
    """
    Wrapper class around a build object.
    """

    resource_type = "build"

    def __str__(self):
        return "%s: %s" % (self.arch_tag, self.buildstate)

    def getSourcePackagePublishingHistory(self):
        link = self._lpobject.current_source_publication_link
        if link:
            if re.search("redacted", link):
                # Too old - the link has been 'redacted'
                return None
            return SourcePackagePublishingHistory(link)
        return None

    def getUrl(self):
        return self()

    def rescore(self, score):
        if self.can_be_rescored:
            self().rescore(score=score)
            return True
        return False

    def retry(self):
        if self.can_be_retried:
            self().retry()
            return True
        return False


class DistributionSourcePackage(BaseWrapper):
    """
    Caching class for distribution_source_package objects.
    """

    resource_type = "distribution_source_package"


class Packageset(BaseWrapper):
    """
    Caching class for packageset objects.
    """

    resource_type = "packageset"
    _lp_packagesets = None
    _source_sets = {}

    @classmethod
    def setsIncludingSource(cls, sourcepackagename, distroseries=None, direct_inclusion=False):
        """Get the package sets including sourcepackagename"""

        if cls._lp_packagesets is None:
            cls._lp_packagesets = Launchpad.packagesets

        key = (sourcepackagename, distroseries, direct_inclusion)
        if key not in cls._source_sets:
            params = {"sourcepackagename": sourcepackagename, "direct_inclusion": direct_inclusion}
            if distroseries is not None:
                params["distroseries"] = distroseries._lpobject

            cls._source_sets[key] = [
                Packageset(packageset)
                for packageset in cls._lp_packagesets.setsIncludingSource(**params)
            ]

        return cls._source_sets[key]
