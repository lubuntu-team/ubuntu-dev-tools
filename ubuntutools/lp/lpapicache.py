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

# Uncomment for tracing LP API calls
# import httplib2
# httplib2.debuglevel = 1

import collections
import sys

from debian.changelog import Changelog, Version
from httplib2 import Http, HttpLib2Error
from launchpadlib.launchpad import Launchpad as LP
from launchpadlib.errors import HTTPError
from lazr.restfulclient.resource import Entry

from ubuntutools.lp import (service, api_version)
from ubuntutools.lp.udtexceptions import (AlreadyLoggedInError,
                                          ArchiveNotFoundException,
                                          ArchSeriesNotFoundException,
                                          PackageNotFoundException,
                                          PocketDoesNotExistError,
                                          SeriesNotFoundException)


__all__ = [
    'Archive',
    'BinaryPackagePublishingHistory',
    'Build',
    'Distribution',
    'DistributionSourcePackage',
    'DistroSeries',
    'Launchpad',
    'PersonTeam',
    'SourcePackagePublishingHistory',
    ]

_POCKETS = ('Release', 'Security', 'Updates', 'Proposed', 'Backports')


class _Launchpad(object):
    '''Singleton for LP API access.'''

    def login(self, service=service, api_version=api_version):
        '''Enforce a non-anonymous login.'''
        if not self.logged_in:
            try:
                self.__lp = LP.login_with('ubuntu-dev-tools', service,
                                          version=api_version)
            except IOError as error:
                print('E: %s' % error, file=sys.stderr)
                raise
        else:
            raise AlreadyLoggedInError('Already logged in to Launchpad.')

    def login_anonymously(self, service=service, api_version=api_version):
        '''Enforce an anonymous login.'''
        if not self.logged_in:
            self.__lp = LP.login_anonymously('ubuntu-dev-tools', service,
                                             version=api_version)
        else:
            raise AlreadyLoggedInError('Already logged in to Launchpad.')

    def login_existing(self, lp):
        '''Use an already logged in Launchpad object'''
        if not self.logged_in:
            self.__lp = lp
        else:
            raise AlreadyLoggedInError('Already logged in to Launchpad.')

    @property
    def logged_in(self):
        '''Are we logged in?'''
        return '_Launchpad__lp' in self.__dict__

    def __getattr__(self, attr):
        if not self.logged_in:
            self.login()
        return getattr(self.__lp, attr)

    def __call__(self):
        return self


Launchpad = _Launchpad()


class MetaWrapper(type):
    '''
    A meta class used for wrapping LP API objects.
    '''
    def __init__(cls, name, bases, attrd):
        super(MetaWrapper, cls).__init__(name, bases, attrd)
        if 'resource_type' not in attrd:
            raise TypeError('Class "%s" needs an associated resource type' %
                            name)
        cls._cache = dict()


class BaseWrapper(object, metaclass=MetaWrapper):
    '''
    A base class from which other wrapper classes are derived.
    '''
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
            (service_root, resource_type) = data.resource_type_link.split('#')
            if service_root == str(Launchpad._root_uri) and resource_type in cls.resource_type:
                # check if it's already cached
                cached = cls._cache.get(data.self_link)
                if not cached:
                    # create a new instance
                    cached = object.__new__(cls)
                    cached._lpobject = data
                    # and add it to our cache
                    cls._cache[data.self_link] = cached
                    # add additional class specific caching (if available)
                    cache = getattr(cls, 'cache', None)
                    if isinstance(cache, collections.Callable):
                        cache(cached)
                return cached
            else:
                raise TypeError("'%s' is not a '%s' object" %
                                (str(data), str(cls.resource_type)))
        else:
            # not a LP API representation, let the specific class handle it
            fetch = getattr(cls, 'fetch', None)
            if isinstance(fetch, collections.Callable):
                return fetch(data)
            else:
                raise NotImplementedError("Don't know how to fetch '%s' from LP"
                                          % str(data))

    def __call__(self):
        return self._lpobject

    def __getattr__(self, attr):
        return getattr(self._lpobject, attr)

    def __repr__(self):
        if hasattr(str, 'format'):
            return '<{0}: {1!r}>'.format(self.__class__.__name__,
                                         self._lpobject)
        else:
            return '<%s: %r>' % (self.__class__.__name__, self._lpobject)


class Distribution(BaseWrapper):
    '''
    Wrapper class around a LP distribution object.
    '''
    resource_type = 'distribution'

    def __init__(self, *args):
        # Don't share _series and _archives between different Distributions
        if '_series' not in self.__dict__:
            self._series = dict()
        if '_archives' not in self.__dict__:
            self._archives = dict()

    def cache(self):
        self._cache[self.name] = self

    @classmethod
    def fetch(cls, dist):
        '''
        Fetch the distribution object identified by 'dist' from LP.
        '''
        if not isinstance(dist, str):
            raise TypeError("Don't know what do with '%r'" % dist)
        cached = cls._cache.get(dist)
        if not cached:
            cached = Distribution(Launchpad.distributions[dist])
        return cached

    def getArchive(self, archive=None):
        '''
        Returns an Archive object for the requested archive.
        Raises a ArchiveNotFoundException if the archive doesn't exist.

        If 'archive' is None, return the main archive.
        '''
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
                message = "The Archive '%s' doesn't exist in %s" % \
                          (archive, self.display_name)
                raise ArchiveNotFoundException(message)
        else:
            if '_main_archive' not in self.__dict__:
                self._main_archive = Archive(self.main_archive_link)
            return self._main_archive

    def getSeries(self, name_or_version):
        '''
        Returns a DistroSeries object for a series passed by name
        (e.g. 'karmic') or version (e.g. '9.10').
        If the series is not found: raise SeriesNotFoundException
        '''
        if name_or_version not in self._series:
            try:
                series = DistroSeries(self().getSeries(name_or_version=name_or_version))
                # Cache with name and version
                self._series[series.name] = series
                self._series[series.version] = series
            except HTTPError:
                message = "Release '%s' is unknown in '%s'." % \
                          (name_or_version, self.display_name)
                raise SeriesNotFoundException(message)
        return self._series[name_or_version]

    def getDevelopmentSeries(self):
        '''
        Returns a DistroSeries object of the current development series.
        '''
        dev = DistroSeries(self.current_series_link)
        # Cache it in _series if not already done
        if dev.name not in self._series:
            self._series[dev.name] = dev
            self._series[dev.version] = dev
        return dev


class DistroArchSeries(BaseWrapper):
    '''
    Wrapper class around a LP distro arch series object.
    '''
    resource_type = 'distro_arch_series'


class DistroSeries(BaseWrapper):
    '''
    Wrapper class around a LP distro series object.
    '''
    resource_type = 'distro_series'

    def __init__(self, *args):
        if "_architectures" not in self.__dict__:
            self._architectures = dict()

    def getArchSeries(self, archtag):
        '''
        Returns a DistroArchSeries object for an architecture passed by name
        (e.g. 'amd64').
        If the architecture is not found: raise ArchSeriesNotFoundException.
        '''
        if archtag not in self._architectures:
            try:
                architecture = DistroArchSeries(
                    self().getDistroArchSeries(archtag=archtag))
                self._architectures[architecture.architecture_tag] = (
                    architecture)
            except HTTPError:
                message = "Architecture %s is unknown." % archtag
                raise ArchSeriesNotFoundException(message)
        return self._architectures[archtag]


class Archive(BaseWrapper):
    '''
    Wrapper class around a LP archive object.
    '''
    resource_type = 'archive'

    def __init__(self, *args):
        self._binpkgs = {}
        self._srcpkgs = {}
        self._pkg_uploaders = {}
        self._pkgset_uploaders = {}
        self._component_uploaders = {}

    def getSourcePackage(self, name, series=None, pocket=None):
        '''
        Returns a SourcePackagePublishingHistory object for the most
        recent source package in the distribution 'dist', series and
        pocket.

        series defaults to the current development series if not specified.

        pocket may be a list, if so, the highest version will be returned.
        It defaults to all pockets except backports.

        If the requested source package doesn't exist a
        PackageNotFoundException is raised.
        '''
        return self._getPublishedItem(name, series, pocket, cache=self._srcpkgs,
                                      function='getPublishedSources',
                                      name_key='source_name',
                                      wrapper=SourcePackagePublishingHistory)

    def getBinaryPackage(self, name, archtag=None, series=None, pocket=None):
        '''
        Returns a BinaryPackagePublishingHistory object for the most
        recent source package in the distribution 'dist', architecture
        'archtag', series and pocket.

        series defaults to the current development series if not specified.

        pocket may be a list, if so, the highest version will be returned.
        It defaults to all pockets except backports.

        If the requested binary package doesn't exist a
        PackageNotFoundException is raised.
        '''
        if archtag is None:
            archtag = []
        return self._getPublishedItem(name, series, pocket, archtag=archtag,
                                      cache=self._binpkgs,
                                      function='getPublishedBinaries',
                                      name_key='binary_name',
                                      wrapper=BinaryPackagePublishingHistory)

    def _getPublishedItem(self, name, series, pocket, cache,
                          function, name_key, wrapper, archtag=None):
        '''Common code between getSourcePackage and getBinaryPackage
        '''
        if pocket is None:
            pockets = frozenset(('Proposed', 'Updates', 'Security', 'Release'))
        elif isinstance(pocket, str):
            pockets = frozenset((pocket,))
        else:
            pockets = frozenset(pocket)

        for pocket in pockets:
            if pocket not in _POCKETS:
                raise PocketDoesNotExistError("Pocket '%s' does not exist." %
                                              pocket)

        dist = Distribution(self.distribution_link)
        # Check if series is already a DistroSeries object or not
        if not isinstance(series, DistroSeries):
            if series:
                series = dist.getSeries(series)
            else:
                series = dist.getDevelopmentSeries()

        # getPublishedSources requires a distro_series, while
        # getPublishedBinaries requires a distro_arch_series.
        # If archtag is not None, I'll assume it's getPublishedBinaries.
        if archtag is not None and archtag != []:
            if not isinstance(archtag, DistroArchSeries):
                arch_series = series.getArchSeries(archtag=archtag)
            else:
                arch_series = archtag

        if archtag is not None and archtag != []:
            index = (name, series.name, archtag, pockets)
        else:
            index = (name, series.name, pockets)

        if index not in cache:
            params = {
                name_key: name,
                'status': 'Published',
                'exact_match': True,
            }
            if archtag is not None and archtag != []:
                params['distro_arch_series'] = arch_series()
            else:
                params['distro_series'] = series()

            if len(pockets) == 1:
                params['pocket'] = list(pockets)[0]

            records = getattr(self, function)(**params)

            latest = None
            for record in records:
                if record.pocket not in pockets:
                    continue
                if latest is None or (Version(latest.source_package_version)
                                      < Version(record.source_package_version)):
                    latest = record

            if latest is None:
                if name_key == 'binary_name':
                    package_type = "binary package"
                elif name_key == 'source_name':
                    package_type = "source package"
                else:
                    package_type = "package"
                msg = ("The %s '%s' does not exist in the %s %s archive" %
                       (package_type, name, dist.display_name, self.name))
                if archtag is not None and archtag != []:
                    msg += " for architecture %s" % archtag
                pockets = [series.name if pocket == 'Release'
                           else '%s-%s' % (series.name, pocket.lower())
                           for pocket in pockets]
                if len(pockets) > 1:
                    pockets[-2:] = [' or '.join(pockets[-2:])]
                msg += " in " + ', '.join(pockets)
                raise PackageNotFoundException(msg)

            cache[index] = wrapper(latest)
        return cache[index]

    def copyPackage(self, source_name, version, from_archive, to_pocket,
                    to_series=None, sponsored=None, include_binaries=False):
        '''Copy a single named source into this archive.

        Asynchronously copy a specific version of a named source to the
        destination archive if necessary.  Calls to this method will return
        immediately if the copy passes basic security checks and the copy
        will happen sometime later with full checking.
        '''

        if isinstance(sponsored, PersonTeam):
            sponsored = sponsored._lpobject

        self._lpobject.copyPackage(
            source_name=source_name,
            version=version,
            from_archive=from_archive._lpobject,
            to_pocket=to_pocket,
            to_series=to_series,
            sponsored=sponsored,
            include_binaries=include_binaries
            )

    def getUploadersForComponent(self, component_name):
        '''Get the list of PersonTeams who can upload packages in the
        specified component.
        [Note: the permission records, themselves, aren't exposed]
        '''
        if component_name not in self._component_uploaders:
            self._component_uploaders[component_name] = sorted(set(
                PersonTeam(permission.person_link) for permission in
                self._lpobject.getUploadersForComponent(component_name=component_name)
            ))
        return self._component_uploaders[component_name]

    def getUploadersForPackage(self, source_package_name):
        '''Get the list of PersonTeams who can upload source_package_name)
        [Note: the permission records, themselves, aren't exposed]
        '''
        if source_package_name not in self._pkg_uploaders:
            self._pkg_uploaders[source_package_name] = sorted(set(
                PersonTeam(permission.person_link) for permission in
                self._lpobject.getUploadersForPackage(source_package_name=source_package_name)
            ))
        return self._pkg_uploaders[source_package_name]

    def getUploadersForPackageset(self, packageset, direct_permissions=False):
        '''Get the list of PersonTeams who can upload packages in packageset
        [Note: the permission records, themselves, aren't exposed]
        '''
        key = (packageset, direct_permissions)
        if key not in self._pkgset_uploaders:
            self._pkgset_uploaders[key] = sorted(set(
                PersonTeam(permission.person_link) for permission in
                self._lpobject.getUploadersForPackageset(
                    packageset=packageset._lpobject,
                    direct_permissions=direct_permissions,
                )
            ))
        return self._pkgset_uploaders[key]


class SourcePackagePublishingHistory(BaseWrapper):
    '''
    Wrapper class around a LP source package object.
    '''
    resource_type = 'source_package_publishing_history'

    def __init__(self, *args):
        self._changelog = None
        self._binaries = None
        # Don't share _builds between different
        # SourcePackagePublishingHistory objects
        if '_builds' not in self.__dict__:
            self._builds = dict()

    def getPackageName(self):
        '''
        Returns the source package name.
        '''
        return self._lpobject.source_package_name

    def getVersion(self):
        '''
        Returns the version of the source package.
        '''
        return self._lpobject.source_package_version

    def getComponent(self):
        '''
        Returns the component of the source package.
        '''
        return self._lpobject.component_name

    def getSeriesAndPocket(self):
        '''
        Returns a human-readable release-pocket
        '''
        series = DistroSeries(self._lpobject.distro_series_link)
        release = series.name
        if self._lpobject.pocket != 'Release':
            release += '-' + self._lpobject.pocket.lower()
        return release

    def getChangelog(self, since_version=None):
        '''
        Return the changelog, optionally since a particular version
        May return None if the changelog isn't available
        Only available in the devel API, not 1.0
        '''
        if self._changelog is None:
            url = self._lpobject.changelogUrl()
            if url is None:
                print('E: No changelog available for %s %s' %
                      (self.getPackageName(), self.getVersion()), file=sys.stderr)
                return None

            try:
                response, changelog = Http().request(url)
            except HttpLib2Error as e:
                print(str(e), file=sys.stderr)
                return None
            if response.status != 200:
                print('%s: %s %s' % (url, response.status, response.reason), file=sys.stderr)
                return None
            self._changelog = changelog

        if since_version is None:
            return self._changelog

        if isinstance(since_version, str):
            since_version = Version(since_version)

        new_entries = []
        for block in Changelog(self._changelog):
            if block.version <= since_version:
                break
            new_entries.append(str(block))
        return u''.join(new_entries)

    def getBinaries(self):
        '''
        Returns the resulting BinaryPackagePublishingHistorys
        '''
        if self._binaries is None:
            self._binaries = [BinaryPackagePublishingHistory(bpph)
                              for bpph in
                              self._lpobject.getPublishedBinaries()]
        return self._binaries

    def _fetch_builds(self):
        '''Populate self._builds with the build records.'''
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
                res.append('  %s' % build)
        return "Build state(s) for '%s':\n%s" % (
            self.getPackageName(), '\n'.join(res))

    def rescoreBuilds(self, archs, score):
        res = list()

        if not self._builds:
            self._fetch_builds()

        for arch in archs:
            build = self._builds.get(arch)
            if build:
                if build.rescore(score):
                    res.append('  %s: done' % arch)
                else:
                    res.append('  %s: failed' % arch)
        return "Rescoring builds of '%s' to %i:\n%s" % (
            self.getPackageName(), score, '\n'.join(res))

    def retryBuilds(self, archs):
        res = list()

        if not self._builds:
            self._fetch_builds()

        for arch in archs:
            build = self._builds.get(arch)
            if build:
                if build.retry():
                    res.append('  %s: done' % arch)
                else:
                    res.append('  %s: failed' % arch)
        return "Retrying builds of '%s':\n%s" % (
            self.getPackageName(), '\n'.join(res))


class BinaryPackagePublishingHistory(BaseWrapper):
    '''
    Wrapper class around a LP binary package object.
    '''
    resource_type = 'binary_package_publishing_history'

    def getPackageName(self):
        '''
        Returns the binary package name.
        '''
        return self._lpobject.binary_package_name

    def getVersion(self):
        '''
        Returns the version of the binary package.
        '''
        return self._lpobject.binary_package_version

    def getComponent(self):
        '''
        Returns the component of the binary package.
        '''
        return self._lpobject.component_name

    def binaryFileUrls(self):
        '''
        Return the URL for this binary publication's files.
        Only available in the devel API, not 1.0
        '''
        try:
            return self._lpobject.binaryFileUrls()
        except AttributeError:
            raise AttributeError("binaryFileUrls can only be found in lpapi "
                                 "devel, not 1.0. Login using devel to have it.")


class MetaPersonTeam(MetaWrapper):
    @property
    def me(cls):
        '''The PersonTeam object of the currently authenticated LP user or
        None when anonymously logged in.
        '''
        if '_me' not in cls.__dict__:
            try:
                cls._me = PersonTeam(Launchpad.me)
            except HTTPError as error:
                if error.response.status == 401:
                    # Anonymous login
                    cls._me = None
                else:
                    raise
        return cls._me


class PersonTeam(BaseWrapper, metaclass=MetaPersonTeam):
    '''
    Wrapper class around a LP person or team object.
    '''

    resource_type = ('person', 'team')

    def __init__(self, *args):
        # Don't share _upload between different PersonTeams
        if '_upload' not in self.__dict__:
            self._upload = dict()

    def __str__(self):
        return u'%s (%s)' % (self.display_name, self.name)

    def cache(self):
        self._cache[self.name] = self

    @classmethod
    def fetch(cls, person_or_team):
        '''
        Fetch the person or team object identified by 'url' from LP.
        '''
        if not isinstance(person_or_team, str):
            raise TypeError("Don't know what do with '%r'" % person_or_team)
        cached = cls._cache.get(person_or_team)
        if not cached:
            cached = PersonTeam(Launchpad.people[person_or_team])
        return cached

    def isLpTeamMember(self, team):
        '''
        Checks if the user is a member of a certain team on Launchpad.

        Returns True if the user is a member of the team otherwise False.
        '''
        return any(t.name == team for t in self.super_teams)

    def canUploadPackage(self, archive, distroseries, package, component,
                         pocket='Release'):
        '''Check if the person or team has upload rights for the source
        package to the specified 'archive' and 'distrorelease'.

        A source package name and a component have to be specified.
        'archive' has to be a Archive object.
        'distroseries' has to be an DistroSeries object.
        '''
        if not isinstance(archive, Archive):
            raise TypeError("'%r' is not an Archive object." % archive)
        if not isinstance(distroseries, DistroSeries):
            raise TypeError("'%r' is not a DistroSeries object." % distroseries)
        if package is not None and not isinstance(package, str):
            raise TypeError('A source package name expected.')
        if component is not None and not isinstance(component, str):
            raise TypeError('A component name expected.')
        if package is None and component is None:
            raise ValueError('Either a source package name or a component has '
                             'to be specified.')
        if pocket not in _POCKETS:
            raise PocketDoesNotExistError("Pocket '%s' does not exist." %
                                          pocket)

        canUpload = self._upload.get((archive, distroseries, pocket, package,
                                      component))

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


class Build(BaseWrapper):
    '''
    Wrapper class around a build object.
    '''
    resource_type = 'build'

    def __str__(self):
        return u'%s: %s' % (self.arch_tag, self.buildstate)

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
    '''
    Caching class for distribution_source_package objects.
    '''
    resource_type = 'distribution_source_package'


class Packageset(BaseWrapper):
    '''
    Caching class for packageset objects.
    '''
    resource_type = 'packageset'
    _lp_packagesets = None
    _source_sets = {}

    @classmethod
    def setsIncludingSource(cls, sourcepackagename, distroseries=None,
                            direct_inclusion=False):
        '''Get the package sets including sourcepackagename'''

        if cls._lp_packagesets is None:
            cls._lp_packagesets = Launchpad.packagesets

        key = (sourcepackagename, distroseries, direct_inclusion)
        if key not in cls._source_sets:
            params = {
                'sourcepackagename': sourcepackagename,
                'direct_inclusion': direct_inclusion,
            }
            if distroseries is not None:
                params['distroseries'] = distroseries._lpobject

            cls._source_sets[key] = [Packageset(packageset) for packageset in
                                     cls._lp_packagesets.setsIncludingSource(**params)]

        return cls._source_sets[key]
