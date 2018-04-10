import six

from collections import namedtuple
from gettext import gettext as _
from logging import getLogger
from optparse import OptionParser

from yum import YumBase
from yum.plugins import TYPE_CORE, TYPE_INTERACTIVE
from yum.Errors import InstallError
from yum import constants
from yum import updateinfo


log = getLogger(__name__)

INSTALLED = _('Installed: {p}')
UPDATED = _('Updated: {p}')
ERASED = _('Erased: {p}')


# Transaction report.
# The 'resolved' field contains a list of resolved packages to be
#    installed/updated/erased.
# The 'deps' field contains a list of additional dependencies to be
#    installed/updated/erased.
# The 'failed' field contains a list of packages that failed to be
#    installed/updated/erased.
TransactionReport = namedtuple('TransactionReport', ['resolved', 'deps', 'failed'])


class Pattern(object):
    """
    Package matching pattern.

    Attributes:
        fields (dict): A dictionary of NEVREA fields with wildcard defaults.
    """

    FIELDS = (
        ('name', None),
        ('epoch', '*'),
        ('version', '*'),
        ('release', '*'),
        ('arch', '*'),
    )

    def __init__(self, nevrea):
        """
        Args:
            nevrea (dict): A dictionary containing the NEVREA as defined by FIELDS.
        """
        self.fields = {f[0]: nevrea.get(f[0], f[1]) for f in self.FIELDS}

    def __str__(self):
        return '{epoch}:{name}-{version}-{release}.{arch}'.format(**self.fields)


class API(object):
    """
    Abstract package management API.

    Attributes:
        commit (bool): Commit the transaction.
    """

    def __init__(self, commit=True):
        """
        Args:
            commit (bool): Commit the transaction.
                Use False for a "dry run".
        """
        self.commit = commit

    @staticmethod
    def transaction_report(ts_info, states):
        """
        Build a transaction report.

        Args:
            ts_info: A YUM transaction.
            states (tuple): List of package states.

        Returns:
            TransactionReport: A report.
        """
        deps = []
        resolved = []
        failed = []
        for t in ts_info:
            if t.output_state not in states:
                continue
            qname = str(t.po)
            package = dict(
                qname=qname,
                repoid=t.repoid,
                name=t.po.name,
                version=t.po.ver,
                release=t.po.rel,
                arch=t.po.arch,
                epoch=t.po.epoch)
            if t.output_state == constants.TS_FAILED:
                failed.append(package)
            if t.isDep:
                deps.append(package)
            else:
                resolved.append(package)
        return TransactionReport(resolved=resolved, deps=deps, failed=failed)

    @staticmethod
    def affected(report):
        """
        The list of packages affected by the transaction.

        Args:
            report (TransactionReport):  A transaction report.

        Returns:
            List of affected fully-qualified package names.
        """
        affected = []
        affected.extend(report.resolved)
        affected.extend(report.deps)
        return [p['qname'] for p in affected]

    @staticmethod
    def installed(ts_info):
        """
        The list of packages installed by the transaction.

        Args:
            ts_info: A YUM transaction.

        Returns:
             TransactionReport: A report.
        """
        states = (
            constants.TS_FAILED,
            constants.TS_INSTALL,
            constants.TS_TRUEINSTALL,
            constants.TS_UPDATE
        )
        return API.transaction_report(ts_info, states)

    @staticmethod
    def updated(ts_info):
        """
        The list of packages updated by the transaction.

        Args:
            ts_info: A YUM transaction.

        Returns:
             TransactionReport: A report.
        """
        states = (
            constants.TS_FAILED,
            constants.TS_INSTALL,
            constants.TS_TRUEINSTALL,
            constants.TS_UPDATE
        )
        return API.transaction_report(ts_info, states)

    @staticmethod
    def erased(ts_info):
        """
        The list of packages erased by the transaction.

        Args:
            ts_info: A YUM transaction.

        Returns:
             TransactionReport: A report.
        """
        states = (
            constants.TS_FAILED,
            constants.TS_ERASE
        )
        return API.transaction_report(ts_info, states)


class Package(API):
    """
    The package management API.
    """

    def install(self, patterns):
        """
        Install packages.

        Args:
            patterns (list): A list of Pattern.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibYum() as lib:
            for pattern in patterns:
                try:
                    lib.install(pattern=str(pattern))
                except InstallError as caught:
                    description = six.text_type(caught).encode('utf-8')
                    caught.value = '%s: %s' % (pattern, description)
                    raise caught
            lib.resolveDeps()
            if self.commit and len(lib.tsInfo):
                lib.processTransaction()
            report = self.installed(lib.tsInfo)
            if self.commit:
                affected = self.affected(report)
                map(log.info, [INSTALLED.format(p=p) for p in affected])
                map(lib.logfile.info, [INSTALLED.format(p=p) for p in affected])
            return report._asdict()

    def update(self, patterns=(), advisories=()):
        """
        Update packages.

        Args:
            patterns (list): A list of Pattern.
            advisories (list): A list of advisory IDs.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibYum() as lib:
            if advisories:
                lib.updateinfo_filters = {
                    'bzs': [],
                    'bugfix': None,
                    'sevs': [],
                    'security': None,
                    'advs': advisories,
                    'cves': []
                }
                updateinfo.update_minimal(lib)
            if patterns:
                for pattern in patterns:
                    lib.update(pattern=str(pattern))
            else:
                lib.update()
            lib.resolveDeps()
            if self.commit and len(lib.tsInfo):
                lib.processTransaction()
            report = self.updated(lib.tsInfo)
            if self.commit:
                affected = self.affected(report)
                map(log.info, [UPDATED.format(p=p) for p in affected])
                map(lib.logfile.info, [UPDATED.format(p=p) for p in affected])
            return report._asdict()

    def uninstall(self, patterns):
        """
        Uninstall (remove) packages.

        Args:
            patterns (list): A list of Pattern.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibYum() as lib:
            for pattern in patterns:
                lib.remove(pattern=str(pattern))
            lib.resolveDeps()
            if self.commit and len(lib.tsInfo):
                lib.processTransaction()
            report = self.erased(lib.tsInfo)
            if self.commit:
                affected = self.affected(report)
                map(log.info, [ERASED.format(p=p) for p in affected])
                map(lib.logfile.info, [ERASED.format(p=p) for p in affected])
            return report._asdict()


class PackageGroup(API):
    """
    Package group management API.
    """

    def install(self, names):
        """
        Install package groups.

        Args:
            names (list): A list of group names.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibYum() as lib:
            for name in names:
                lib.selectGroup(name)
            lib.resolveDeps()
            if self.commit and len(lib.tsInfo):
                lib.processTransaction()
            report = self.installed(lib.tsInfo)
            if self.commit:
                affected = self.affected(report)
                map(log.info, [INSTALLED.format(p=p) for p in affected])
                map(lib.logfile.info, [INSTALLED.format(p=p) for p in affected])
            return report._asdict()

    def uninstall(self, names):
        """
        Uninstall package groups.

        Args:
            names (list): A list of group names.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibYum() as lib:
            for name in names:
                lib.groupRemove(name)
            lib.resolveDeps()
            if self.commit and len(lib.tsInfo):
                lib.processTransaction()
            report = self.erased(lib.tsInfo)
            if self.commit:
                affected = self.affected(report)
                map(log.info, [ERASED.format(p=p) for p in affected])
                map(lib.logfile.info, [ERASED.format(p=p) for p in affected])
            return report._asdict()


class LibYum(YumBase):
    """
    A YUM base.
    """

    def __init__(self):
        """
        Initialization.
        """
        parser = OptionParser()
        parser.parse_args([])
        self.__parser = parser
        super(YumBase, self).__init__()
        self.preconf.optparser = self.__parser
        self.preconf.plugin_types = (TYPE_CORE, TYPE_INTERACTIVE)
        self.conf.assumeyes = True
        self.logfile = getLogger('yum.filelogging')

    def doPluginSetup(self, *args, **kwargs):
        """
        Plugin setup.

        Args:
            *args:
            **kwargs:
        """
        super(LibYum, self).doPluginSetup(self, *args, **kwargs)
        p = self.__parser
        options, args = p.parse_args([])
        self.plugins.setCmdLine(options, args)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
