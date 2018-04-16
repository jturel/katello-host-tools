import logging

import hawkey

from collections import namedtuple
from gettext import gettext as _

from dnf import Base
from dnf.exceptions import CompsError

log = logging.getLogger(__name__)


# Transaction report.
# The 'resolved' field contains a list of resolved packages to be
#    installed/updated/erased.
# The 'deps' field contains a list of additional dependencies to be
#    installed/updated/erased.  NOT SUPPORTED BY DNF.
# The 'failed' field contains a list of packages that failed to be
#    installed/updated/erased.  NOT SUPPORTED BY DNF.
TransactionReport = namedtuple('TransactionReport', ['resolved', 'deps', 'failed'])


class Pattern(object):
    """
    Package matching pattern.

    Attributes:
        fields (dict): A dictionary of NEVREA fields with wildcard defaults.
    """

    FIELDS = (
        ('epoch', ('', ':')),
        ('name', ('', '')),
        ('version', ('-', '')),
        ('release', ('-', '')),
        ('arch', ('.', '')),
    )

    def __init__(self, nevrea):
        """
        Args:
            nevrea (dict): A dictionary containing the NEVREA as defined by FIELDS.
        """
        self.fields = {f[0]: nevrea.get(f[0]) for f in self.FIELDS}

    def __str__(self):
        pattern = []
        for name, sep in self.FIELDS:
            value = self.fields.get(name)
            if not value:
                continue
            if sep[0]:
                pattern.append(sep[0])
            pattern.append(value)
            if sep[1]:
                pattern.append(sep[1])
        return ''.join(pattern)


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
    def transaction_report(transaction):
        """
        Build a transaction report.

        Args:
            transaction: A DNF transaction.

        Returns:
            TransactionReport: A report.
        """
        resolved = []
        failed = []
        for item in transaction:
            po = item.installed or item.erased
            if po:
                _list = resolved
            else:
                _list = failed
            package = dict(
                qname=str(po),
                repoid=po.repoid,
                name=po.name,
                version=po.version,
                release=po.release,
                arch=po.arch,
                epoch=po.epoch)
            _list.append(package)
        return TransactionReport(resolved=resolved, deps=[], failed=failed)


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
        with LibDnf() as lib:
            lib.install(str(p) for p in patterns)
            if self.commit:
                lib.do_transaction()
            report = self.transaction_report(lib.transaction)
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
        with LibDnf() as lib:
            if advisories:
                patterns = set(str(p) for p in patterns)
                for ad, packages in lib.applicable_advisories(AdvisoryFilter(ids=advisories)):
                    for name, evr in packages:
                        patterns.add(name)
                if patterns:
                    lib.upgrade(patterns)
            else:
                lib.upgrade(patterns)
            if self.commit:
                lib.do_transaction()
            report = self.transaction_report(lib.transaction or ())
        return report._asdict()

    def uninstall(self, patterns):
        """
        Uninstall (remove) packages.

        Args:
            patterns (list): A list of Pattern.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibDnf() as lib:
            lib.remove(str(p) for p in patterns)
            if self.commit:
                lib.do_transaction()
            report = self.transaction_report(lib.transaction)
        return report._asdict()


class PackageGroup(API):
    """
    Package group management API.
    """

    @staticmethod
    def _resolved(lib, names):
        """
        Resolve group names to IDs.

        Args:
            lib (LibDnf): An opened lib.
            names (list): A list of group names.

        Yields:
            Group IDs.

        Raises:
            CompsError: When name cannot be resolved.
        """
        for p in names:
            group = lib.comps.group_by_pattern(p)
            if not group:
                raise CompsError(_('Group "{g}" not found.').format(g=p))
            else:
                yield group.id

    def install(self, names):
        """
        Install package groups.

        Args:
            names (list): A list of group names.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibDnf() as lib:
            lib.group_install(self._resolved(lib, names))
            if self.commit:
                lib.do_transaction()
            report = self.transaction_report(lib.transaction)
        return report._asdict()

    def uninstall(self, names):
        """
        Uninstall package groups.

        Args:
            names (list): A list of group names.

        Returns:
            dict: A dictionary representation of a TransactionReport.
        """
        with LibDnf() as lib:
            lib.group_remove(self._resolved(lib, names))
            if self.commit:
                lib.do_transaction()
            report = self.transaction_report(lib.transaction)
        return report._asdict()


class AdvisoryFilter(object):
    """
    Advisory filter.

    Filter by advisory IDs and/or types.
    """

    LABEL2TYPE = {
        _('BUGFIX'): hawkey.ADVISORY_BUGFIX,
        _('ENHANCEMENT'): hawkey.ADVISORY_ENHANCEMENT,
        _('SECURITY'): hawkey.ADVISORY_SECURITY,
        _('UNKNOWN'): hawkey.ADVISORY_UNKNOWN,
    }

    def __init__(self, ids=(), types=()):
        """
        Args:
            ids (list): List of advisory IDs.
            types (list): List of advisory types.  See: LABEL2TYPE.
        """
        self.ids = {s.upper() for s in ids}
        self.types = {self.LABEL2TYPE.get(s.upper(), hawkey.ADVISORY_UNKNOWN) for s in types}

    def match(self, advisory):
        """
        Match advisory.

        Args:
            advisory: An advisory.

        Returns:
            bool: True when matched.
        """
        if self.ids and (advisory.id.upper() not in self.ids):
            return False
        if self.types and (advisory.type not in self.types):
            return False
        return True


class LibDnf(Base):
    """
    DNF base.

    Notes:
        Requires dnf >= 2.7.5
    """

    # plugins cannot be reloaded within the process.
    __plugins_loaded = False

    def __init__(self):
        """
        Initialization.
        """
        super(LibDnf, self).__init__()
        self.conf.assumeyes = True

    def open(self):
        """
        Open the lib.
        """
        self.read_all_repos()
        if not LibDnf.__plugins_loaded:
            self.init_plugins()
            LibDnf.__plugins_loaded = True
        self.fill_sack('auto', True)
        self._plugins.run_sack()
        self.read_comps()

    def install(self, patterns):
        """
        Install packages specified by the patterns.

        Args:
            patterns: List of (str) patterns.

        Notes:
            Need to call do_transaction() to commit the changes.
        """
        for p in patterns:
            super(LibDnf, self).install(p)
        self.resolve(allow_erasing=False)
        self._plugins.run_resolved()
        self._download()

    def upgrade(self, patterns=()):
        """
        Upgrade packages specified by the patterns.

        Args:
            patterns: List of (str) patterns.

        Notes:
            Need to call do_transaction() to commit the changes.
        """
        if patterns:
            for p in patterns:
                super(LibDnf, self).upgrade(p)
        else:
            self.upgrade_all()
        self.resolve(allow_erasing=False)
        self._plugins.run_resolved()
        self._download()

    def remove(self, patterns):
        """
        Remove packages specified by the patterns.

        Args:
            patterns: List of (str) patterns.

        Notes:
            Need to call do_transaction() to commit the changes.
        """
        for p in patterns:
            super(LibDnf, self).remove(p)
        self.resolve(allow_erasing=False)
        self._plugins.run_resolved()

    def group_install(self, grp_ids):
        """
        Install package groups.

        Args:
            grp_ids: List of (str) group IDs.

        Notes:
            Need to call do_transaction() to commit the changes.
        """
        for grp_id in grp_ids:
            super(LibDnf, self).group_install(grp_id, ('mandatory', 'default'))
        self.resolve(allow_erasing=False)
        self._plugins.run_resolved()
        self._download()

    def group_remove(self, grp_ids):
        """
        Remove package groups.

        Args:
            grp_ids: List of (str) group IDs.

        Notes:
            Need to call do_transaction() to commit the changes.
        """
        for grp_id in grp_ids:
            super(LibDnf, self).group_remove(grp_id)
        self.resolve(allow_erasing=False)
        self._plugins.run_resolved()

    def list_advisories(self, filter=AdvisoryFilter()):
        """
        Get a list of advisories matching the filter.

        Args:
            filter (AdvisoryFilter): An optional filter.

        Returns:
            list: The list of matching advisories.
        """
        advisories = []
        query = self.sack.query().filter(upgradable=True)
        for package in query.installed():
            for ad in package.get_advisories(hawkey.GT):
                if filter.match(ad):
                    advisories.append(ad)
        return advisories

    def applicable_advisories(self, filter=AdvisoryFilter()):
        """
        Get a list of applicable advisories matching the filter.

        Args:
            filter (AdvisoryFilter): An optional filter.

        Returns:
            list: The list of applicable advisories.
        """
        advisories = []
        query = self.sack.query()
        installed = {(p.name, p.arch): p for p in query.installed()}
        for ad in self.list_advisories(filter):
            packages = set()
            for ap in ad.packages:
                try:
                    ip = installed[(ap.name, ap.arch)]
                except KeyError:
                    continue
                if self.sack.evr_cmp(ip.evr, ap.evr) < 0:
                    packages.add((ap.name, ap.evr))
            if packages:
                advisories.append((ad, packages))
        return advisories

    def _download(self):
        """
        Download packages as needed.
        """
        downloads = []
        for tx in self.transaction:
            if tx.installed:
                downloads.append(tx.installed)
        self.download_packages(downloads)

    def __enter__(self):
        super(LibDnf, self).__enter__()
        self.open()
        return self
