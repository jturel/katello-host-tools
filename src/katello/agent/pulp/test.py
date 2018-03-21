from libdnf import *


def test():
    from dnf.cli.main import main as cli
    cli(['install', 'ksh'])


def test_pattern():
    p = Pattern({'name': 'jeff', 'version-': '1', 'arch': 'x68', 'release-': '2'})
    print(p)


def test_packages():
    names = ['bmake', 'mk-files']
    print('\nBegin')
    p = Package()
    log.info('Installed: %s', p.install(names))
    log.info('Updated: %s', p.update(names))
    log.info('Uninstall: %s', p.uninstall(names))
    print('\nEnd')


def test_groups():
    names = ['Pulp Consumer']
    print('\nBegin')
    g = PackageGroup()
    log.info('Installed (group) %s', g.install(names))
    log.info('Uninstall (group) %s', g.uninstall(names))
    print('\nEnd')


def test_advisories():
    with LibDnf() as dnf:
        advisories = dnf.list_advisories()
        for ad in advisories:
            print('Ad: {}'.format(ad.id))
            for p in ad.packages:
                print('\t{}'.format(p.name))
        print('total: {}'.format(len(advisories)))


def test_applicable_advisories():
    with LibDnf() as dnf:
        advisories = dnf.applicable_advisories()
        for ad, packages in advisories:
            print('Ad: {}'.format(ad.id))
            for p in sorted(packages):
                print('\t{}'.format(p))
        print('total: {}'.format(len(advisories)))


def test_advisory_update():
    print('\nBegin')
    p = Package()
    log.info('Ad-Update: %s', p.update(advisories=['FEDORA-2017-de8a421dcd']))
    print('\nEnd')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_packages()
    # test_applicable_advisories()
    # test_pattern()
    # test_advisories()
    # test_advisory_update()
