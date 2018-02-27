import os

from katello.rhsm import get_manager


def upload_package_profile():
    get_manager().profilelib._do_update()

def purge_package_cache():
    try:
        os.remove('/var/lib/rhsm/packages/packages.json')
    except OSError:
        pass

