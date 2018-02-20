import os
import sys

sys.path.append('/usr/lib/yum-plugins')
sys.path.append('/usr/share/rhsm')

try:
  from subscription_manager import action_client
except ImportError:
  from subscription_manager import certmgr

try:
  from subscription_manager.identity import ConsumerIdentity
except ImportError:
  from subscription_manager.certlib import ConsumerIdentity

try:
    from subscription_manager.injectioninit import init_dep_injection
    init_dep_injection()
except ImportError:
    pass

from rhsm import connection

def upload_package_profile():
    get_manager().profilelib._do_update()


def purge_package_cache():
    try:
        os.remove('/var/lib/rhsm/packages/packages.json')
    except OSError:
        pass


def get_manager():
    if 'subscription_manager.action_client' in sys.modules:
        mgr = action_client.ActionClient()
    else:
        # for compatability with subscription-manager > =1.13
        uep = connection.UEPConnection(cert_file=ConsumerIdentity.certpath(),
                                        key_file=ConsumerIdentity.keypath())
        mgr = certmgr.CertManager(uep=uep)
    return mgr
