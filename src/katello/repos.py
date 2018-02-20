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
from rhsm.connection import GoneException, RemoteServerException, UEPConnection

try:
    import json
except ImportError:
    import simplejson as json

def error_message(msg):
    sys.stderr.write(msg + "\n")


def lookup_consumer_id():
    try:
        certificate = ConsumerIdentity.read()
        return certificate.getConsumerId()
    except IOError:
        return None


def upload_enabled_repos_report(report):
    uep = UEP()
    content = report.content
    consumer_id = lookup_consumer_id()
    if consumer_id is None:
        error_message('Cannot upload enabled repos report, is this client registered?')
    else:
        cache = EnabledRepoCache(consumer_id, content)
        if not cache.is_valid():
            uep.report_enabled(consumer_id, content)
            cache.save()


class EnabledRepoCache:
    CACHE_FILE = '/var/cache/katello-agent/enabled_repos.json'

    def __init__(self, consumer_id, content):
        self.consumer_id = consumer_id
        self.content = content

    @staticmethod
    def remove_cache():
        try:
            os.remove(EnabledRepoCache.CACHE_FILE)
        except OSError:
            pass

    def is_valid(self):
        if not os.path.isfile(self.CACHE_FILE):
            return False
        file = open(self.CACHE_FILE)
        try:
            return self.data() == json.loads(file.read())
        except ValueError:
            return False

    def data(self):
        return {self.consumer_id: self.content}

    def save(self):
        file = open(self.CACHE_FILE, 'w')
        file.write(json.dumps(self.data()))
        file.close()


class UEP(UEPConnection):
    """
    Represents the UEP.
    """

    def __init__(self):
        key = ConsumerIdentity.keypath()
        cert = ConsumerIdentity.certpath()
        UEPConnection.__init__(self, key_file=key, cert_file=cert)

    def report_enabled(self, consumer_id, report):
        """
        Report enabled repositories to the UEP.
        :param consumer_id: The consumer ID.
        :type consumer_id: str
        :param report: The report to send.
        :type report: dict
        """
        method = '/systems/%s/enabled_repos' % self.sanitize(consumer_id)
        try:
            self.conn.request_put(method, report)
        except (RemoteServerException, GoneException):
            e = sys.exc_info()[1] # backward and forward compatible way to get the exception
            error_message(str(e))
