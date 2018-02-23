from katello.repos import lookup_consumer_id
from katello.rhsm_compat import ConsumerIdentity, UEPConnection

def upload_tracer_profile(queryfunc, plugin):
    key = ConsumerIdentity.keypath()
    cert = ConsumerIdentity.certpath()
    uep = UEPConnection(key_file=key, cert_file=cert)

    method = '/consumers/%s/tracer' % uep.sanitize(lookup_consumer_id())
    data = {"tracer": get_apps(queryfunc, plugin)}
    uep.conn.request_put(method, data)

def get_apps(queryfunc, plugin):
    """
    Return a array with nested arrays
    containing name, how to restart & app type
    for every package that needs restarting
    """
    apps = {}
    for app in queryfunc(plugin):
        apps[app.name] = {"helper": app.helper, "type": app.type}
    if plugin:
        #Don't report yum/dnf back if this if being ran via them.
        apps.pop("yum", None)
        apps.pop("dnf", None)
    return apps
