import sys
from os import environ

from rhsm import config as rhsmConfig

try:
    import yum
    IS_YUM = True
except ImportError:
    IS_YUM = False

if sys.version_info[0] == 3:
    from configparser import ConfigParser, NoOptionError
else:
    from ConfigParser import ConfigParser, NoOptionError


def plugin_enabled(filepath, environment_variable=None, force=False):
    return force or (config_enabled(filepath) and not environment_disabled(environment_variable) and not subman_profile_enabled())


def config_enabled(filepath):
    try:
        parser = ConfigParser()
        parser.read(filepath)
        return parser.getint('main', 'enabled') == 1
    except:
        return False


def environment_disabled(variable):
    return variable is not None and variable in environ and environ[variable] != ''

def has_subman_yum_package_plugin():
    try:
        import rhsm.yum.whatever.plugin
        return True
    except:
        return False


def subman_profile_enabled():
    cfg = rhsmConfig.initConfig()
    try:
        config_enabled = cfg.get('rhsm', 'package_profile_on_trans') == '1'
        if config_enabled and IS_YUM:
            return has_subman_yum_package_plugin()

        return config_enabled
    except NoOptionError:
        return False
