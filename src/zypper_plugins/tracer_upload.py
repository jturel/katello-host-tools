#!/usr/bin/python
#
# Copyright 2019 ATIX AG
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should

import json
import httplib
from os import path, environ
import sys
import logging
from rhsm.config import RhsmConfigParser, initConfig
from zypp_plugin import Plugin

sys.path.append('/usr/share/rhsm')
from subscription_manager.identity import ConsumerIdentity

# The path is defined in zypper, see https://github.com/openSUSE/libzypp/blob/master/zypp/target/TargetImpl.cc
REBOOT_NEEDED_FLAG = "/var/run/reboot-needed"

class TracerUploadPlugin(Plugin):
    def collect_data(self):
        apps = {}
        if path.isfile(REBOOT_NEEDED_FLAG):
            apps["kernel"] = { "helper": "You will have to reboot your computer", "type": "static" }
        return apps

    def upload_tracer_profile(self):
        data =  json.dumps({ "traces": self.collect_data() })
        headers = { "Content-Type": "application/json" }

        cfg = initConfig()
        conn = httplib.HTTPSConnection(
            RhsmConfigParser.get(cfg,'server', 'hostname'),
            RhsmConfigParser.get(cfg,'server', 'port'),
            key_file=ConsumerIdentity.keypath(),
            cert_file=ConsumerIdentity.certpath()
        )
        conn.request('PUT', '/rhsm/consumers/%s/tracer' % (ConsumerIdentity.read().getConsumerId()), data, headers=headers)
        conn.getresponse()

    def PLUGINEND(self, headers, body):
        logging.info("PLUGINEND")

        logging.info("Uploading Tracer Profile")
        try:
            self.upload_tracer_profile()
        except:
            logging.error("Unable to upload Tracer Profile")

        self.ack()

if __name__ == '__main__':
    if "DISABLE_TRACER_UPLOAD_PLUGIN" in environ:
        logging.info("$DISABLE_TRACER_UPLOAD_PLUGIN is set - disabling katello tracer upload plugin")

        # a dummy Plugin is needed
        plugin = Plugin()
    else:
        plugin = TracerUploadPlugin()

    plugin.main()
