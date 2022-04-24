# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whois_domain_ip
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Guillermo Herreros Peláez <guillermoherrerostic@gmail.com>
#
# Created:     24/04/20202
# Copyright:   (c) Guillermo Herreros Peláez 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import whois
from ipwhois import IPWhois
from IPy import IP
import subprocess

class sfp_whois_domain_ip(SpiderFootPlugin):

    meta = {
        'name': "Whois Domain IP",
        'summary': "Perform a whois lookup on the domain name or IP address and checks if it is public or private.",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            try:
                if IP(eventData):
                    if IP(eventData).iptype() == 'PUBLIC':
                            ip_data = IPWhois(eventData)
                            print(ip_data.lookup_whois())
                    else:
                            print('Domain or IP address '+ eventData + ' is not public.')
                                
            except:
                print(whois.whois(eventData))

            if not ip_data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        typ = "DOMAIN_NAME"

        evt = SpiderFootEvent(typ, ip_data, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_new_module class