# -*- coding: utf-8 -*-
"""Burp entry point for AllInMapping.

Load this file in Burp (Extensions > Add > Python). The extension itself lives
in the allinmapping/ package next to this file; this stub only makes that
package importable and hands over to allinmapping.extender.AllInMapping.
"""
import os
import sys

from burp import IBurpExtender

_PACKAGE = "allinmapping"


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # __file__ isn't available in Burp's Jython execution context, so the
        # package directory comes from Burp itself.
        base = os.path.dirname(os.path.abspath(callbacks.getExtensionFilename()))
        if base not in sys.path:
            sys.path.insert(0, base)

        # Jython keeps imported modules cached across extension reloads, so
        # without this, edits to the package would only show up after a Burp
        # restart.
        for name in list(sys.modules):
            if name == _PACKAGE or name.startswith(_PACKAGE + "."):
                del sys.modules[name]

        from allinmapping.extender import AllInMapping
        self.extension = AllInMapping()
        self.extension.registerExtenderCallbacks(callbacks)
