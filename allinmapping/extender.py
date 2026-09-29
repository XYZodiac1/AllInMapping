# -*- coding: utf-8 -*-
from burp import IContextMenuFactory, IExtensionStateListener, IHttpListener, ITab
from javax.swing import SwingUtilities
import time
import threading

from allinmapping.constants import EXTENSION_BUILD_STAMP
from allinmapping.ui.builder import UIBuilder

from allinmapping.core.persistence import PersistenceMixin
from allinmapping.core.ingest import IngestMixin
from allinmapping.core.node_ops import NodeOpsMixin
from allinmapping.core.filtering import FilteringMixin
from allinmapping.core.search import SearchMixin
from allinmapping.core.burp_actions import BurpActionsMixin
from allinmapping.views.map_render import MapRenderMixin
from allinmapping.views.grid import GridMixin
from allinmapping.views.features import FeaturesMixin
from allinmapping.ui.toolbar import ToolbarMixin
from allinmapping.ui.tabs import TabsMixin
from allinmapping.ui.dialogs import DialogsMixin
from allinmapping.export.excel import ExcelExportMixin
from allinmapping.export.svg import SvgExportMixin
from allinmapping.export.canvas import CanvasExportMixin


class AllInMapping(PersistenceMixin, IngestMixin, NodeOpsMixin, FilteringMixin,
                   SearchMixin, BurpActionsMixin, MapRenderMixin, GridMixin,
                   FeaturesMixin, ToolbarMixin, TabsMixin, DialogsMixin,
                   ExcelExportMixin, SvgExportMixin, CanvasExportMixin, ITab,
                   IHttpListener, IContextMenuFactory, IExtensionStateListener):
    """The extension object Burp talks to.

    All behaviour lives in the mixins (one per concern, see the imports
    above); this class only owns startup/shutdown and the ITab plumbing.
    Every mixin method operates on the shared state set up in
    registerExtenderCallbacks, so a method can move between mixins freely."""

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Interactive Attack Surface MindMap")

        # Version stamp - printed on load so it's possible to confirm from
        # the Output tab that a reload actually picked up the latest edits
        # rather than silently continuing to run a previously-loaded copy.
        # __file__ isn't available in Burp's Jython execution context, so
        # this is a manually-bumped constant (see EXTENSION_BUILD_STAMP
        # in constants.py) rather than a file hash.
        callbacks.printOutput(u"AllInMapping: build {0}".format(EXTENSION_BUILD_STAMP))

        self.copied_burp_request = None
        self.target_roots = {} 
        self.activeRoot = None

        self.selected_nodes = set() 
        self.selected_relation = None
        self.selected_method = None
        self.zoom_factor = 1.0 
        self.relation_paths = {}
        self.method_hitboxes = []

        self.is_vertical_layout = False
        self.current_theme = "Vibrant"

        self.relationships = []
        self.is_relating = False
        self.relate_source = None
        self.hide_tested = False

        self.custom_columns = []
        self.custom_mappings = []
        self.features = []
        self.visible_features = []
        self.is_recording_feature = False
        self.recorded_reqs = []
        self.selected_feature_req = None
        self.current_view_mode = "map"

        self.search_matches = []
        self.search_query = ""
        self.search_root = None
        self.search_index = -1

        self.internal_clipboard = []
        self.last_copied_text = ""

        self.undo_stack = []
        self.redo_stack = []

        self.live_processed_urls = set()
        self.unloaded = False

        # Load saved settings if they exist, otherwise use defaults
        saved_interval = self.callbacks.loadExtensionSetting("MindMap_AutosaveInterval")
        saved_save_exit = self.callbacks.loadExtensionSetting("MindMap_SaveOnExit")
        saved_auto_load = self.callbacks.loadExtensionSetting("MindMap_AutoLoad")

        self.autosave_interval_sec = int(saved_interval) if saved_interval is not None else 300
        self.save_on_exit = (saved_save_exit == "True") if saved_save_exit is not None else True
        self.auto_load_on_start = (saved_auto_load == "True") if saved_auto_load is not None else False
        self.last_saved_at = None

        self.callbacks.registerHttpListener(self)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerExtensionStateListener(self)
        SwingUtilities.invokeLater(UIBuilder(self))

        def auto_save_loop():
            elapsed = 0
            while not self.unloaded:
                time.sleep(1)
                if self.unloaded: break
                interval = self.autosave_interval_sec
                if interval <= 0:
                    elapsed = 0
                    continue
                elapsed += 1
                if elapsed >= interval:
                    elapsed = 0
                    if self.activeRoot:
                        self.save_project_state(silent=True)

        t = threading.Thread(target=auto_save_loop)
        t.daemon = True
        t.start()
        

    def extensionUnloaded(self):
        self.unloaded = True
        if self.save_on_exit:
            self.save_project_state(silent=True)

    def getTabCaption(self): return "AllInMapping"

    def getUiComponent(self): return self.mainPanel
