# -*- coding: utf-8 -*-
"""Workspace state: (de)serialization, undo/redo, project-file and JSON save/load."""
from javax.swing import JFileChooser, JOptionPane, SwingUtilities
from java.awt import Color
import json
import time

from allinmapping.model import MindMapNode, RestoredHttpService, RestoredReqRes


class PersistenceMixin(object):
    """Workspace state: (de)serialization, undo/redo, project-file and JSON save/load."""

    def export_workspace_json(self, event=None):
        if not self.target_roots: return
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Workspace JSON File")
        if chooser.showSaveDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith(".json"): filepath += ".json"
            try:
                state_dict = self.get_full_state()
                with open(filepath, 'w') as f:
                    json.dump(state_dict, f, indent=4)
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "Workspace exported to JSON successfully!")
            except Exception as e:
                self.callbacks.printError("Failed to export JSON: " + str(e))
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "Failed to export JSON: " + str(e))

    def import_workspace_json(self, event=None):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Workspace JSON File")
        if chooser.showOpenDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                self.apply_state(data)
                self.undo_stack = []
                self.redo_stack = []
                self.set_zoom(1.0) 
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "Workspace imported from JSON successfully!")
            except Exception as e:
                self.callbacks.printError("Failed to import JSON: " + str(e))
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "Failed to import JSON: " + str(e))

    def save_project_state(self, event=None, silent=False):
        if not self.target_roots: return
        try:
            state_dict = self.get_full_state()
            json_string = json.dumps(state_dict)
            self.callbacks.saveExtensionSetting("MindMapProjectState", json_string)
            self.last_saved_at = time.strftime("%H:%M:%S", time.localtime())
            self.update_last_saved_label()
            if not silent and event:
                JOptionPane.showMessageDialog(self.mainPanel, "Workspace saved to the Burp Project successfully!")
        except Exception as e:
            self.callbacks.printError("Failed to save state: " + str(e))
            if not silent and event:
                JOptionPane.showMessageDialog(self.mainPanel, "Failed to save: " + str(e))

    def update_last_saved_label(self):
        if not hasattr(self, 'last_saved_label'): return
        text = "Last saved: " + self.last_saved_at if self.last_saved_at else "Last saved: never"
        SwingUtilities.invokeLater(lambda: self.last_saved_label.setText(text))

    def load_project_state(self, event=None):
        try:
            saved_json = self.callbacks.loadExtensionSetting("MindMapProjectState")
            if saved_json:
                data = json.loads(saved_json)
                self.apply_state(data)
                self.undo_stack = []
                self.redo_stack = []
                self.set_zoom(1.0) 
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "Workspace loaded from Burp Project successfully!")
            else:
                if event:
                    JOptionPane.showMessageDialog(self.mainPanel, "No saved workspace found in this project.")
        except Exception as e:
            self.callbacks.printError("Failed to restore Workspace: " + str(e))
            if event:
                JOptionPane.showMessageDialog(self.mainPanel, "Failed to load Workspace: " + str(e))

    def get_full_state(self):
        targets_state = {}
        for host, root in self.target_roots.items():
            targets_state[host] = self.serialize_node(root)
        return {
            "targets": targets_state,
            "relationships": list(self.relationships),
            "custom_columns": list(self.custom_columns),
            "custom_mappings": list(self.custom_mappings),
            "features": list(self.features)
        }

    def apply_state(self, state):
        self.target_roots = {}
        self.tabbed_pane.removeAll()
        self.activeRoot = None
        self.custom_columns = state.get("custom_columns", [])
        self.custom_mappings = state.get("custom_mappings", [])
        self.features = state.get("features", [])

        if hasattr(self, 'table_model'):
            self.table_model.setColumnCount(0)
            for c in self.table_model.base_cols + self.custom_columns:
                self.table_model.addColumn(c)

        for host, root_data in state.get("targets", {}).items():
            root_node = self.deserialize_node(root_data, None)
            self.add_target_tab(host, root_node)

        self.relationships = state.get("relationships", [])
        self.selected_nodes = set()
        self.selected_method = None
        self.update_toolbar()

        if hasattr(self, 'features_master_model'):
            self.update_features_master_table()
            
        if hasattr(self, 'gridTable'):
            self.apply_grid_renderer()

        if self.activeRoot:
            self.auto_arrange(None)

    def save_state(self):
        state = self.get_full_state()
        self.undo_stack.append(state)
        if len(self.undo_stack) > 10: self.undo_stack.pop(0)
        self.redo_stack = []

    def undo(self, event=None):
        if not self.undo_stack: return
        self.redo_stack.append(self.get_full_state())
        if len(self.redo_stack) > 10: self.redo_stack.pop(0)
        prev_state = self.undo_stack.pop()
        self.apply_state(prev_state)

    def redo(self, event=None):
        if not self.redo_stack: return
        self.undo_stack.append(self.get_full_state())
        if len(self.undo_stack) > 10: self.undo_stack.pop(0)
        next_state = self.redo_stack.pop()
        self.apply_state(next_state)

    def serialize_color(self, c):
        if not c: return None
        return "#{:02x}{:02x}{:02x}{:02x}".format(c.getRed(), c.getGreen(), c.getBlue(), c.getAlpha())

    def deserialize_color(self, hex_str):
        if not hex_str: return None
        r = int(hex_str[1:3], 16)
        g = int(hex_str[3:5], 16)
        b = int(hex_str[5:7], 16)
        a = int(hex_str[7:9], 16) if len(hex_str) == 9 else 255
        return Color(r, g, b, a)

    def serialize_node(self, node):
        method_reqs = {}
        for m, reqRes in node.method_requests.items():
            if reqRes:
                req = reqRes.getRequest()
                res = reqRes.getResponse()
                svc = reqRes.getHttpService()
                m_req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req)) if req else ""
                m_res_b64 = self.helpers.bytesToString(self.helpers.base64Encode(res)) if res else ""
                m_svc_data = None
                if svc:
                    m_svc_data = {"host": svc.getHost(), "port": svc.getPort(), "protocol": svc.getProtocol()}
                method_reqs[m] = {"req": m_req_b64, "res": m_res_b64, "svc": m_svc_data}

        req_b64 = ""
        res_b64 = ""
        svc_data = None

        if node.linked_request:
            req = node.linked_request.getRequest()
            if req: req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req))
            res = node.linked_request.getResponse()
            if res: res_b64 = self.helpers.bytesToString(self.helpers.base64Encode(res))
            svc = node.linked_request.getHttpService()
            if svc:
                svc_data = {
                    "host": svc.getHost(),
                    "port": svc.getPort(),
                    "protocol": svc.getProtocol()
                }

        return {
            "id": node.id,
            "text": node.text, "x": node.x, "y": node.y, "width": node.width, "height": node.height,
            "methods": [unicode(m) for m in node.methods], 
            "statuses": [int(s) for s in node.statuses], 
            "content_lengths": [int(c) for c in node.content_lengths],
            "severity": node.severity, "note": node.note, "privilege": getattr(node, 'privilege', ""), 
            "custom_color": self.serialize_color(node.custom_color),
            "status": node.status, 
            "params": [unicode(p) for p in node.params],
            "collapsed": getattr(node, 'collapsed', False), 
            "is_manual": getattr(node, 'is_manual', False),
            "is_custom_mapping": getattr(node, 'is_custom_mapping', False),
            "manual_resize": getattr(node, 'manual_resize', False),
            "req_b64": req_b64,
            "res_b64": res_b64,
            "svc_data": svc_data,
            "method_requests": method_reqs,
            "custom_cols": getattr(node, 'custom_cols', {}),
            "children": [self.serialize_node(child) for child in node.children]
        }

    def deserialize_node(self, data, parent):
        node = MindMapNode(data["text"], parent=parent)
        if "id" in data: node.id = data["id"]
        node.x = data.get("x", 0)
        node.y = data.get("y", 0)
        node.width = data.get("width", 70)
        node.height = data.get("height", 44)
        node.methods = set(data.get("methods", []))
        node.statuses = set(data.get("statuses", []))
        node.content_lengths = set(data.get("content_lengths", []))
        node.severity = data.get("severity", None)
        node.note = data.get("note", "")
        node.privilege = data.get("privilege", "")
        node.custom_color = self.deserialize_color(data.get("custom_color", None))

        node.status = data.get("status", "")
        node.params = set(data.get("params", []))
        node.collapsed = data.get("collapsed", False) 
        node.is_manual = data.get("is_manual", False)
        node.is_custom_mapping = data.get("is_custom_mapping", False)
        node.manual_resize = data.get("manual_resize", False)
        node.custom_cols = data.get("custom_cols", {})

        req_b64 = data.get("req_b64", "")
        res_b64 = data.get("res_b64", "")
        svc_data = data.get("svc_data", None)

        if req_b64 or res_b64:
            req_bytes = self.helpers.base64Decode(req_b64) if req_b64 else None
            res_bytes = self.helpers.base64Decode(res_b64) if res_b64 else None
            svc = None
            if svc_data:
                svc = RestoredHttpService(svc_data["host"], svc_data["port"], svc_data["protocol"])
            node.linked_request = RestoredReqRes(req_bytes, res_bytes, svc)
            
        node.method_requests = {}
        if "method_requests" in data:
            for m, m_data in data["method_requests"].items():
                m_req_b64 = m_data.get("req", "")
                m_res_b64 = m_data.get("res", "")
                m_svc_data = m_data.get("svc", None)
                
                req_bytes = self.helpers.base64Decode(m_req_b64) if m_req_b64 else None
                res_bytes = self.helpers.base64Decode(m_res_b64) if m_res_b64 else None
                svc = None
                if m_svc_data:
                    svc = RestoredHttpService(m_svc_data["host"], m_svc_data["port"], m_svc_data["protocol"])
                node.method_requests[m] = RestoredReqRes(req_bytes, res_bytes, svc)

        for child_data in data.get("children", []):
            node.children.append(self.deserialize_node(child_data, node))
        return node
