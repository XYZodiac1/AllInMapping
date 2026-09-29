# -*- coding: utf-8 -*-
"""Features view: recorded request chains."""
from javax.swing import JMenu, JMenuItem, JOptionPane, JPopupMenu, SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseAdapter
from java.lang import Boolean, String
import uuid


class FeaturesMasterTableModel(DefaultTableModel):
    def __init__(self, extender):
        self.extender = extender
        DefaultTableModel.__init__(self, ["Feature Name", "Reqs", "Tested", "Privilege"], 0)

    def getColumnClass(self, col):
        if col == 2: return Boolean
        return String

    def isCellEditable(self, row, col):
        return col == 0 or col >= 2

    def setValueAt(self, val, row, col):
        if col == 0:
            feat = self.extender.visible_features[row]
            feat["name"] = unicode(val) if val else u"Unnamed Feature"
            self.extender.save_state()
        elif col == 2:
            feat = self.extender.visible_features[row]
            feat["tested"] = bool(val)
            self.extender.save_state()
            if getattr(self.extender, 'hide_tested', False):
                SwingUtilities.invokeLater(lambda: self.extender.update_features_master_table())
        elif col == 3:
            feat = self.extender.visible_features[row]
            feat["privilege"] = unicode(val) if val else u""
            self.extender.save_state()
            self.extender.update_features_master_table()
            
        DefaultTableModel.setValueAt(self, val, row, col)


class FeatureReqsTableModel(DefaultTableModel):
    def __init__(self, extender):
        self.extender = extender
        self.current_feature = None
        DefaultTableModel.__init__(self, ["Method", "URL", "Notes", "Privilege"], 0)

    def isCellEditable(self, row, col):
        return col >= 2

    def setValueAt(self, val, row, col):
        if col == 2 and self.current_feature:
            self.current_feature["requests"][row]["notes"] = unicode(val) if val else u""
            self.extender.save_state()
        elif col == 3:
            if self.current_feature:
                self.current_feature["requests"][row]["privilege"] = unicode(val) if val else u""
            else:
                self.extender.recorded_reqs[row]["privilege"] = unicode(val) if val else u""
            self.extender.save_state()
            self.extender.update_features_detail_table()

        DefaultTableModel.setValueAt(self, val, row, col)


class FeatureMasterMouseHandler(MouseAdapter):
    def __init__(self, extender): self.extender = extender
    def mousePressed(self, e): self.check_popup(e)
    def mouseReleased(self, e): self.check_popup(e)
    def mouseClicked(self, e):
        row = self.extender.features_master_table.rowAtPoint(e.getPoint())
        if row == -1: 
            self.extender.features_master_table.clearSelection()
            self.extender.features_reqs_model.current_feature = None
            self.extender.update_features_detail_table()
            self.extender.close_feature_note()
            self.extender.selected_feature_req = None
            self.extender.update_toolbar()
        else:
            if SwingUtilities.isLeftMouseButton(e):
                if not self.extender.features_master_table.isRowSelected(row):
                    self.extender.features_master_table.setRowSelectionInterval(row, row)
                
                model_row = self.extender.features_master_table.convertRowIndexToModel(row)
                self.extender.features_reqs_model.current_feature = self.extender.visible_features[model_row]
                self.extender.update_features_detail_table()
                self.extender.selected_feature_req = None
                self.extender.update_toolbar()

                if e.getClickCount() == 1:
                    feat = self.extender.visible_features[model_row]
                    self.extender.editing_feature = feat
                    self.extender.feature_note_area.setText(feat.get("notes", ""))
                    self.extender.feature_note_scroll.setVisible(True)
                    self.extender.feature_note_area.requestFocusInWindow()

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            row = self.extender.features_master_table.rowAtPoint(e.getPoint())
            if row >= 0:
                if not self.extender.features_master_table.isRowSelected(row):
                    self.extender.features_master_table.setRowSelectionInterval(row, row)
                model_row = self.extender.features_master_table.convertRowIndexToModel(row)
                menu = JPopupMenu()
                p_menu = JMenu("Set Feature Privilege")
                for p_level in ["Clear", "No Auth", "Low Privs", "High Privs"]:
                    item = JMenuItem(p_level)
                    val = "" if p_level == "Clear" else p_level
                    def set_fp(evt, v=val, r=model_row):
                        feat = self.extender.visible_features[r]
                        feat["privilege"] = v
                        self.extender.save_state()
                        self.extender.update_features_master_table()
                    item.addActionListener(set_fp)
                    p_menu.add(item)
                menu.add(p_menu)
                
                menu.addSeparator()
                rep_item = JMenuItem("Send Feature to Repeater")
                rep_item.addActionListener(lambda evt, r=model_row: self.extender.send_feature_to_repeater(self.extender.visible_features[r]))
                menu.add(rep_item)
                
                menu.show(e.getComponent(), e.getX(), e.getY())


class FeatureReqsMouseHandler(MouseAdapter):
    def __init__(self, extender): self.extender = extender
    def mousePressed(self, e): self.check_popup(e)
    def mouseReleased(self, e): self.check_popup(e)
    def mouseClicked(self, e):
        row = self.extender.features_reqs_table.rowAtPoint(e.getPoint())
        if row == -1: 
            self.extender.features_reqs_table.clearSelection()
            self.extender.selected_feature_req = None
            self.extender.update_toolbar()
        else:
            if SwingUtilities.isLeftMouseButton(e):
                if not self.extender.features_reqs_table.isRowSelected(row):
                    self.extender.features_reqs_table.setRowSelectionInterval(row, row)
                model_row = self.extender.features_reqs_table.convertRowIndexToModel(row)
                if self.extender.features_reqs_model.current_feature:
                    self.extender.selected_feature_req = self.extender.features_reqs_model.current_feature["requests"][model_row]
                else:
                    self.extender.selected_feature_req = self.extender.recorded_reqs[model_row]
                self.extender.update_toolbar()
        self.extender.close_feature_note()

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            row = self.extender.features_reqs_table.rowAtPoint(e.getPoint())
            if row >= 0:
                if not self.extender.features_reqs_table.isRowSelected(row):
                    self.extender.features_reqs_table.setRowSelectionInterval(row, row)
                model_row = self.extender.features_reqs_table.convertRowIndexToModel(row)
                menu = JPopupMenu()
                p_menu = JMenu("Set Request Privilege")
                for p_level in ["Clear", "No Auth", "Low Privs", "High Privs"]:
                    item = JMenuItem(p_level)
                    val = "" if p_level == "Clear" else p_level
                    def set_rp(evt, v=val, r=model_row):
                        if self.extender.features_reqs_model.current_feature:
                            req = self.extender.features_reqs_model.current_feature["requests"][r]
                            req["privilege"] = v
                            self.extender.save_state()
                        else:
                            req = self.extender.recorded_reqs[r]
                            req["privilege"] = v
                        self.extender.update_features_detail_table()
                    item.addActionListener(set_rp)
                    p_menu.add(item)
                menu.add(p_menu)
                
                menu.addSeparator()
                rep_item = JMenuItem("Send to Repeater")
                def send_req(evt, r=model_row):
                    if self.extender.features_reqs_model.current_feature:
                        req_data = self.extender.features_reqs_model.current_feature["requests"][r]
                    else:
                        req_data = self.extender.recorded_reqs[r]
                    self.extender.send_feature_req_to_repeater(req_data)
                rep_item.addActionListener(send_req)
                menu.add(rep_item)
                
                menu.show(e.getComponent(), e.getX(), e.getY())


class FeaturesMixin(object):
    """Features view: recorded request chains."""

    def add_nodes_to_feature(self, nodes_to_add):
        if not nodes_to_add: return
        
        valid_nodes = []
        for n in nodes_to_add:
            if n.linked_request or n.methods:
                valid_nodes.append(n)
                
        if not valid_nodes:
            JOptionPane.showMessageDialog(self.mainPanel, "Selected nodes do not have associated HTTP requests.")
            return

        options = [f["name"] for f in self.features]
        options.append("[+] Create New Feature")
        
        choice = JOptionPane.showInputDialog(
            self.mainPanel, 
            "Select a Feature to add {} request(s) to:".format(len(valid_nodes)), 
            "Add to Feature", 
            JOptionPane.QUESTION_MESSAGE, 
            None, 
            options, 
            options[0] if options else None
        )
        
        if not choice: return
        
        target_feature = None
        if choice == "[+] Create New Feature":
            new_name = JOptionPane.showInputDialog(self.mainPanel, "Enter New Feature Name:")
            if not new_name or not new_name.strip(): return
            target_feature = {
                "id": str(uuid.uuid4()),
                "name": new_name.strip(),
                "requests": [],
                "notes": "",
                "privilege": "",
                "tested": False
            }
            self.features.append(target_feature)
        else:
            for f in self.features:
                if f["name"] == choice:
                    target_feature = f
                    break
                    
        if not target_feature: return

        added_count = 0
        for node in valid_nodes:
            methods_to_add = node.method_requests.keys() if node.method_requests else [None]
            
            for m in methods_to_add:
                req_b64 = ""
                res_b64 = ""
                svc_data = None
                method = m if m else "GET"
                
                reqRes = node.method_requests.get(m) if m else node.linked_request
                
                if reqRes:
                    req_bytes = reqRes.getRequest()
                    res_bytes = reqRes.getResponse()
                    svc = reqRes.getHttpService()
                    if req_bytes:
                        req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req_bytes))
                        try:
                            info = self.helpers.analyzeRequest(req_bytes)
                            method = info.getMethod()
                        except: pass
                    if res_bytes:
                        res_b64 = self.helpers.bytesToString(self.helpers.base64Encode(res_bytes))
                    if svc:
                        svc_data = {
                            "host": svc.getHost(),
                            "port": svc.getPort(),
                            "protocol": svc.getProtocol()
                        }
                else:
                    host, port, use_https, req_bytes = self.build_http_request(node)
                    if req_bytes:
                        req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req_bytes))
                        try:
                            info = self.helpers.analyzeRequest(req_bytes)
                            method = info.getMethod()
                        except: pass
                        svc_data = {
                            "host": host,
                            "port": port,
                            "protocol": "https" if use_https else "http"
                        }
                        
                if req_b64:
                    target_feature["requests"].append({
                        "id": str(uuid.uuid4()),
                        "method": method,
                        "url": node.get_full_url(),
                        "notes": "",
                        "privilege": getattr(node, 'privilege', ""),
                        "req_b64": req_b64,
                        "res_b64": res_b64,
                        "svc_data": svc_data
                    })
                    added_count += 1
                
        if added_count > 0:
            self.save_state()
            if getattr(self, 'current_view_mode', 'map') == 'features':
                self.update_features_master_table()
                if hasattr(self, 'features_reqs_model') and self.features_reqs_model.current_feature == target_feature:
                    self.update_features_detail_table()

    def update_features_master_table(self):
        self.features_master_model.setRowCount(0)
        self.visible_features = []
        for f in self.features:
            if getattr(self, 'hide_tested', False) and f.get("tested", False):
                continue
            self.visible_features.append(f)
            self.features_master_model.addRow([f["name"], str(len(f["requests"])), Boolean(f.get("tested", False)), f.get("privilege", "")])

    def update_features_detail_table(self):
        self.features_reqs_model.setRowCount(0)
        reqs = []
        if self.features_reqs_model.current_feature:
            reqs = self.features_reqs_model.current_feature["requests"]
        elif self.is_recording_feature:
            reqs = self.recorded_reqs

        for r in reqs:
            self.features_reqs_model.addRow([r["method"], r["url"], r.get("notes", ""), r.get("privilege", "")])
