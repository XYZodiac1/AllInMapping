# -*- coding: utf-8 -*-
"""Context-sensitive toolbar/traffic preview and the node right-click menu."""
from javax.swing import JMenu, JMenuItem, JPopupMenu, SwingUtilities
from java.awt import BorderLayout

from allinmapping.model import SimpleMessageEditorController


class ToolbarMixin(object):
    """Context-sensitive toolbar/traffic preview and the node right-click menu."""

    def update_toolbar(self):
        has_selection = len(self.selected_nodes) > 0
        if hasattr(self, 'color_bar') and self.color_bar.isVisible() != has_selection:
            self.color_bar.setVisible(has_selection)

        if hasattr(self, 'request_panel'):
            req_out = None
            res_out = None
            source_svc = None

            if len(self.selected_nodes) > 0 and getattr(self, 'current_view_mode', 'map') != 'features':
                node = list(self.selected_nodes)[0]

                req_bytes = None
                res_bytes = None
                source_svc = None

                if hasattr(self, 'selected_method') and self.selected_method:
                    target_req = node.method_requests.get(self.selected_method)
                    if target_req:
                        req_bytes = target_req.getRequest()
                        res_bytes = target_req.getResponse()
                        source_svc = target_req.getHttpService()

                if not req_bytes and node.linked_request:
                    req_bytes = node.linked_request.getRequest()
                    res_bytes = node.linked_request.getResponse()
                    source_svc = node.linked_request.getHttpService()

                has_http_data = (len(node.statuses) > 0) or (req_bytes is not None) or (len(node.methods) > 0)

                if not getattr(node, 'is_manual', False) and has_http_data:
                    if req_bytes:
                        req_out = req_bytes
                    else:
                        host, port, use_https, req = self.build_http_request(node)
                        if req:
                            req_out = req
                            res_out = self.helpers.stringToBytes("[Preview not available - No linked request]")

                    if res_bytes:
                        res_out = res_bytes

            elif getattr(self, 'current_view_mode', 'map') == 'features' and getattr(self, 'selected_feature_req', None):
                f_req = self.selected_feature_req
                if f_req.get("req_b64"):
                    req_out = self.helpers.base64Decode(f_req["req_b64"])
                if f_req.get("res_b64"):
                    res_out = self.helpers.base64Decode(f_req["res_b64"])

            if req_out or res_out:
                final_req = req_out or self.helpers.stringToBytes("")
                final_res = res_out or self.helpers.stringToBytes("")

                # setMessage() on the existing, long-lived editor instances
                # has proven unreliable here - confirmed (via logging) to be
                # called with the correct, freshly-resolved bytes every time,
                # yet the display sometimes keeps showing an earlier node's
                # content regardless of any delay before the call. That
                # points to internal state inside Burp's IMessageEditor
                # component itself (most likely a scroll position or a
                # cached render) that setMessage() doesn't fully reset.
                # Rather than fight that further, replace the editor
                # components outright on every update - a brand new
                # IMessageEditor cannot have leftover state from anything.
                #
                # Also supply a real IMessageEditorController instead of
                # None - a response that Burp's own Proxy History viewer
                # renders correctly was confirmed to display blank in a
                # controller-less standalone editor, so some of Burp's
                # internal rendering appears to depend on that context
                # being available.
                controller = SimpleMessageEditorController(source_svc, final_req, final_res)

                new_request_editor = self.callbacks.createMessageEditor(controller, False)
                new_request_editor.setMessage(final_req, True)
                self.req_panel.removeAll()
                self.req_panel.add(new_request_editor.getComponent(), BorderLayout.CENTER)
                self.request_editor = new_request_editor

                new_response_editor = self.callbacks.createMessageEditor(controller, False)
                new_response_editor.setMessage(final_res, False)
                self.res_panel.removeAll()
                self.res_panel.add(new_response_editor.getComponent(), BorderLayout.CENTER)
                self.response_editor = new_response_editor

                self.req_panel.revalidate()
                self.req_panel.repaint()
                self.res_panel.revalidate()
                self.res_panel.repaint()

                if not self.request_panel.isVisible():
                    self.request_panel.setVisible(True)
                    if hasattr(self, 'outer_split_pane') and hasattr(self, 'mainPanel'):
                        self.outer_split_pane.setDividerLocation(int(self.mainPanel.getHeight() * 0.40))
                        SwingUtilities.invokeLater(lambda: self.traffic_split.setDividerLocation(0.5))
            else:
                # Nothing to show for the current selection (no node
                # selected, or the selected node has no captured
                # request/response at all) - explicitly clear both editors
                # rather than relying solely on hiding the panel. If
                # visibility doesn't actually change for some reason, or
                # the panel gets shown again before this runs, a stale
                # previous node's response must never be left on screen to
                # fool the user into thinking it belongs to the current
                # selection. The panel itself stays hidden, matching prior
                # behavior - it should not pop open for a node with nothing
                # to show.
                self.request_editor.setMessage(self.helpers.stringToBytes(""), True)
                self.response_editor.setMessage(self.helpers.stringToBytes(""), False)
                self.request_panel.setVisible(False)

        self.mainPanel.revalidate()
        self.mainPanel.repaint()

    def show_context_menu(self, component, x, y, node):
        menu = JPopupMenu()
        sel_count = len(self.selected_nodes)
        suffix = " (" + str(sel_count) + " Selected)" if sel_count > 1 else ""

        status_menu = JMenu("Set Testing Status" + suffix)
        st_none = JMenuItem("Not Started (Clear)")
        st_none.addActionListener(lambda e: self.set_node_status(""))
        status_menu.add(st_none)
        st_prog = JMenuItem("In Progress")
        st_prog.addActionListener(lambda e: self.set_node_status("In Progress"))
        status_menu.add(st_prog)
        st_test = JMenuItem("Tested")
        st_test.addActionListener(lambda e: self.set_node_status("Tested"))
        status_menu.add(st_test)
        st_vuln = JMenuItem("Vulnerable") 
        st_vuln.addActionListener(lambda e: self.set_node_status("Vulnerable"))
        status_menu.add(st_vuln)

        menu.add(status_menu)
        
        priv_menu = JMenu("Set Privilege Level" + suffix)
        for p_level in ["Clear", "No Auth", "Low Privs", "High Privs"]:
            item = JMenuItem(p_level)
            val = "" if p_level == "Clear" else p_level
            item.addActionListener(lambda e, v=val: self.set_node_privilege(v))
            priv_menu.add(item)
        menu.add(priv_menu)
        
        menu.addSeparator()
        copy_item = JMenuItem("Copy URL(s)" + suffix)
        copy_item.addActionListener(lambda e: self.copy_node_url(node))
        menu.add(copy_item)
        menu.addSeparator()
        repeater_item = JMenuItem("Send to Repeater")
        repeater_item.addActionListener(lambda e: self.send_to_repeater(node))
        menu.add(repeater_item)
        intruder_item = JMenuItem("Send to Intruder (Fuzz)")
        intruder_item.addActionListener(lambda e: self.send_to_intruder(node))
        menu.add(intruder_item)
        scan_item = JMenuItem("Do Active Scan")
        scan_item.addActionListener(lambda e: self.do_active_scan(node))
        menu.add(scan_item)
        menu.addSeparator()
        note_item = JMenuItem("Add / Edit Note")
        note_item.addActionListener(lambda e: self.edit_note(node))
        menu.add(note_item)
        menu.addSeparator()
        
        add_feat_item = JMenuItem("Add to Features View" + suffix)
        add_feat_item.addActionListener(lambda e: self.add_nodes_to_feature(list(self.selected_nodes)))
        menu.add(add_feat_item)
        menu.addSeparator()
        
        add_item = JMenuItem("Add Child Box")
        add_item.addActionListener(lambda e: self.add_custom_node(node))
        menu.add(add_item)

        collapse_item = JMenuItem("Toggle Hide/Show Children")
        collapse_item.addActionListener(lambda e: self.toggle_collapse(node))
        menu.add(collapse_item)

        del_item = JMenuItem("Delete Box(es)" + suffix)
        del_item.addActionListener(lambda e: self.delete_nodes(node))
        menu.add(del_item)
        menu.show(component, x, y)
