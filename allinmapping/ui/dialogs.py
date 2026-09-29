# -*- coding: utf-8 -*-
"""Modal dialogs: settings and custom mapping (with its sample-request picker)."""
from javax.swing import BorderFactory, BoxLayout, JButton, JCheckBox, JComboBox, JDialog, JLabel, JOptionPane, JPanel, JScrollPane, JSplitPane, JTable, JTextField, ListSelectionModel
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Component, Dimension, FlowLayout, Font
from java.awt.event import MouseAdapter
from java.lang import Integer, String
import uuid


class SampleRequestTableModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, ["#", "Method", "URL", "Status"], 0)

    def getColumnClass(self, col):
        if col in (0, 3): return Integer
        return String

    def isCellEditable(self, row, col):
        return False


class DialogsMixin(object):
    """Modal dialogs: settings and custom mapping (with its sample-request picker)."""

    def open_settings_dialog(self, event=None):
        dialog = JDialog()
        dialog.setTitle("Settings")
        dialog.setModal(True)
        dialog.setSize(380, 260)
        dialog.setLocationRelativeTo(self.mainPanel)

        content = JPanel(BorderLayout(8, 8))
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        dialog.setContentPane(content)

        form = JPanel()
        form.setLayout(BoxLayout(form, BoxLayout.Y_AXIS))

        def add_row(comp):
            comp.setAlignmentX(Component.LEFT_ALIGNMENT)
            form.add(comp)

        def make_hint(text):
            hint = JLabel(text)
            hint.setForeground(Color.GRAY)
            hint.setFont(Font("SansSerif", Font.PLAIN, 10))
            hint.setBorder(BorderFactory.createEmptyBorder(0, 7, 8, 0))
            return hint

        row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        row.add(JLabel("Autosave interval (seconds):"))
        interval_field = JTextField(str(self.autosave_interval_sec), 6)
        row.add(interval_field)
        add_row(row)
        add_row(make_hint("0 disables autosave."))

        exit_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        save_on_exit_check = JCheckBox("Save to Project when the extension unloads/Burp exits", self.save_on_exit)
        exit_row.add(save_on_exit_check)
        add_row(exit_row)

        load_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        auto_load_check = JCheckBox("Load from Project automatically on startup", self.auto_load_on_start)
        load_row.add(auto_load_check)
        add_row(load_row)
        add_row(make_hint("Recommended: avoids autosave overwriting a saved map you forgot to load."))

        content.add(form, BorderLayout.CENTER)

        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 2))

        def do_save(e):
            raw = interval_field.getText().strip()
            try:
                val = int(raw)
                if val < 0: raise ValueError()
            except ValueError:
                JOptionPane.showMessageDialog(dialog, "Enter a whole number of seconds (0 disables autosave).")
                return
            self.autosave_interval_sec = val
            self.save_on_exit = save_on_exit_check.isSelected()
            self.auto_load_on_start = auto_load_check.isSelected()
            
            # Save settings persistently to Burp
            self.callbacks.saveExtensionSetting("MindMap_AutosaveInterval", str(self.autosave_interval_sec))
            self.callbacks.saveExtensionSetting("MindMap_SaveOnExit", str(self.save_on_exit))
            self.callbacks.saveExtensionSetting("MindMap_AutoLoad", str(self.auto_load_on_start))
            
            dialog.dispose()

        save_btn = JButton("Save")
        save_btn.addActionListener(do_save)
        btn_row.add(save_btn)

        cancel_btn = JButton("Cancel")
        cancel_btn.addActionListener(lambda e: dialog.dispose())
        btn_row.add(cancel_btn)

        content.add(btn_row, BorderLayout.SOUTH)

        # Allow pressing 'Enter' anywhere in the dialog to trigger the Save button
        dialog.getRootPane().setDefaultButton(save_btn)

        dialog.setVisible(True)

    def open_custom_mapping_dialog(self, event=None):
        dialog = JDialog()
        dialog.setTitle("Custom Mapping")
        dialog.setModal(True)
        dialog.setSize(880, 660)
        dialog.setLocationRelativeTo(self.mainPanel)

        content = JPanel(BorderLayout(8, 8))
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        dialog.setContentPane(content)

        north_panel = JPanel()
        north_panel.setLayout(BoxLayout(north_panel, BoxLayout.Y_AXIS))

        intro = JLabel(u"<html><b>Map requests by content, not just by URL.</b><br>"
                       u"Useful when an app sends every request to the same endpoint and the "
                       u"real operation only shows up inside the body (a GraphQL operationName, "
                       u"a JSON-RPC method, a SOAP action, etc). Paste or load a sample request "
                       u"below, highlight the value that identifies the operation, then click "
                       u"'Use Selected Text'.</html>")
        intro.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))
        north_panel.add(intro)

        host_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        host_row.add(JLabel("Host:"))
        hosts = sorted(self.target_roots.keys())
        host_combo = JComboBox(hosts)
        host_combo.setEditable(True)
        if hosts: host_combo.setSelectedItem(hosts[0])
        host_combo.setPreferredSize(Dimension(280, host_combo.getPreferredSize().height))
        host_row.add(host_combo)
        hint_lbl = JLabel("  (use * to match every host)")
        hint_lbl.setForeground(Color.GRAY)
        host_row.add(hint_lbl)
        north_panel.add(host_row)

        name_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        name_row.add(JLabel("Mapping Name:"))
        name_field = JTextField("Operation", 18)
        name_row.add(name_field)
        north_panel.add(name_row)

        content.add(north_panel, BorderLayout.NORTH)

        def get_combo_text():
            item = host_combo.getEditor().getItem()
            return unicode(item).strip() if item is not None else u""

        # --- Sample request editor ---
        sample_editor = self.callbacks.createMessageEditor(None, True)
        editor_panel = JPanel(BorderLayout(4, 4))
        editor_panel.setBorder(BorderFactory.createTitledBorder("Sample Request"))

        editor_toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        load_hist_btn = JButton("Load From Proxy History...")
        editor_toolbar.add(load_hist_btn)
        editor_panel.add(editor_toolbar, BorderLayout.NORTH)
        editor_panel.add(sample_editor.getComponent(), BorderLayout.CENTER)

        # --- Extraction rule fields ---
        rule_panel = JPanel()
        rule_panel.setLayout(BoxLayout(rule_panel, BoxLayout.Y_AXIS))
        rule_panel.setBorder(BorderFactory.createTitledBorder("Extraction Rule"))

        start_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        start_row.add(JLabel("Start After:"))
        start_field = JTextField(30)
        start_row.add(start_field)
        rule_panel.add(start_row)

        end_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        end_row.add(JLabel("End Before:  "))
        end_field = JTextField(30)
        end_row.add(end_field)
        rule_panel.add(end_row)

        preview_label = JLabel(" ")

        # Holds where (as a fraction of the sample request's length) the
        # selected value was actually found, so extract_custom_mapping_value
        # can prefer the occurrence of "start" closest to that position
        # instead of always grabbing the first one in the request.
        captured_offset_ratio = [None]

        def do_preview(e):
            full = sample_editor.getMessage()
            if not full:
                preview_label.setForeground(Color.GRAY)
                preview_label.setText("Load or paste a sample request first.")
                return
            full_text = self.helpers.bytesToString(full)
            start_text = start_field.getText()
            rule = {"start": start_text, "end": end_field.getText(), "sample_offset_ratio": captured_offset_ratio[0]}
            value = self.extract_custom_mapping_value(rule, full_text)
            if value is None:
                preview_label.setForeground(Color(200, 80, 80))
                preview_label.setText("No match found with the current Start/End text.")
            else:
                occurrences = full_text.count(start_text) if start_text else 0
                if occurrences > 1:
                    preview_label.setForeground(Color(200, 140, 40))
                    preview_label.setText(
                        u"Extracted value: \"{0}\"  (warning: \"Start After\" text appears {1} times "
                        u"in this sample - pick more unique text if other requests get grouped "
                        u"incorrectly)".format(value, occurrences))
                else:
                    preview_label.setForeground(Color(90, 170, 90))
                    preview_label.setText(u"Extracted value: \"{0}\"".format(value))

        def do_use_selection(e):
            bounds = sample_editor.getSelectionBounds()
            if not bounds or bounds[0] == bounds[1]:
                JOptionPane.showMessageDialog(dialog,
                    "Highlight the value you want to map on inside the request above, then click this button.")
                return
            full = sample_editor.getMessage()
            full_text = self.helpers.bytesToString(full)
            s, en = bounds[0], bounds[1]
            ctx = 20

            captured_offset_ratio[0] = (float(s) / len(full_text)) if full_text else None

            # Keep anchors on the same line as the selection: JTextField mangles
            # embedded \r\n on setText/getText, and a selection is very often made
            # right after the \r\n\r\n that ends the headers, so the naive
            # fixed-length window would otherwise usually include a newline.
            pre_text = full_text[max(0, s - ctx):s]
            nl = pre_text.rfind(u"\n")
            if nl != -1: pre_text = pre_text[nl + 1:]
            pre_text = pre_text.replace(u"\r", u"")

            post_text = full_text[en:en + ctx]
            nl2 = post_text.find(u"\n")
            if nl2 != -1: post_text = post_text[:nl2]
            post_text = post_text.replace(u"\r", u"")

            start_field.setText(pre_text)
            end_field.setText(post_text)
            do_preview(e)

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        use_sel_btn = JButton("<< Use Selected Text From Request")
        use_sel_btn.addActionListener(do_use_selection)
        btn_row.add(use_sel_btn)
        test_btn = JButton("Test Rule")
        test_btn.addActionListener(do_preview)
        btn_row.add(test_btn)
        rule_panel.add(btn_row)
        rule_panel.add(preview_label)

        add_rule_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        add_rule_btn = JButton("Add Mapping Rule")
        add_rule_row.add(add_rule_btn)
        rule_panel.add(add_rule_row)

        # --- Existing rules table ---
        rules_cols = ["Host", "Name", "Start After", "End Before"]
        rules_model = DefaultTableModel(rules_cols, 0)
        rules_ref = []

        def refresh_rules_table():
            rules_model.setRowCount(0)
            del rules_ref[:]
            rules_ref.extend(self.custom_mappings)
            for r in rules_ref:
                rules_model.addRow([r.get("host", ""), r.get("name", ""), r.get("start", ""), r.get("end", "")])

        rules_table = JTable(rules_model)
        rules_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        rules_scroll = JScrollPane(rules_table)
        rules_scroll.setPreferredSize(Dimension(400, 140))

        rules_wrap = JPanel(BorderLayout(4, 4))
        rules_wrap.setBorder(BorderFactory.createTitledBorder("Saved Rules"))
        rules_wrap.add(rules_scroll, BorderLayout.CENTER)
        del_rule_row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        del_rule_btn = JButton("Delete Selected Rule")
        del_rule_row.add(del_rule_btn)
        rules_wrap.add(del_rule_row, BorderLayout.SOUTH)

        def do_add_rule(e):
            host = get_combo_text() or "*"
            name = name_field.getText().strip() or "Match"
            start = start_field.getText()
            end = end_field.getText()
            if not start or not end:
                JOptionPane.showMessageDialog(dialog, "Both 'Start After' and 'End Before' must be set. Use the selection helper above.")
                return
            self.custom_mappings.append({
                "id": str(uuid.uuid4()),
                "host": host.lower(),
                "name": name,
                "start": start,
                "end": end,
                "sample_offset_ratio": captured_offset_ratio[0]
            })
            self.save_state()
            refresh_rules_table()
            self.rebuild_map_from_history()
            JOptionPane.showMessageDialog(dialog,
                "Rule saved and the map has been rebuilt from Proxy History.\n\n"
                "This doesn't create a separate tab - look inside the existing "
                "\"{0}\" tab: matching requests now branch one level deeper, under "
                "a new node labeled [{1}] <value>.".format(host, name))

        add_rule_btn.addActionListener(do_add_rule)

        def do_delete_rule(e):
            row = rules_table.getSelectedRow()
            if row < 0: return
            target = rules_ref[row]
            self.custom_mappings = [r for r in self.custom_mappings if r.get("id") != target.get("id")]
            self.save_state()
            refresh_rules_table()
            self.rebuild_map_from_history()

        del_rule_btn.addActionListener(do_delete_rule)

        def do_load_hist(e):
            filter_host = get_combo_text()
            self.pick_sample_request(dialog, sample_editor, filter_host)
        load_hist_btn.addActionListener(do_load_hist)

        bottom_panel = JPanel()
        bottom_panel.setLayout(BoxLayout(bottom_panel, BoxLayout.Y_AXIS))
        bottom_panel.add(rule_panel)
        bottom_panel.add(rules_wrap)

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, editor_panel, bottom_panel)
        center_split.setResizeWeight(0.55)
        center_split.setContinuousLayout(True)
        content.add(center_split, BorderLayout.CENTER)

        south_row = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 5))
        close_btn = JButton("Close")
        close_btn.addActionListener(lambda e: dialog.dispose())
        south_row.add(close_btn)
        content.add(south_row, BorderLayout.SOUTH)

        refresh_rules_table()
        dialog.setVisible(True)

    def pick_sample_request(self, owner_dialog, sample_editor, filter_host):
        candidates = []
        try:
            all_items = list(self.callbacks.getProxyHistory())
        except Exception:
            all_items = []

        for idx, reqRes in enumerate(all_items):
            info = self.helpers.analyzeRequest(reqRes)
            if not info or not info.getUrl(): continue
            host = info.getUrl().getHost()
            if filter_host and filter_host != "*" and host != filter_host: continue

            # reqRes.getStatusCode() is only reliably populated for *live* intercepted
            # messages, not historical items from getProxyHistory() - parse it from the
            # response bytes instead.
            status = 0
            response = reqRes.getResponse()
            if response:
                try:
                    status = self.helpers.analyzeResponse(response).getStatusCode()
                except Exception:
                    pass

            candidates.append({
                "num": idx + 1,
                "method": info.getMethod(),
                "url": unicode(info.getUrl()),
                "status": status,
                "reqRes": reqRes
            })

        if not candidates:
            JOptionPane.showMessageDialog(owner_dialog, "No matching requests found in Proxy History.")
            return

        pick_dialog = JDialog(owner_dialog, "Select Sample Request", True)
        pick_dialog.setSize(1000, 580)
        pick_dialog.setLocationRelativeTo(owner_dialog)

        table_model = SampleRequestTableModel()
        for c in candidates:
            table_model.addRow([Integer(c["num"]), c["method"], c["url"], Integer(c["status"])])

        req_table = JTable(table_model)
        req_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        req_table.setRowSelectionAllowed(True)
        req_table.setColumnSelectionAllowed(False)
        req_table.setAutoCreateRowSorter(True)
        req_table.getColumnModel().getColumn(0).setPreferredWidth(45)
        req_table.getColumnModel().getColumn(1).setPreferredWidth(70)
        req_table.getColumnModel().getColumn(2).setPreferredWidth(420)
        req_table.getColumnModel().getColumn(3).setPreferredWidth(55)

        list_panel = JPanel(BorderLayout())
        list_panel.setBorder(BorderFactory.createTitledBorder(u"Matching Requests ({0}) - click a column header to sort".format(len(candidates))))
        list_panel.add(JScrollPane(req_table), BorderLayout.CENTER)

        preview_editor = self.callbacks.createMessageEditor(None, False)
        preview_panel = JPanel(BorderLayout())
        preview_panel.setBorder(BorderFactory.createTitledBorder("Request Preview"))
        preview_panel.add(preview_editor.getComponent(), BorderLayout.CENTER)

        def get_selected_candidate():
            view_row = req_table.getSelectedRow()
            if view_row < 0: return None
            model_row = req_table.convertRowIndexToModel(view_row)
            return candidates[model_row]

        def show_selected_preview():
            c = get_selected_candidate()
            if c is None: return
            preview_editor.setMessage(c["reqRes"].getRequest(), True)

        def do_select(e=None):
            c = get_selected_candidate()
            if c is None: return
            sample_editor.setMessage(c["reqRes"].getRequest(), True)
            pick_dialog.dispose()

        def on_table_selection(e):
            if e.getValueIsAdjusting(): return
            show_selected_preview()
        req_table.getSelectionModel().addListSelectionListener(on_table_selection)

        def on_table_click(e):
            if e.getClickCount() == 2: do_select()
        req_table.addMouseListener(type("PickTableDblClick", (MouseAdapter,), {
            "mouseClicked": lambda s, e: on_table_click(e)
        })())

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, list_panel, preview_panel)
        split.setResizeWeight(0.42)
        split.setContinuousLayout(True)

        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        panel.add(split, BorderLayout.CENTER)

        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 5))
        select_btn = JButton("Use This Request")
        select_btn.addActionListener(do_select)
        btn_row.add(select_btn)
        cancel_btn = JButton("Cancel")
        cancel_btn.addActionListener(lambda e: pick_dialog.dispose())
        btn_row.add(cancel_btn)
        panel.add(btn_row, BorderLayout.SOUTH)

        pick_dialog.setContentPane(panel)

        req_table.setRowSelectionInterval(0, 0)
        show_selected_preview()

        pick_dialog.setVisible(True)
