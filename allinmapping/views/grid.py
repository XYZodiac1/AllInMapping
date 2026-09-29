# -*- coding: utf-8 -*-
"""Grid view: populating the table, renderers and selection sync."""
from javax.swing import SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseAdapter
from java.net import URL
from java.lang import Boolean, String

from allinmapping.views.privilege import PrivilegeBoolRenderer, PrivilegeRowRenderer, create_privilege_editor


class MindMapTableModel(DefaultTableModel):
    def __init__(self, extender):
        self.extender = extender
        self.base_cols = ["Method", "URL", "Endpoint", "Tested", "Privilege", "Note"]
        self.row_data_map = []
        DefaultTableModel.__init__(self, 0, len(self.base_cols) + len(self.extender.custom_columns))

    def getColumnCount(self):
        if not hasattr(self, 'extender'): return 6
        return len(self.base_cols) + len(self.extender.custom_columns)

    def getColumnName(self, col):
        if col < len(self.base_cols):
            return self.base_cols[col]
        return self.extender.custom_columns[col - len(self.base_cols)]

    def getColumnClass(self, col):
        if col == 3: return Boolean
        return String

    def isCellEditable(self, row, col):
        return col >= 3

    def getValueAt(self, row, col):
        if row >= len(self.row_data_map): return ""
        node, method = self.row_data_map[row]
        
        if col == 0:
            return method
        elif col == 1:
            try:
                u = URL(node.get_full_url())
                domain = u.getProtocol() + "://" + u.getHost()
                if u.getPort() not in [-1, 80, 443]: domain += ":" + str(u.getPort())
                return domain
            except: return ""
        elif col == 2:
            try:
                u = URL(node.get_full_url())
                endpoint = u.getPath()
                return endpoint if endpoint else "/"
            except: return node.text
        elif col == 3:
            return Boolean(node.status == "Tested")
        elif col == 4:
            return node.privilege
        elif col == 5:
            return node.note
        else:
            col_name = self.getColumnName(col)
            return node.custom_cols.get(col_name, "")

    def setValueAt(self, val, row, col):
        node, method = self.row_data_map[row]
        if col == 3:
            if val: node.status = "Tested"
            else:
                if node.status == "Tested": node.status = ""
            self.extender.save_state()
            if getattr(self.extender, 'current_view_mode', 'map') == 'map':
                self.extender.render_map()
        elif col == 4:
            node.privilege = unicode(val) if val else u""
            self.extender.save_state()
            self.extender.populate_grid()
        elif col == 5:
            node.note = unicode(val) if val else u""
            self.extender.save_state()
            if getattr(self.extender, 'current_view_mode', 'map') == 'map':
                self.extender.render_map()
        elif col > 5:
            col_name = self.getColumnName(col)
            node.custom_cols[col_name] = unicode(val) if val else u""
            self.extender.save_state()
        self.fireTableCellUpdated(row, col)


class GridMouseHandler(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mousePressed(self, e): self.check_popup(e)
    def mouseReleased(self, e): self.check_popup(e)

    def mouseClicked(self, e):
        row = self.extender.gridTable.rowAtPoint(e.getPoint())
        col = self.extender.gridTable.columnAtPoint(e.getPoint())
        if row == -1: 
            self.extender.gridTable.clearSelection()
            self.extender.selected_nodes = set()
            self.extender.selected_method = None
            self.extender.update_toolbar()
        else:
            if SwingUtilities.isLeftMouseButton(e):
                if not self.extender.gridTable.isRowSelected(row):
                    self.extender.gridTable.setRowSelectionInterval(row, row)
            model_row = self.extender.gridTable.convertRowIndexToModel(row)
            self.extender.selected_nodes = {self.extender.table_model.row_data_map[model_row][0]}
            self.extender.selected_method = self.extender.table_model.row_data_map[model_row][1]
            
            if col >= 0:
                model_col = self.extender.gridTable.convertColumnIndexToModel(col)
                if model_col not in (3, 4, 5):
                    self.extender.update_toolbar()
            else:
                self.extender.update_toolbar()

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            row = self.extender.gridTable.rowAtPoint(e.getPoint())
            col = self.extender.gridTable.columnAtPoint(e.getPoint())
            if row >= 0:
                if not self.extender.gridTable.isRowSelected(row):
                    self.extender.gridTable.setRowSelectionInterval(row, row)
                
                selected_rows = self.extender.gridTable.getSelectedRows()
                nodes = [self.extender.table_model.row_data_map[self.extender.gridTable.convertRowIndexToModel(r)][0] for r in selected_rows]
                self.extender.selected_nodes = set(nodes)
                
                if len(selected_rows) == 1:
                    model_row = self.extender.gridTable.convertRowIndexToModel(selected_rows[0])
                    self.extender.selected_method = self.extender.table_model.row_data_map[model_row][1]
                else:
                    self.extender.selected_method = None
                    
                if col >= 0:
                    model_col = self.extender.gridTable.convertColumnIndexToModel(col)
                    if model_col not in (3, 4, 5):
                        self.extender.update_toolbar()
                else:
                    self.extender.update_toolbar()
                
                model_row = self.extender.gridTable.convertRowIndexToModel(row)
                node = self.extender.table_model.row_data_map[model_row][0]
                self.extender.show_context_menu(e.getComponent(), e.getX(), e.getY(), node)


class GridMixin(object):
    """Grid view: populating the table, renderers and selection sync."""

    def apply_grid_renderer(self):
        if not hasattr(self, 'gridTable'): return
        # Update: get the node from the tuple at index 0
        text_renderer = PrivilegeRowRenderer(lambda r: self.table_model.row_data_map[r][0].privilege if hasattr(self, 'table_model') and r < len(self.table_model.row_data_map) else "")
        bool_renderer = PrivilegeBoolRenderer(lambda r: self.table_model.row_data_map[r][0].privilege if hasattr(self, 'table_model') and r < len(self.table_model.row_data_map) else "")
        
        for i in range(self.gridTable.getColumnCount()):
            if i == 3: # Tested Column
                self.gridTable.getColumnModel().getColumn(i).setCellRenderer(bool_renderer)
            else:
                self.gridTable.getColumnModel().getColumn(i).setCellRenderer(text_renderer)

        # Re-apply column widths and editors so they survive "Load from Project"
        if self.gridTable.getColumnCount() >= 6:
            # Method Column (0)
            self.gridTable.getColumnModel().getColumn(0).setMinWidth(50)
            self.gridTable.getColumnModel().getColumn(0).setMaxWidth(65)
            self.gridTable.getColumnModel().getColumn(0).setPreferredWidth(55)
            
            # Tested Column (3)
            self.gridTable.getColumnModel().getColumn(3).setMinWidth(45)
            self.gridTable.getColumnModel().getColumn(3).setMaxWidth(55)
            self.gridTable.getColumnModel().getColumn(3).setPreferredWidth(50)
            
            # Privilege Column (4)
            priv_col = self.gridTable.getColumnModel().getColumn(4)
            priv_col.setMinWidth(75)
            priv_col.setMaxWidth(90)
            priv_col.setPreferredWidth(85)
            priv_col.setCellEditor(create_privilege_editor())
            
            # Note Column (5)
            note_col = self.gridTable.getColumnModel().getColumn(5)
            note_col.setPreferredWidth(250)

    def select_node_in_grid(self, node):
        if not hasattr(self, 'gridTable'): return
        self.populate_grid()
        row = None
        method = None
        for i, entry in enumerate(self.table_model.row_data_map):
            if entry[0] is node:
                row, method = i, entry[1]
                break
        if row is None:
            self.update_toolbar()
            return
        self.selected_method = method
        
        # Convert the model row back to the sorted view row to highlight it correctly on screen
        view_row = self.gridTable.convertRowIndexToView(row)
        if view_row >= 0:
            self.gridTable.setRowSelectionInterval(view_row, view_row)
            rect = self.gridTable.getCellRect(view_row, 0, True)
            SwingUtilities.invokeLater(lambda: self.gridTable.scrollRectToVisible(rect))
            
        self.update_toolbar()

    def populate_grid(self):
        if not hasattr(self, 'table_model'): return
        self.table_model.setRowCount(0)
        self.table_model.row_data_map = []
        if not self.activeRoot: return

        filter_methods = []
        if hasattr(self, 'grid_method_filter'):
            raw_filter = self.grid_method_filter.getText().strip().upper()
            if raw_filter:
                filter_methods = [f.strip() for f in raw_filter.split(',') if f.strip()]

        grid_hide_exts = []
        if hasattr(self, 'grid_ext_filter'):
            raw_ext = self.grid_ext_filter.getText().strip().lower()
            if raw_ext:
                grid_hide_exts = [x.strip() for x in raw_ext.split(',') if x.strip()]

        grid_hide_statuses = set()
        if hasattr(self, 'grid_status_filter'):
            raw_st = self.grid_status_filter.getText().strip()
            if raw_st:
                try: 
                    grid_hide_statuses = set([int(x.strip()) for x in raw_st.split(",") if x.strip().isdigit()])
                except: 
                    pass

        def traverse(node):
            if not self.should_show(node): return

            has_http_data = (len(node.statuses) > 0) or (node.linked_request is not None) or (len(node.methods) > 0)

            if node != self.activeRoot:
                show_this_node = True
                
                # Exclude based on Extensions
                if grid_hide_exts and node.text:
                    if any(node.text.lower().endswith(ext) for ext in grid_hide_exts):
                        show_this_node = False
                        
                # Exclude based on Status Code (if ALL statuses on this node match the excluded list)
                if show_this_node and grid_hide_statuses and node.statuses:
                    if all(s in grid_hide_statuses for s in node.statuses):
                        show_this_node = False

                if show_this_node and not getattr(node, 'is_manual', False) and has_http_data:
                    # If the node has methods, split into multiple rows
                    methods_to_display = sorted(list(node.methods)) if node.methods else ["N/A"]
                    
                    for m in methods_to_display:
                        match = True
                        if filter_methods:
                            # If ANY of the filtered methods are found in this method, exclude it
                            if any(f in m for f in filter_methods):
                                match = False
                        
                        if match:
                            self.table_model.row_data_map.append((node, m))
                            row_data = ["", "", "", False, "", ""]
                            for _ in self.custom_columns: row_data.append("")
                            self.table_model.addRow(row_data)

            if getattr(node, 'collapsed', False): return 

            for child in node.children:
                traverse(child)

        traverse(self.activeRoot)
        self.adjust_url_column_width() # Dynamically locks the URL length + 10

    def adjust_url_column_width(self):
        if not hasattr(self, 'gridTable') or self.gridTable.getColumnCount() < 2: return
        
        table = self.gridTable
        url_col_idx = 1
        max_width = 50 # Base minimum
        
        try:
            # Measure the rendered width of text in all rows for the URL column
            for r in range(table.getRowCount()):
                renderer = table.getCellRenderer(r, url_col_idx)
                comp = renderer.getTableCellRendererComponent(table, table.getValueAt(r, url_col_idx), False, False, r, url_col_idx)
                max_width = max(max_width, comp.getPreferredSize().width)
                
            max_width += 10 # Add the requested 10px padding
            
            # Lock the column to exactly this calculated size
            col = table.getColumnModel().getColumn(url_col_idx)
            col.setMinWidth(max_width)
            col.setMaxWidth(max_width)
            col.setPreferredWidth(max_width)
        except Exception:
            pass # Failsafe against empty tables or threading artifacts
