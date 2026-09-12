# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IExtensionStateListener
from javax.swing import JPanel, JLabel, JTextArea, JTextField, JButton, JToggleButton, JScrollPane, JOptionPane, BorderFactory, UIManager, SwingUtilities, ImageIcon, JPopupMenu, JMenuItem, AbstractAction, KeyStroke, JComponent, JFileChooser, JCheckBox, JMenu, BoxLayout, Box, JSplitPane, JTable, JTabbedPane, ButtonGroup, ListSelectionModel, JComboBox, DefaultCellEditor
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellRenderer
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, BasicStroke, RenderingHints, Cursor, Toolkit, Font, Polygon, Dimension, CardLayout, Insets
from java.awt.datatransfer import StringSelection, DataFlavor
from java.awt.event import MouseAdapter, KeyEvent, KeyAdapter, FocusListener
from java.awt.geom import Path2D
from java.awt.image import BufferedImage
from java.net import URL
from java.lang import Runnable, Integer, Boolean, String
import json
import uuid
import time
import threading
from java.util import ArrayList

BURP_ORANGE = Color(229, 106, 37)

def get_privilege_color(priv_level, is_selected, is_dark_theme):
    if not priv_level: return None
    
    pl = priv_level.strip().lower()
    if pl == "no auth":
        base = Color(38, 65, 105) if is_dark_theme else Color(173, 216, 230) # Medium Blue
    elif pl == "low privs":
        base = Color(38, 90, 50) if is_dark_theme else Color(144, 238, 144) # Medium Green
    elif pl == "high privs":
        base = Color(115, 42, 42) if is_dark_theme else Color(255, 182, 193) # Medium Red
    else:
        # Custom Privilege
        base = Color(32, 95, 105) if is_dark_theme else Color(224, 255, 255) # Medium Cyan

    if is_selected:
        return base.darker()
    return base

def create_privilege_editor():
    combo = JComboBox(["", "No Auth", "Low Privs", "High Privs"])
    combo.setEditable(True)
    editor = DefaultCellEditor(combo)
    editor.setClickCountToStart(1) # Start editing on single click
    return editor

class PrivilegeRowRenderer(DefaultTableCellRenderer):
    def __init__(self, data_source_callback):
        self.data_source_callback = data_source_callback
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        priv = self.data_source_callback(row)
        
        is_dark = UIManager.getColor("Panel.background").getRed() < 128
        bg_color = get_privilege_color(priv, isSelected, is_dark)
        
        if bg_color:
            c.setBackground(bg_color)
            if is_dark:
                c.setForeground(Color.WHITE if not isSelected else table.getSelectionForeground())
            else:
                c.setForeground(Color.BLACK if not isSelected else table.getSelectionForeground())
        else:
            c.setBackground(table.getSelectionBackground() if isSelected else table.getBackground())
            c.setForeground(table.getSelectionForeground() if isSelected else table.getForeground())
            
        return c

class PrivilegeBoolRenderer(JCheckBox, TableCellRenderer):
    def __init__(self, data_source_callback):
        self.data_source_callback = data_source_callback
        self.setHorizontalAlignment(JCheckBox.CENTER)
        self.setOpaque(True)
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        if value is not None:
            self.setSelected(bool(value))
        else:
            self.setSelected(False)
            
        priv = self.data_source_callback(row)
        is_dark = UIManager.getColor("Panel.background").getRed() < 128
        bg_color = get_privilege_color(priv, isSelected, is_dark)
        
        if bg_color:
            self.setBackground(bg_color)
        else:
            self.setBackground(table.getSelectionBackground() if isSelected else table.getBackground())
        return self

class RestoredHttpService:
    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol
    def getHost(self): return self.host
    def getPort(self): return self.port
    def getProtocol(self): return self.protocol

class RestoredReqRes:
    def __init__(self, req, res, svc):
        self.req = req
        self.res = res
        self.svc = svc
    def getRequest(self): return self.req
    def getResponse(self): return self.res
    def getHttpService(self): return self.svc

class MindMapNode:
    def __init__(self, text, parent=None):
        self.id = str(uuid.uuid4())
        self.text = text
        self.children = []
        self.parent = parent  
        self.x = 0
        self.y = 0
        self.width = 0
        self.height = 44  
        self.subtree_height = 0
        self.subtree_width = 0

        self.methods = set()
        self.method_requests = {} 
        self.statuses = set()
        self.content_lengths = set()
        self.severity = None 
        self.note = ""
        self.privilege = ""
        self.custom_color = None
        self.status = "" 
        self.params = set()
        self.collapsed = False 

        self.is_playbook_node = False
        self.is_manual = False 
        self.manual_resize = False 
        self.linked_request = None 
        self.custom_cols = {}

    def find_child(self, text):
        for child in self.children:
            if child.text == text:
                return child
        return None

    def get_full_url(self):
        parts = []
        current = self

        while current is not None:
            if current.text:
                parts.insert(0, current.text)
            current = current.parent

        if not parts: return ""

        base = parts[0]
        if not base.startswith("http"):
            base = "https://" + base

        if len(parts) > 1:
            path = "/".join(parts[1:])
            path = "/".join(filter(None, path.split("/"))) 
            if base.endswith("/"): base = base[:-1]
            return base + "/" + path

        return base

class MindMapTableModel(DefaultTableModel):
    def __init__(self, extender):
        self.extender = extender
        self.base_cols = ["Method", "URL", "Endpoint", "Tested", "Privilege", "Note"]
        # We now store a tuple of (node, method) for each row
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

class EditFieldListener(KeyAdapter, FocusListener):
    def __init__(self, extender): self.extender = extender
    def keyPressed(self, e):
        if e.getKeyCode() == KeyEvent.VK_ENTER:
            if e.isShiftDown():
                self.extender.inline_edit_field.append("\n")
                e.consume()
            else:
                self.extender.commit_inline_edit()
                e.consume()
        elif e.getKeyCode() == KeyEvent.VK_ESCAPE:
            self.extender.inline_edit_field.setVisible(False)
            self.extender.canvasScroll.requestFocusInWindow()
    def focusLost(self, e):
        self.extender.commit_inline_edit()
    def focusGained(self, e): pass

class DeleteNodeAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        if getattr(self.extender, 'selected_relation', None):
            self.extender.save_state()
            if self.extender.selected_relation in self.extender.relationships:
                self.extender.relationships.remove(self.extender.selected_relation)
            self.extender.selected_relation = None
            self.extender.render_map()
        elif self.extender.selected_nodes: 
            self.extender.delete_nodes(list(self.extender.selected_nodes)[0])

class CutAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.cut_nodes()

class SendToRepeaterAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        if len(self.extender.selected_nodes) == 1:
            self.extender.send_to_repeater(list(self.extender.selected_nodes)[0])

class SendToIntruderAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        if len(self.extender.selected_nodes) == 1:
            self.extender.send_to_intruder(list(self.extender.selected_nodes)[0])

class CopyAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.copy_nodes()

class PasteAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.paste_nodes()

class UndoAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.undo()

class ZoomInAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.set_zoom(self.extender.zoom_factor + 0.1)

class ZoomOutAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.set_zoom(self.extender.zoom_factor - 0.1)

class ZoomResetAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.set_zoom(1.0)

class AddChildNodeAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        if len(self.extender.selected_nodes) == 1:
            node = list(self.extender.selected_nodes)[0]
            self.extender.add_custom_node(node)

class GridMouseHandler(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mousePressed(self, e): self.check_popup(e)
    def mouseReleased(self, e): self.check_popup(e)

    def mouseClicked(self, e):
        row = self.extender.gridTable.rowAtPoint(e.getPoint())
        if row == -1: 
            self.extender.gridTable.clearSelection()
            self.extender.selected_nodes = set()
            self.extender.update_toolbar()

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            row = self.extender.gridTable.rowAtPoint(e.getPoint())
            if row >= 0:
                if not self.extender.gridTable.isRowSelected(row):
                    self.extender.gridTable.setRowSelectionInterval(row, row)
                
                selected_rows = self.extender.gridTable.getSelectedRows()
                # Unpack the tuple: extract just the node
                nodes = [self.extender.table_model.row_data_map[r][0] for r in selected_rows]
                self.extender.selected_nodes = set(nodes)
                self.extender.update_toolbar()
                
                # Unpack the tuple: pass just the node to the context menu
                node = self.extender.table_model.row_data_map[row][0]
                self.extender.show_context_menu(e.getComponent(), e.getX(), e.getY(), node)

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
            if e.getClickCount() == 1 and not SwingUtilities.isRightMouseButton(e):
                feat = self.extender.visible_features[row]
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
                menu = JPopupMenu()
                p_menu = JMenu("Set Feature Privilege")
                for p_level in ["Clear", "No Auth", "Low Privs", "High Privs"]:
                    item = JMenuItem(p_level)
                    val = "" if p_level == "Clear" else p_level
                    def set_fp(evt, v=val, r=row):
                        feat = self.extender.visible_features[r]
                        feat["privilege"] = v
                        self.extender.save_state()
                        self.extender.update_features_master_table()
                    item.addActionListener(set_fp)
                    p_menu.add(item)
                menu.add(p_menu)
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
        self.extender.close_feature_note()

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            row = self.extender.features_reqs_table.rowAtPoint(e.getPoint())
            if row >= 0:
                if not self.extender.features_reqs_table.isRowSelected(row):
                    self.extender.features_reqs_table.setRowSelectionInterval(row, row)
                menu = JPopupMenu()
                p_menu = JMenu("Set Request Privilege")
                for p_level in ["Clear", "No Auth", "Low Privs", "High Privs"]:
                    item = JMenuItem(p_level)
                    val = "" if p_level == "Clear" else p_level
                    def set_rp(evt, v=val, r=row):
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
                menu.show(e.getComponent(), e.getX(), e.getY())

class MapMouseHandler(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
        self.dragged_node = None
        self.resizing_node = None
        self.logical_last_x = 0
        self.logical_last_y = 0
        self.has_dragged = False
        self.pre_action_state = None

        self.panning = False
        self.pan_start_x = 0
        self.pan_start_y = 0
        self.start_scroll_x = 0
        self.start_scroll_y = 0

    def get_logical_coords(self, e):
        z = self.extender.zoom_factor
        return e.getX() / z, e.getY() / z

    def mouseWheelMoved(self, e):
        self.extender.commit_inline_edit()
        if e.isControlDown() or e.isMetaDown():
            rot = e.getWheelRotation()
            if rot < 0: self.extender.set_zoom(self.extender.zoom_factor + 0.1)
            else: self.extender.set_zoom(self.extender.zoom_factor - 0.1)
            e.consume() 
        else:
            pane = self.extender.canvasScroll
            if e.isShiftDown(): bar = pane.getHorizontalScrollBar()
            else: bar = pane.getVerticalScrollBar()
            bar.setValue(bar.getValue() + (e.getWheelRotation() * bar.getUnitIncrement() * 4))

    def check_popup(self, e):
        if e.isPopupTrigger() or SwingUtilities.isRightMouseButton(e):
            self.extender.commit_inline_edit()
            if getattr(self.extender, 'is_relating', False): return False
            lx, ly = self.get_logical_coords(e)
            node = self.extender.get_node_at(lx, ly)
            if node:
                if node not in self.extender.selected_nodes:
                    self.extender.selected_nodes = {node}
                    self.extender.selected_relation = None
                    self.extender.selected_method = None
                    self.extender.update_toolbar()
                    self.extender.render_map()
                self.extender.show_context_menu(e.getComponent(), e.getX(), e.getY(), node)
            return True
        return False

    def mouseMoved(self, e):
        if getattr(self.extender, 'is_relating', False): return
        lx, ly = self.get_logical_coords(e)

        toggle_node = self.extender.get_toggle_at(lx, ly)
        if toggle_node:
            self.extender.map_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            self.extender.map_label.setToolTipText("Click to expand/collapse")
            return

        node = self.extender.get_node_at(lx, ly)
        if node and lx >= node.x + node.width - 15 and ly >= node.y + node.height - 15:
            self.extender.map_label.setCursor(Cursor.getPredefinedCursor(Cursor.SE_RESIZE_CURSOR))
            self.extender.map_label.setToolTipText(None)
        elif node:
            self.extender.map_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            if node.note:
                self.extender.map_label.setToolTipText("<html><p width='250'>" + node.note.replace("\n", "<br>") + "</p></html>")
            else:
                self.extender.map_label.setToolTipText(None)
        else:
            self.extender.map_label.setCursor(Cursor.getDefaultCursor())
            self.extender.map_label.setToolTipText(None)

    def mousePressed(self, e):
        self.extender.commit_inline_edit()
        self.extender.canvasScroll.requestFocusInWindow()
        if self.check_popup(e): return

        lx, ly = self.get_logical_coords(e)

        toggle_node = self.extender.get_toggle_at(lx, ly)
        if toggle_node and SwingUtilities.isLeftMouseButton(e):
            self.extender.save_state()
            toggle_node.collapsed = not getattr(toggle_node, 'collapsed', False)
            self.extender.auto_arrange(None)
            return

        node = self.extender.get_node_at(lx, ly)

        if getattr(self.extender, 'is_relating', False):
            if node:
                if not getattr(self.extender, 'relate_source', None):
                    self.extender.relate_source = node
                else:
                    if node != self.extender.relate_source:
                        new_rel = (self.extender.relate_source.id, node.id)
                        if new_rel not in self.extender.relationships:
                            self.extender.save_state()
                            self.extender.relationships.append(new_rel)
                    self.extender.relate_source = None
            else:
                self.extender.relate_source = None 
            self.extender.render_map()
            return

        self.logical_last_x = lx
        self.logical_last_y = ly
        self.has_dragged = False

        if self.extender.activeRoot:
            self.pre_action_state = self.extender.get_full_state()

        is_multi = e.isControlDown() or e.isShiftDown() or e.isMetaDown()

        if node:
            self.extender.selected_relation = None
            if lx >= node.x + node.width - 15 and ly >= node.y + node.height - 15:
                self.resizing_node = node
            else:
                self.dragged_node = node

            if is_multi:
                if node in self.extender.selected_nodes:
                    self.extender.selected_nodes.remove(node)
                else:
                    self.extender.selected_nodes.add(node)
            else:
                if node not in self.extender.selected_nodes:
                    self.extender.selected_nodes = {node}
        else:
            clicked_rel = None
            stroke = BasicStroke(8.0 / self.extender.zoom_factor) 
            for rel, path in self.extender.relation_paths.items():
                if stroke.createStrokedShape(path).contains(lx, ly):
                    clicked_rel = rel
                    break

            if clicked_rel:
                self.extender.selected_relation = clicked_rel
                self.extender.selected_nodes = set()
            else:
                if not is_multi:
                    self.extender.selected_nodes = set()
                self.extender.selected_relation = None
                self.panning = True
                self.pan_start_x = e.getXOnScreen()
                self.pan_start_y = e.getYOnScreen()
                self.start_scroll_x = self.extender.canvasScroll.getHorizontalScrollBar().getValue()
                self.start_scroll_y = self.extender.canvasScroll.getVerticalScrollBar().getValue()
                self.extender.map_label.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR))

        self.extender.update_toolbar()
        self.extender.render_map() 

    def mouseDragged(self, e):
        if getattr(self.extender, 'is_relating', False): return

        if self.panning:
            dx = e.getXOnScreen() - self.pan_start_x
            dy = e.getYOnScreen() - self.pan_start_y
            self.extender.canvasScroll.getHorizontalScrollBar().setValue(self.start_scroll_x - dx)
            self.extender.canvasScroll.getVerticalScrollBar().setValue(self.start_scroll_y - dy)
            return

        self.has_dragged = True
        lx, ly = self.get_logical_coords(e)
        dx = lx - self.logical_last_x
        dy = ly - self.logical_last_y
        self.logical_last_x = lx
        self.logical_last_y = ly

        if self.resizing_node:
            self.resizing_node.width = max(50, self.resizing_node.width + dx) 
            self.resizing_node.height = max(28, self.resizing_node.height + dy) 
            self.resizing_node.manual_resize = True
            self.extender.render_map() 
        elif self.dragged_node:
            if self.dragged_node in self.extender.selected_nodes:
                for n in self.extender.selected_nodes:
                    n.x += dx
                    n.y += dy
            else:
                self.dragged_node.x += dx
                self.dragged_node.y += dy
            self.extender.render_map() 

    def mouseReleased(self, e):
        if getattr(self.extender, 'is_relating', False): return

        self.check_popup(e)
        self.panning = False
        self.extender.map_label.setCursor(Cursor.getDefaultCursor())

        if self.has_dragged and (self.dragged_node or self.resizing_node) and self.pre_action_state:
            self.extender.undo_stack.append(self.pre_action_state)
            if len(self.extender.undo_stack) > 10:
                self.extender.undo_stack.pop(0)
            self.extender.redo_stack = []
            if self.resizing_node:
                self.extender.auto_arrange(None)

        self.dragged_node = None
        self.resizing_node = None
        self.has_dragged = False
        self.pre_action_state = None

    def mouseClicked(self, e):
        if getattr(self.extender, 'is_relating', False): return

        lx, ly = self.get_logical_coords(e)
        if self.extender.get_toggle_at(lx, ly): return

        if e.getClickCount() == 2 and not SwingUtilities.isRightMouseButton(e):
            node = self.extender.get_node_at(lx, ly)
            if node: self.extender.trigger_inline_edit(node)
            return

        if not self.has_dragged and not SwingUtilities.isRightMouseButton(e):
            hit_method = False
            for (bx, by, bw, bh, node, m) in self.extender.method_hitboxes:
                if bx <= lx <= bx + bw and by <= ly <= by + bh:
                    self.extender.selected_nodes = {node}
                    self.extender.selected_method = m
                    self.extender.update_toolbar()
                    hit_method = True
                    break
            
            if not hit_method:
                node = self.extender.get_node_at(lx, ly)
                if node:
                    self.extender.selected_method = None
                    self.extender.update_toolbar()


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Interactive Attack Surface MindMap")

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
        self.features = [] 
        self.visible_features = []
        self.is_recording_feature = False
        self.recorded_reqs = []
        self.selected_feature_req = None 
        self.current_view_mode = "map"

        self.internal_clipboard = []
        self.last_copied_text = ""

        self.undo_stack = []
        self.redo_stack = []

        self.live_processed_urls = set()
        self.unloaded = False 

        self.callbacks.registerHttpListener(self)
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerExtensionStateListener(self)
        SwingUtilities.invokeLater(UIBuilder(self))

        def auto_save_loop():
            while not self.unloaded:
                for _ in range(300): 
                    if self.unloaded: break
                    time.sleep(1)
                if not self.unloaded and self.activeRoot:
                    self.save_project_state(silent=True)

        t = threading.Thread(target=auto_save_loop)
        t.daemon = True 
        t.start()
        
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

    def extensionUnloaded(self):
        self.unloaded = True
        self.save_project_state(silent=True)

    def trigger_inline_edit(self, node):
        self.editing_node = node
        self.inline_edit_field.setText(node.text)

        zx = int(node.x * self.zoom_factor)
        zy = int(node.y * self.zoom_factor)
        zw = int(node.width * self.zoom_factor)
        zh = int(node.height * self.zoom_factor) 

        self.inline_edit_field.setBounds(zx, zy, zw, zh)
        self.inline_edit_field.setFont(Font("Hack", Font.PLAIN, int(12 * self.zoom_factor)))
        self.inline_edit_field.setVisible(True)
        self.inline_edit_field.requestFocusInWindow()
        self.inline_edit_field.selectAll()

    def commit_inline_edit(self, e=None):
        if not hasattr(self, 'inline_edit_field') or not self.inline_edit_field.isVisible() or not getattr(self, 'editing_node', None): 
            return

        new_text = self.inline_edit_field.getText().strip()
        if new_text:
            self.save_state()
            self.editing_node.text = new_text
        elif self.editing_node.is_manual and not self.editing_node.text:
            if self.editing_node.parent:
                self.editing_node.parent.children.remove(self.editing_node)
                if self.editing_node in self.selected_nodes:
                    self.selected_nodes.remove(self.editing_node)

        self.inline_edit_field.setVisible(False)
        self.editing_node = None
        self.auto_arrange(None)
        self.canvasScroll.requestFocusInWindow()

    def cut_nodes(self):
        if not self.selected_nodes: return
        self.copy_nodes()
        nodes_to_delete = list(self.selected_nodes)
        for node in nodes_to_delete:
            self.delete_nodes(node)

    def copy_nodes(self):
        if not self.selected_nodes: return
        self.internal_clipboard = [self.serialize_node(n) for n in self.selected_nodes]
        urls = [n.get_full_url() for n in self.selected_nodes if n.get_full_url()]
        text = "\n".join(urls) if urls else ", ".join([n.text for n in self.selected_nodes])
        self.last_copied_text = text
        selection = StringSelection(text)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)

    def reset_node_ids(self, node):
        node.id = str(uuid.uuid4())
        for c in node.children: self.reset_node_ids(c)

    def paste_nodes(self):
        if len(self.selected_nodes) != 1: return
        parent = list(self.selected_nodes)[0]
        self.save_state()

        clipboard_text = ""
        try:
            clip = Toolkit.getDefaultToolkit().getSystemClipboard().getContents(None)
            if clip and clip.isDataFlavorSupported(DataFlavor.stringFlavor):
                clipboard_text = clip.getTransferData(DataFlavor.stringFlavor)
        except: pass

        if clipboard_text == self.last_copied_text and self.internal_clipboard:
            for node_data in self.internal_clipboard:
                new_node = self.deserialize_node(node_data, parent)
                self.reset_node_ids(new_node) 
                parent.children.append(new_node)
        else:
            if clipboard_text.strip():
                new_node = MindMapNode(clipboard_text.strip(), parent=parent)
                new_node.is_manual = True
                new_node.width = 70
                parent.children.append(new_node)

        parent.collapsed = False
        self.auto_arrange(None)

    def export_excel(self, event):
        if not self.target_roots: return
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Excel (XLS)")
        if chooser.showSaveDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith(".xls"): filepath += ".xls"

            excluded_exts = (
                '.gif', '.png', '.jpg', '.jpeg', '.svg', '.mp4', '.mp3', 
                '.ico', '.js', '.min.js', '.js.min', '.wav', '.mov', 
                '.ttf', '.woff', '.woff2', '.eot', '.otf', '.css', '.map'
            )

            try:
                xml_data = []
                xml_data.append('<?xml version="1.0"?>')
                xml_data.append('<?mso-application progid="Excel.Sheet"?>')
                xml_data.append('<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">')

                xml_data.append(""" <Styles>
  <Style ss:ID="HeaderL">
   <Font ss:Bold="1"/>
   <Interior ss:Color="#7DEFFF" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="HeaderR">
   <Font ss:Bold="1"/>
   <Interior ss:Color="#7DEFFF" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="NormL">
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="NormR">
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="TestL">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="TestR">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotL">
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotR">
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotTestL">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotTestR">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
 </Styles>""")

                for host, root in self.target_roots.items():
                    sheet_name = host.replace("/", "").replace("\\", "").replace("?", "").replace("*", "").replace(":", "").replace("[", "").replace("]", "")
                    if len(sheet_name) > 31: sheet_name = sheet_name[:31]
                    if not sheet_name: sheet_name = "Unknown"

                    xml_data.append(' <Worksheet ss:Name="{}">'.format(sheet_name))
                    xml_data.append('  <Table>')

                    xml_data.append('   <Column ss:Width="60"/>') 
                    xml_data.append('   <Column ss:Width="300"/>') 
                    xml_data.append('   <Column ss:Width="100"/>')
                    xml_data.append('   <Column ss:Width="60"/>')  
                    xml_data.append('   <Column ss:Width="80"/>')  
                    xml_data.append('   <Column ss:Width="200"/>') 

                    xml_data.append('   <Row>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Method</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">URL</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Endpoint</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Tested</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Privilege</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderR"><Data ss:Type="String">Notes</Data></Cell>')
                    xml_data.append('   </Row>')

                    rows_data = []

                    def traverse_excel(node):
                        has_http = (len(node.statuses) > 0) or (node.linked_request is not None) or (len(node.methods) > 0)
                        if node != root and not getattr(node, 'is_manual', False) and has_http:
                            full_url = node.get_full_url()
                            try:
                                u = URL(full_url)
                                endpoint = u.getPath()
                                if not endpoint: endpoint = "/"
                            except:
                                endpoint = node.text

                            if not any(endpoint.lower().endswith(ext) for ext in excluded_exts):
                                is_tested = True if node.status == "Tested" else False
                                ep_clean = endpoint.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                meths = ", ".join(node.methods)
                                nts = node.note.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                privs = getattr(node, 'privilege', "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                rows_data.append((meths, full_url, ep_clean, is_tested, privs, nts))

                        for child in node.children:
                            traverse_excel(child)

                    traverse_excel(root)

                    for idx, (meths, full_url, ep_clean, is_tested, privs, nts) in enumerate(rows_data):
                        is_last = (idx == len(rows_data) - 1)
                        if is_last:
                            style_L = "BotTestL" if is_tested else "BotL"
                            style_R = "BotTestR" if is_tested else "BotR"
                        else:
                            style_L = "TestL" if is_tested else "NormL"
                            style_R = "TestR" if is_tested else "NormR"

                        tested_str = "Yes" if is_tested else "No"

                        xml_data.append('   <Row>')
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, meths))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, full_url))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, ep_clean))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, tested_str))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, privs))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_R, nts))
                        xml_data.append('   </Row>')

                    xml_data.append('  </Table>')
                    xml_data.append(' </Worksheet>')
                xml_data.append('</Workbook>')

                with open(filepath, 'w') as f:
                    f.write("\n".join(xml_data).encode("utf-8"))

                JOptionPane.showMessageDialog(self.mainPanel, "Excel Exported successfully!")
            except Exception as e:
                self.callbacks.printError("Failed to export Excel: " + str(e))
                JOptionPane.showMessageDialog(self.mainPanel, "Excel Export Failed: " + str(e))

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

    def export_canvas(self, event=None):
        if not self.target_roots:
            JOptionPane.showMessageDialog(self.mainPanel, "No targets to export.")
            return

        chooser = JFileChooser()
        chooser.setDialogTitle("Export Obsidian Canvas File")
        if chooser.showSaveDialog(self.mainPanel) != JFileChooser.APPROVE_OPTION:
            return

        filepath = chooser.getSelectedFile().getAbsolutePath()
        if not filepath.endswith(".canvas"):
            filepath += ".canvas"

        SCALE = 2.0

        def hex_color(c):
            if not c: return None
            return "#{:02x}{:02x}{:02x}".format(c.getRed(), c.getGreen(), c.getBlue())

        STATUS_HEX = {
            "Vulnerable": "#f50000",
            "Tested": "#00f500",
            "In Progress": "#fff500",
        }
        SEVERITY_HEX = {
            "High": "#ef4444", "Medium": "#f97316", "Low": "#eab308", "Information": "#3b82f6",
        }
        THEME_PALETTES = {
            "Light": ["#bd93f9", "#50fa7b", "#8be9fd", "#ff79c6", "#f1fa8c", "#ffb86c"],
            "Synthwave": ["#d2a8ff", "#39bae6", "#aad94c", "#ffb454", "#f07178", "#59c2ff"],
            "Vibrant": ["#ffffff", "#00e5ff", "#ff2a2a", "#00ffc3", "#d500ff", "#adff00"],
        }
        DEFAULT_THEME_HEX = "#e56a25"

        def node_canvas_color(node, level):
            custom = hex_color(node.custom_color)
            if custom:
                return custom
            if node.status in STATUS_HEX:
                return STATUS_HEX[node.status]
            if node.severity in SEVERITY_HEX:
                return SEVERITY_HEX[node.severity]
            palette = THEME_PALETTES.get(getattr(self, 'current_theme', 'Default'))
            if palette:
                return palette[level % len(palette)]
            return DEFAULT_THEME_HEX

        def node_markdown(node):
            lines = [u"## " + (node.text or u"(unnamed)")]
            full_url = node.get_full_url()
            if full_url:
                lines.append(full_url)
            if node.methods:
                lines.append(u"**Methods:** " + u", ".join(sorted(node.methods)))
            if node.statuses:
                lines.append(u"**Statuses:** " + u", ".join(str(s) for s in sorted(node.statuses)))
            if node.status:
                lines.append(u"**Status:** " + node.status)
            if getattr(node, 'privilege', ""):
                lines.append(u"**Privilege:** " + node.privilege)
            if node.params:
                lines.append(u"**Params:** " + u", ".join(sorted(node.params)))
            if node.note:
                lines.append(u"")
                lines.append(node.note)
            return u"\n\n".join(lines)

        try:
            canvas_nodes = []
            canvas_edges = []
            node_index = {}
            y_cursor = 0
            GAP = 400

            for host, root in self.target_roots.items():
                bounds = {"min_x": None, "max_x": None, "min_y": None, "max_y": None}

                def collect_bounds(node):
                    x0, y0 = node.x, node.y
                    x1, y1 = node.x + node.width, node.y + node.height
                    if bounds["min_x"] is None or x0 < bounds["min_x"]: bounds["min_x"] = x0
                    if bounds["min_y"] is None or y0 < bounds["min_y"]: bounds["min_y"] = y0
                    if bounds["max_x"] is None or x1 > bounds["max_x"]: bounds["max_x"] = x1
                    if bounds["max_y"] is None or y1 > bounds["max_y"]: bounds["max_y"] = y1
                    for c in node.children:
                        collect_bounds(c)

                collect_bounds(root)
                min_x = bounds["min_x"] or 0
                min_y = bounds["min_y"] or 0
                max_x = bounds["max_x"] or 0
                max_y = bounds["max_y"] or 0

                dx = -min_x * SCALE
                dy = y_cursor - (min_y * SCALE)

                group_id = str(uuid.uuid4())
                canvas_nodes.append({
                    "id": group_id, "type": "group", "label": host,
                    "x": int(min_x * SCALE + dx) - 40,
                    "y": int(min_y * SCALE + dy) - 60,
                    "width": max(int((max_x - min_x) * SCALE) + 80, 300),
                    "height": max(int((max_y - min_y) * SCALE) + 120, 200),
                })

                def walk(node, level):
                    node_index[node.id] = node
                    cn = {
                        "id": node.id,
                        "type": "text",
                        "x": int(node.x * SCALE + dx),
                        "y": int(node.y * SCALE + dy),
                        "width": max(int(node.width * SCALE), 240),
                        "height": max(int(node.height * SCALE) + 40, 90),
                        "text": node_markdown(node),
                    }
                    col = node_canvas_color(node, level)
                    if col: cn["color"] = col
                    canvas_nodes.append(cn)

                    for child in node.children:
                        canvas_edges.append({
                            "id": str(uuid.uuid4()),
                            "fromNode": node.id,
                            "fromSide": "bottom" if self.is_vertical_layout else "right",
                            "toNode": child.id,
                            "toSide": "top" if self.is_vertical_layout else "left",
                        })
                        walk(child, level + 1)

                walk(root, 0)
                y_cursor += (max_y - min_y) * SCALE + GAP

            for src_id, tgt_id in self.relationships:
                if src_id in node_index and tgt_id in node_index:
                    canvas_edges.append({
                        "id": str(uuid.uuid4()),
                        "fromNode": src_id,
                        "fromSide": "right",
                        "toNode": tgt_id,
                        "toSide": "left",
                        "color": "5",
                        "label": "related",
                    })

            canvas_data = {"nodes": canvas_nodes, "edges": canvas_edges}
            with open(filepath, 'w') as f:
                json.dump(canvas_data, f, indent=2)

            JOptionPane.showMessageDialog(self.mainPanel, "Exported to Obsidian Canvas successfully!")
        except Exception as e:
            self.callbacks.printError("Failed to export Canvas: " + str(e))
            JOptionPane.showMessageDialog(self.mainPanel, "Canvas Export Failed: " + str(e))

    def save_project_state(self, event=None, silent=False):
        if not self.target_roots: return
        try:
            state_dict = self.get_full_state()
            json_string = json.dumps(state_dict)
            self.callbacks.saveExtensionSetting("MindMapProjectState", json_string)
            if not silent and event:
                JOptionPane.showMessageDialog(self.mainPanel, "Workspace saved to the Burp Project successfully!")
        except Exception as e:
            self.callbacks.printError("Failed to save state: " + str(e))
            if not silent and event:
                JOptionPane.showMessageDialog(self.mainPanel, "Failed to save: " + str(e))

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

    def get_hidden_statuses(self):
        if hasattr(self, 'hide_status_field'):
            raw_st = self.hide_status_field.getText().strip()
            if raw_st:
                try: 
                    return set([int(x.strip()) for x in raw_st.split(",") if x.strip().isdigit()])
                except: 
                    pass
            else:
                return set() 
        return {0, 404, 500, 302, 301}

    def get_content_length(self, response):
        if not response: return 0
        info = self.helpers.analyzeResponse(response)
        for header in info.getHeaders():
            if header.lower().startswith("content-length:"):
                try: return int(header.split(":")[1].strip())
                except: pass
        return len(response) - info.getBodyOffset()

    def set_theme(self, theme_name):
        self.current_theme = theme_name
        self.render_map()

    def should_show(self, node):
        if getattr(self, 'hide_tested', False) and node.status == "Tested":
            return False

        if node == self.activeRoot:
            return True

        has_param_filter = hasattr(self, 'param_only_cb') and self.param_only_cb.isSelected()
        has_hide_get_filter = hasattr(self, 'hide_get_cb') and self.hide_get_cb.isSelected()

        hide_cls = set()
        if hasattr(self, 'cl_filter_field'):
            raw_cl = self.cl_filter_field.getText().strip()
            if raw_cl:
                try: hide_cls = set([int(x.strip()) for x in raw_cl.split(",") if x.strip().isdigit()])
                except: pass

        hide_statuses = self.get_hidden_statuses()

        ext_excludes = []
        ext_includes = []
        if hasattr(self, 'filterField'):
            raw_ex = self.filterField.getText().strip().lower()
            ext_excludes = [x.strip() for x in raw_ex.split(',') if x.strip()]

            raw_inc = self.includeField.getText().strip().lower()
            ext_includes = [x.strip() for x in raw_inc.split(',') if x.strip()]

        def check_node_or_descendants(n):
            if getattr(self, 'hide_tested', False) and n.status == "Tested":
                return False

            if getattr(n, 'is_manual', False) or getattr(n, 'is_playbook_node', False) or n.note or n.custom_color or n.status:
                return True

            has_http_data = bool(n.methods or n.statuses or n.params)

            passes_filters = True
            if has_http_data:
                if has_param_filter and not n.params: passes_filters = False
                if has_hide_get_filter and (not n.methods or all(m == "GET" for m in n.methods)): passes_filters = False
                if hide_cls and n.content_lengths and all(cl in hide_cls for cl in n.content_lengths): passes_filters = False
                if hide_statuses and n.statuses and all(s in hide_statuses for s in n.statuses): passes_filters = False

                txt = n.text.lower()
                if ext_excludes and any(txt.endswith(ext) for ext in ext_excludes): passes_filters = False
                if ext_includes and "." in txt and not any(txt.endswith(ext) for ext in ext_includes): passes_filters = False
            else:
                passes_filters = False 

            if passes_filters: return True

            for child in n.children:
                if check_node_or_descendants(child):
                    return True
            return False

        return check_node_or_descendants(node)

    def find_node_by_id(self, current_node, search_id):
        if not current_node: return None
        if getattr(current_node, 'id', None) == search_id: return current_node
        for child in current_node.children:
            res = self.find_node_by_id(child, search_id)
            if res: return res
        return None

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            item = JMenuItem("Send to MindMap Playbook")
            messages = invocation.getSelectedMessages()
            if messages:
                item.addActionListener(lambda e: self.handle_global_send_to_map(messages[0]))
                menu_list.add(item)
        return menu_list

    def handle_global_send_to_map(self, reqRes):
        if getattr(self, 'is_prompting', False): return 
        self.is_prompting = True

        try:
            info = self.helpers.analyzeRequest(reqRes)
            url_obj = info.getUrl()
            host = url_obj.getHost()

            if host not in self.target_roots:
                self.add_target_tab(host)

            target_root = self.target_roots[host]

            node_title = JOptionPane.showInputDialog(self.mainPanel, "Enter a title for this Attack Box:", "Test for XYZ attack")
            if not node_title or not node_title.strip():
                return

            self.save_state()

            new_node = MindMapNode(node_title.strip(), parent=target_root)
            new_node.is_playbook_node = True
            
            method = info.getMethod()
            new_node.methods.add(method)
            new_node.method_requests[method] = self.callbacks.saveBuffersToTempFiles(reqRes)
            new_node.linked_request = new_node.method_requests[method]

            dummy_label = JLabel()
            fm = dummy_label.getFontMetrics(dummy_label.getFont())
            new_node.width = max(90, fm.stringWidth(new_node.text) + 24)
            new_node.custom_color = Color(0, 127, 255, 51)

            target_root.children.append(new_node)
            self.selected_nodes = {new_node}

            if self.activeRoot != target_root:
                for i in range(self.tabbed_pane.getTabCount()):
                    panel = self.tabbed_pane.getComponentAt(i)
                    if panel.getClientProperty("target_root") == target_root:
                        self.tabbed_pane.setSelectedIndex(i)
                        break

            self.auto_arrange(None)
        finally:
            SwingUtilities.invokeLater(lambda: setattr(self, 'is_prompting', False))

    def set_zoom(self, new_zoom):
        self.zoom_factor = max(0.2, min(5.0, new_zoom))
        if getattr(self, 'current_view_mode', 'map') == 'map':
            self.render_map()

    def serialize_req_res(self, reqRes):
        req_b64 = ""
        res_b64 = ""
        svc_data = None
        req = reqRes.getRequest()
        if req: req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req))
        res = reqRes.getResponse()
        if res: res_b64 = self.helpers.bytesToString(self.helpers.base64Encode(res))
        svc = reqRes.getHttpService()
        if svc:
            svc_data = {
                "host": svc.getHost(),
                "port": svc.getPort(),
                "protocol": svc.getProtocol()
            }
        return req_b64, res_b64, svc_data

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest: return

        if self.is_recording_feature and toolFlag == self.callbacks.TOOL_PROXY:
            info = self.helpers.analyzeRequest(messageInfo)
            if info and info.getUrl() and self.callbacks.isInScope(info.getUrl()):
                req_b64, res_b64, svc_data = self.serialize_req_res(messageInfo)
                self.recorded_reqs.append({
                    "id": str(uuid.uuid4()),
                    "method": info.getMethod(),
                    "url": unicode(info.getUrl()),
                    "notes": "",
                    "privilege": "",
                    "req_b64": req_b64,
                    "res_b64": res_b64,
                    "svc_data": svc_data
                })
                if hasattr(self, 'features_reqs_model') and self.features_reqs_model.current_feature is None:
                    SwingUtilities.invokeLater(lambda: self.update_features_detail_table())

        if toolFlag not in [self.callbacks.TOOL_PROXY, self.callbacks.TOOL_REPEATER]: return
        if not hasattr(self, 'live_sync_cb') or not self.live_sync_cb.isSelected(): return
        SwingUtilities.invokeLater(lambda: self.process_live_request(messageInfo, toolFlag))

    def process_live_request(self, reqRes, toolFlag, bypass_live_sync_check=False):
        info = self.helpers.analyzeRequest(reqRes)
        if not info or not info.getUrl(): return

        response = reqRes.getResponse()
        if not response or len(response) == 0: return 

        resp_info = self.helpers.analyzeResponse(response)
        status_code = resp_info.getStatusCode()

        if status_code in self.get_hidden_statuses(): return 

        url_obj = info.getUrl()
        url_str_full = unicode(url_obj)

        if not bypass_live_sync_check:
            if url_str_full in self.live_processed_urls and toolFlag != self.callbacks.TOOL_REPEATER: return
            self.live_processed_urls.add(url_str_full)

        matched_target = url_obj.getHost()

        if matched_target not in self.target_roots:
            if self.callbacks.isInScope(url_obj):
                self.add_target_tab(matched_target)
            else:
                return 

        targetRoot = self.target_roots[matched_target]
        cl = self.get_content_length(response)
        method = info.getMethod()

        params = set()
        for p in info.getParameters():
            if p.getType() == 0: 
                params.add(p.getName())

        path = url_obj.getPath()
        current_node = targetRoot
        is_new_data = False

        if path and path != "/":
            parts = path.split("/")
            for part in parts:
                if not part: continue
                next_node = current_node.find_child(part)
                if next_node is None:
                    next_node = MindMapNode(part, parent=current_node)
                    current_node.children.append(next_node)
                    is_new_data = True
                current_node = next_node

        before_m = len(current_node.methods)
        current_node.methods.add(method)
        if len(current_node.methods) > before_m: is_new_data = True

        if status_code:
            before_s = len(current_node.statuses)
            current_node.statuses.add(status_code)
            if len(current_node.statuses) > before_s: is_new_data = True

        if cl is not None:
            before_cl = len(current_node.content_lengths)
            current_node.content_lengths.add(cl)
            if len(current_node.content_lengths) > before_cl: is_new_data = True

        before_p = len(current_node.params)
        current_node.params.update(params)
        if len(current_node.params) > before_p: is_new_data = True

        saved_req_res = self.callbacks.saveBuffersToTempFiles(reqRes)
        current_node.method_requests[method] = saved_req_res
        current_node.linked_request = saved_req_res 

        if toolFlag == self.callbacks.TOOL_REPEATER:
            if current_node.status != "Tested":
                current_node.status = "Tested"
                is_new_data = True

        if is_new_data and targetRoot == self.activeRoot:
            self.auto_arrange(None)

    def getTabCaption(self): return "Visual MindMap"
    def getUiComponent(self): return self.mainPanel

    def get_full_state(self):
        targets_state = {}
        for host, root in self.target_roots.items():
            targets_state[host] = self.serialize_node(root)
        return {
            "targets": targets_state,
            "relationships": list(self.relationships),
            "custom_columns": list(self.custom_columns),
            "features": list(self.features)
        }

    def apply_state(self, state):
        self.target_roots = {}
        self.tabbed_pane.removeAll()
        self.activeRoot = None
        self.custom_columns = state.get("custom_columns", [])
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

    def get_node_at(self, lx, ly):
        if not self.activeRoot: return None
        def search(node):
            if node != self.activeRoot and not self.should_show(node): return None
            if node.x <= lx <= node.x + node.width and node.y <= ly <= node.y + node.height:
                return node
            if getattr(node, 'collapsed', False): return None 
            for child in node.children:
                res = search(child)
                if res: return res
            return None
        return search(self.activeRoot)

    def get_toggle_at(self, lx, ly):
        if not self.activeRoot: return None
        def search(node):
            if node != self.activeRoot and not self.should_show(node): return None

            has_visible_children = len([c for c in node.children if self.should_show(c)]) > 0
            if has_visible_children:
                if self.is_vertical_layout:
                    bx = node.x + node.width / 2.0
                    by = node.y + node.height
                else:
                    bx = node.x + node.width
                    by = node.y + 22

                if (bx - 7) <= lx <= (bx + 7) and (by - 7) <= ly <= (by + 7):
                    return node

            if getattr(node, 'collapsed', False): return None

            for child in node.children:
                res = search(child)
                if res: return res
            return None

        return search(self.activeRoot)

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

    def update_toolbar(self):
        has_selection = len(self.selected_nodes) > 0
        if hasattr(self, 'color_bar') and self.color_bar.isVisible() != has_selection:
            self.color_bar.setVisible(has_selection)

        if hasattr(self, 'request_panel'):
            req_out = None
            res_out = None

            if len(self.selected_nodes) > 0 and getattr(self, 'current_view_mode', 'map') != 'features':
                node = list(self.selected_nodes)[0]

                req_bytes = None
                res_bytes = None

                if hasattr(self, 'selected_method') and self.selected_method:
                    target_req = node.method_requests.get(self.selected_method)
                    if target_req:
                        req_bytes = target_req.getRequest()
                        res_bytes = target_req.getResponse()

                if not req_bytes and node.linked_request:
                    req_bytes = node.linked_request.getRequest()
                    res_bytes = node.linked_request.getResponse()

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
                self.request_editor.setMessage(req_out or self.helpers.stringToBytes(""), True)
                self.response_editor.setMessage(res_out or self.helpers.stringToBytes(""), False)
                if not self.request_panel.isVisible():
                    self.request_panel.setVisible(True)
                    if hasattr(self, 'outer_split_pane') and hasattr(self, 'mainPanel'):
                        self.outer_split_pane.setDividerLocation(int(self.mainPanel.getHeight() * 0.40))
                        SwingUtilities.invokeLater(lambda: self.traffic_split.setDividerLocation(0.5))
            else:
                self.request_panel.setVisible(False)

        self.mainPanel.revalidate()
        self.mainPanel.repaint()

    def apply_color_to_selection(self, base_color):
        if not self.selected_nodes: return
        self.save_state() 
        final_color = None
        if base_color is not None:
            final_color = Color(base_color.getRed(), base_color.getGreen(), base_color.getBlue(), 51)
        for n in self.selected_nodes:
            n.custom_color = final_color
        self.auto_arrange(None)

    def set_node_privilege(self, priv):
        self.save_state()
        for n in self.selected_nodes: 
            n.privilege = priv
        self.auto_arrange(None)

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

    def toggle_collapse(self, target_node):
        self.save_state()
        nodes_to_toggle = self.selected_nodes if target_node in self.selected_nodes else [target_node]
        for n in nodes_to_toggle:
            n.collapsed = not getattr(n, 'collapsed', False)
        self.update_toolbar()
        self.auto_arrange(None)

    def set_node_status(self, string_status):
        self.save_state()
        for n in self.selected_nodes: n.status = string_status
        self.auto_arrange(None)

    def edit_note(self, node):
        note_area = JTextArea(node.note, 5, 30)
        scroll = JScrollPane(note_area)
        res = JOptionPane.showConfirmDialog(self.mainPanel, scroll, "Pentester Note:", JOptionPane.OK_OPTION)
        if res == JOptionPane.OK_OPTION:
            self.save_state()
            node.note = note_area.getText().strip()
            mode = getattr(self, 'current_view_mode', 'map')
            if mode == 'map':
                self.render_map()
            elif mode == 'grid':
                self.populate_grid()

    def build_http_request(self, node):
        url_str = node.get_full_url()
        if not url_str: return None, None, None, None
        try:
            url_obj = URL(url_str)
            host = url_obj.getHost()
            use_https = (url_obj.getProtocol().lower() == "https")
            port = url_obj.getPort()
            if port == -1: port = 443 if use_https else 80
            req = self.helpers.buildHttpRequest(url_obj)
            return host, port, use_https, req
        except Exception as e:
            return None, None, None, None

    def send_to_intruder(self, node):
        if node.linked_request:
            service = node.linked_request.getHttpService()
            self.callbacks.sendToIntruder(service.getHost(), service.getPort(), (service.getProtocol().lower() == "https"), node.linked_request.getRequest())
        else:
            host, port, use_https, req = self.build_http_request(node)
            if req: self.callbacks.sendToIntruder(host, port, use_https, req)

    def send_to_repeater(self, node):
        if node.linked_request:
            service = node.linked_request.getHttpService()
            self.callbacks.sendToRepeater(
                service.getHost(), service.getPort(), (service.getProtocol().lower() == "https"),
                node.linked_request.getRequest(), node.text
            )
        else:
            host, port, use_https, req = self.build_http_request(node)
            if req: self.callbacks.sendToRepeater(host, port, use_https, req, node.text)

    def do_active_scan(self, node):
        host, port, use_https, req = self.build_http_request(node)
        if req:
            self.callbacks.doActiveScan(host, port, use_https, req)
            JOptionPane.showMessageDialog(self.mainPanel, "Sent to Active Scanner!")

    def copy_node_url(self, target_node):
        nodes = self.selected_nodes if target_node in self.selected_nodes else [target_node]
        urls = [n.get_full_url() for n in nodes if n.get_full_url()]
        if urls:
            selection = StringSelection("\n".join(urls))
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)

    def add_custom_node(self, parent_node):
        self.save_state() 
        new_node = MindMapNode("", parent=parent_node)
        new_node.x = parent_node.x + parent_node.width + 60
        new_node.y = parent_node.y + (parent_node.height // 2)
        new_node.is_manual = True 
        new_node.width = 70
        parent_node.children.append(new_node)
        parent_node.collapsed = False 
        self.selected_nodes = {new_node}
        self.update_toolbar()
        self.auto_arrange(None)
        if getattr(self, 'current_view_mode', 'map') == 'map':
            SwingUtilities.invokeLater(lambda: self.trigger_inline_edit(new_node))

    def delete_nodes(self, target_node):
        self.save_state() 
        nodes_to_delete = list(self.selected_nodes) if target_node in self.selected_nodes else [target_node]

        if self.activeRoot in nodes_to_delete:
            JOptionPane.showMessageDialog(self.mainPanel, "You cannot delete the Workspace Root.")
            nodes_to_delete.remove(self.activeRoot)

        def remove_recursive(current, target):
            for child in current.children:
                if child == target:
                    current.children.remove(child)
                    return True
                if remove_recursive(child, target): return True
            return False

        for n in nodes_to_delete:
            for root in self.target_roots.values():
                remove_recursive(root, n)
            if n in self.selected_nodes: self.selected_nodes.remove(n)

        deleted_ids = [n.id for n in nodes_to_delete]
        self.relationships = [r for r in self.relationships if r[0] not in deleted_ids and r[1] not in deleted_ids]

        self.update_toolbar()
        self.auto_arrange(None)

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

    def export_svg(self, event):
        if not self.activeRoot: return
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            filepath = file.getAbsolutePath()
            if not filepath.endswith(".svg"): filepath += ".svg"

            try:
                svg_data = self.generate_svg_xml()
                with open(filepath, 'w') as f:
                    f.write(svg_data.encode("utf-8"))
                JOptionPane.showMessageDialog(self.mainPanel, "SVG Exported successfully!")
            except Exception as e:
                JOptionPane.showMessageDialog(self.mainPanel, "SVG Export Failed: " + str(e))

    def generate_svg_xml(self):
        def find_max_bounds(node):
            if not self.should_show(node): return 0, 0
            mx, my = node.x + node.width, node.y + node.height
            if getattr(node, 'collapsed', False): return mx, my
            for c in node.children:
                cmx, cmy = find_max_bounds(c)
                if cmx > mx: mx = cmx
                if cmy > my: my = cmy
            return mx, my

        mx, my = find_max_bounds(self.activeRoot)
        width, height = int(mx + 300), int(my + 300)

        lines = []
        lines.append('<?xml version="1.0" encoding="UTF-8"?>')
        lines.append('<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="-50 -50 {} {}" style="background-color:#3c3f41; font-family:sans-serif;">'.format(width, height, width+100, height+100))

        def draw_connections(node):
            if not self.should_show(node) or getattr(node, 'collapsed', False): return
            if self.is_vertical_layout: px, py = node.x + node.width / 2.0, node.y + node.height
            else: px, py = node.x + node.width, node.y + 22

            for child in node.children:
                if not self.should_show(child): continue
                if self.is_vertical_layout:
                    cx, cy = child.x + child.width / 2.0, child.y
                    cx1, cy1, cx2, cy2 = px, py + (cy - py)/2.0, cx, py + (cy - py)/2.0
                else:
                    cx, cy = child.x, child.y + 22
                    cx1, cy1, cx2, cy2 = px + (cx - px)/2.0, py, px + (cx - px)/2.0, cy
                lines.append('<path d="M {},{} C {},{} {},{} {},{}" fill="none" stroke="#777777" stroke-width="1.5"/>'.format(px, py, cx1, cy1, cx2, cy2, cx, cy))
                draw_connections(child)

        draw_connections(self.activeRoot)

        for src_id, tgt_id in self.relationships:
            src = self.find_node_by_id(self.activeRoot, src_id)
            tgt = self.find_node_by_id(self.activeRoot, tgt_id)
            if src and tgt and self.should_show(src) and self.should_show(tgt):
                sx, sy = src.x + src.width, src.y + src.height / 2.0
                tx, ty = tgt.x, tgt.y + tgt.height / 2.0
                ctrl_x1 = sx + 60
                ctrl_x2 = tx - 60
                lines.append('<path d="M {},{} C {},{} {},{} {},{}" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-dasharray="8,8"/>'.format(sx, sy, ctrl_x1, sy, ctrl_x2, ty, tx, ty))

        def draw_nodes(node, level):
            if not self.should_show(node): return
            bg = "#2a2c2e"
            if node.custom_color:
                c = node.custom_color
                bg = "rgba({},{},{},{})".format(c.getRed(), c.getGreen(), c.getBlue(), c.getAlpha()/255.0)
            elif level == 0: bg = "gray"

            bc = "#e56a25" 
            if self.current_theme == "Light": 
                dracula_hex = ["#bd93f9", "#50fa7b", "#8be9fd", "#ff79c6", "#f1fa8c", "#ffb86c"]
                bc = dracula_hex[level % len(dracula_hex)]
            elif self.current_theme == "Synthwave": 
                ayu_hex = ["#d2a8ff", "#39bae6", "#aad94c", "#ffb454", "#f07178", "#59c2ff"]
                bc = ayu_hex[level % len(ayu_hex)]
            elif self.current_theme == "Vibrant": 
                Vibrant_hex = ["#ffffff", "#00e5ff", "#ff2a2a", "#00ffc3", "#d500ff", "#adff00"]
                bc = Vibrant_hex[level % len(Vibrant_hex)]

            if node.status == "Vulnerable": bc = "red"
            elif node.status == "Tested": bc = "green"
            elif node.status == "In Progress": bc = "yellow"

            if getattr(node, 'collapsed', False): return 
            for child in node.children:
                draw_nodes(child, level + 1)

        draw_nodes(self.activeRoot, 0)
        lines.append('</svg>')
        return "\n".join(lines)

    def wrap_text(self, text, metrics, max_width):
        if max_width <= 20: return [text]
        lines = []
        for paragraph in text.split("\n"):
            if not paragraph:
                lines.append("")
                continue
            words = paragraph.split(" ")
            current_line = ""
            for word in words:
                test_line = current_line + word + " " if current_line else word + " "
                if metrics.stringWidth(test_line) > max_width and current_line:
                    lines.append(current_line.strip())
                    current_line = word + " "
                else:
                    current_line = test_line
            if current_line:
                lines.append(current_line.strip())
        return lines

    def auto_arrange(self, event):
        if not self.activeRoot: return
        if event is not None: self.save_state() 

        mode = getattr(self, 'current_view_mode', 'map')

        if mode == 'grid':
            self.populate_grid()
        elif mode == 'features':
            if hasattr(self, 'features_master_model'):
                self.update_features_master_table()
                self.update_features_detail_table()
        else:
            dummy = JLabel()
            metrics = dummy.getFontMetrics(dummy.getFont())
            self.calculate_subtree_dimensions(self.activeRoot, metrics)
            if self.is_vertical_layout: self.assign_coordinates_vertical(self.activeRoot, 30, 30)
            else: self.assign_coordinates_horizontal(self.activeRoot, 30, 30)
            self.render_map()

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

    def populate_grid(self):
        if not hasattr(self, 'table_model'): return
        self.table_model.setRowCount(0)
        self.table_model.row_data_map = []
        if not self.activeRoot: return

        filter_method = ""
        if hasattr(self, 'grid_method_filter'):
            filter_method = self.grid_method_filter.getText().strip().upper()

        def traverse(node):
            if not self.should_show(node): return

            has_http_data = (len(node.statuses) > 0) or (node.linked_request is not None) or (len(node.methods) > 0)

            if node != self.activeRoot:
                if not getattr(node, 'is_manual', False) and has_http_data:
                    # If the node has methods, split into multiple rows
                    methods_to_display = sorted(list(node.methods)) if node.methods else ["N/A"]
                    
                    for m in methods_to_display:
                        match = True
                        if filter_method:
                            if filter_method not in m:
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

    def on_tab_changed(self):
        idx = self.tabbed_pane.getSelectedIndex()
        if idx < 0: return
        panel = self.tabbed_pane.getComponentAt(idx)
        root = panel.getClientProperty("target_root")
        self.activeRoot = root

        panel.add(self.outer_split_pane, BorderLayout.CENTER)
        panel.revalidate()
        panel.repaint()

        self.selected_nodes = set()
        self.selected_method = None
        self.selected_feature_req = None
        self.update_toolbar()
        self.auto_arrange(None)

    def add_target_tab(self, host, existing_node=None):
        if host in self.target_roots: return
        root = existing_node if existing_node else MindMapNode(host)
        self.target_roots[host] = root

        dummy_panel = JPanel(BorderLayout())
        dummy_panel.putClientProperty("target_root", root)

        idx = self.tabbed_pane.getTabCount()
        self.tabbed_pane.addTab(host, dummy_panel)

        tab_comp = JPanel(CardLayout())
        tab_comp.setOpaque(False)
        tab_comp.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)) 

        # 1. Shrink font and margins
        lbl = JLabel(host)
        lbl.setFont(Font("SansSerif", Font.PLAIN, 11))
        lbl.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8)) 
        
        # 2. Strip the default bulky borders off the hidden text field
        txt = JTextField(host, 15)
        txt.setFont(Font("SansSerif", Font.PLAIN, 11))
        txt.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2))

        tab_comp.add(lbl, "label")
        tab_comp.add(txt, "edit")

        # 3. FORCE the height of the tab to be strictly 20 pixels tall
        pref_width = tab_comp.getPreferredSize().width
        tab_comp.setPreferredSize(Dimension(pref_width, 10))

        def handle_mouse_click(e):
            tab_idx = self.tabbed_pane.indexOfTabComponent(tab_comp)
            if tab_idx != -1:
                if e.getClickCount() == 1:
                    self.tabbed_pane.setSelectedIndex(tab_idx)
                elif e.getClickCount() == 2:
                    txt.setText(lbl.getText())
                    tab_comp.getLayout().show(tab_comp, "edit")
                    txt.requestFocusInWindow()
                    txt.selectAll()

        click_listener = type("TabClickListener", (MouseAdapter,), {
            "mouseClicked": lambda self, e: handle_mouse_click(e)
        })()

        lbl.addMouseListener(click_listener)
        tab_comp.addMouseListener(click_listener)

        def commit_edit(e):
            new_name = txt.getText().strip()
            if new_name:
                lbl.setText(new_name)
                root.text = new_name
                tab_idx = self.tabbed_pane.indexOfTabComponent(tab_comp)
                if tab_idx != -1:
                    self.tabbed_pane.setTitleAt(tab_idx, new_name)
            card = tab_comp.getLayout()
            card.show(tab_comp, "label")
            self.auto_arrange(None)

        txt.addActionListener(lambda e: commit_edit(e))
        txt.addFocusListener(type("Focus", (FocusListener,), {
            "focusLost": lambda self, e: commit_edit(e),
            "focusGained": lambda self, e: None
        })())

        self.tabbed_pane.setTabComponentAt(idx, tab_comp)

        if self.activeRoot is None:
            self.tabbed_pane.setSelectedIndex(idx)

    def load_scope_and_history(self):
        all_requests = list(self.callbacks.getProxyHistory()) + list(self.callbacks.getSiteMap(None))
        for reqRes in all_requests:
            if not reqRes.getResponse(): continue
            info = self.helpers.analyzeRequest(reqRes)
            if not info: continue
            url_obj = info.getUrl()
            if self.callbacks.isInScope(url_obj):
                self.process_live_request(reqRes, self.callbacks.TOOL_PROXY, bypass_live_sync_check=True)

    def render_map(self):
        if not self.activeRoot: return

        self.method_hitboxes = []

        def find_max_bounds(node):
            if not self.should_show(node):
                return 0, 0
            mx = node.x + node.width
            my = node.y + node.height
            if getattr(node, 'collapsed', False): return mx, my 
            for c in node.children:
                cmx, cmy = find_max_bounds(c)
                if cmx > mx: mx = cmx
                if cmy > my: my = cmy
            return mx, my

        actual_max_x, actual_max_y = find_max_bounds(self.activeRoot)

        img_width = int((actual_max_x + 300) * self.zoom_factor)
        img_height = int((actual_max_y + 300) * self.zoom_factor)

        img_width = max(img_width, 1000)
        img_height = max(img_height, 800)

        image = BufferedImage(img_width, img_height, BufferedImage.TYPE_INT_ARGB)
        g2d = image.createGraphics()

        base_bg = UIManager.getColor("Panel.background") or Color(60, 63, 65)
        g2d.setColor(base_bg)
        g2d.fillRect(0, 0, img_width, img_height)
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

        g2d.scale(self.zoom_factor, self.zoom_factor)

        self.relation_paths = {}
        for src_id, tgt_id in self.relationships:
            src = self.find_node_by_id(self.activeRoot, src_id)
            tgt = self.find_node_by_id(self.activeRoot, tgt_id)
            if src and tgt and self.should_show(src) and self.should_show(tgt):
                sx = src.x + src.width
                sy = src.y + src.height / 2.0
                tx = tgt.x
                ty = tgt.y + tgt.height / 2.0

                path = Path2D.Float()
                path.moveTo(sx, sy)
                path.curveTo(sx + 60, sy, tx - 60, ty, tx, ty)

                self.relation_paths[(src_id, tgt_id)] = path

                is_sel = getattr(self, 'selected_relation', None) == (src_id, tgt_id)
                if is_sel:
                    g2d.setColor(Color(59, 130, 246)) 
                    g2d.setStroke(BasicStroke(4.0))
                else:
                    g2d.setColor(Color.WHITE) 
                    g2d.setStroke(BasicStroke(2.0, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10.0, [8.0, 8.0], 0.0))
                g2d.draw(path)

        self.draw_node(g2d, self.activeRoot, 0)

        g2d.dispose() 
        self.map_label.setIcon(ImageIcon(image))
        self.map_label.getParent().revalidate()
        self.map_label.getParent().repaint()

    def calculate_subtree_dimensions(self, node, metrics):
        display_text = node.text
        show_status = not hasattr(self, 'status_cb') or self.status_cb.isSelected()
        
        badge_text_length = 0
        if node.methods:
            badge_text_length += sum([metrics.stringWidth(m) + 4 for m in node.methods])
        if node.statuses and show_status:
            st_text = " [" + ",".join([str(s) for s in node.statuses]) + "]"
            badge_text_length += metrics.stringWidth(st_text)

        show_params = hasattr(self, 'params_cb') and self.params_cb.isSelected() and node.params
        max_param_w = 0
        param_height = 0
        if show_params:
            for p in node.params:
                pw = metrics.stringWidth(p)
                if pw > max_param_w: max_param_w = pw
            param_height = len(node.params) * 14 + 10

        if getattr(node, 'manual_resize', False):
            text_lines = self.wrap_text(display_text, metrics, node.width - 10)
            w1 = 0
        else:
            text_lines = display_text.split("\n")
            w1 = max([metrics.stringWidth(line) for line in text_lines]) if text_lines else 0

        w2 = badge_text_length if badge_text_length > 0 else 0

        if not getattr(node, 'manual_resize', False):
            min_w = max(w1, w2, max_param_w) + 24
            node.width = max(min_w, 70) 

        text_height = len(text_lines) * 14

        if not getattr(node, 'manual_resize', False):
            node.height = max(44, text_height + 30) + param_height
        else:
            node.height = max(node.height, text_height + 30 + param_height)

        visible_children = [] if getattr(node, 'collapsed', False) else [c for c in node.children if self.should_show(c)]

        if not visible_children:
            node.subtree_height = node.height + 10 
            node.subtree_width = node.width + 10
            return

        total_height = 0
        total_width = 0
        for child in visible_children:
            self.calculate_subtree_dimensions(child, metrics)
            total_height += child.subtree_height
            total_width += child.subtree_width

        node.subtree_height = max(total_height, node.height + 10)
        node.subtree_width = max(total_width, node.width + 10)

    def assign_coordinates_horizontal(self, node, x, y_start):
        node.x = x
        visible_children = [] if getattr(node, 'collapsed', False) else [c for c in node.children if self.should_show(c)]

        if not visible_children:
            node.y = y_start + (node.subtree_height / 2.0) - (node.height / 2.0)
            return

        node.y = y_start + (node.subtree_height / 2.0) - (node.height / 2.0)
        current_y = y_start
        for child in visible_children:
            self.assign_coordinates_horizontal(child, node.x + node.width + 40, current_y)
            current_y += child.subtree_height

    def assign_coordinates_vertical(self, node, x_start, y):
        node.y = y
        visible_children = [] if getattr(node, 'collapsed', False) else [c for c in node.children if self.should_show(c)]

        if not visible_children:
            node.x = x_start + (node.subtree_width / 2.0) - (node.width / 2.0)
            return

        node.x = x_start + (node.subtree_width / 2.0) - (node.width / 2.0)
        current_x = x_start
        for child in visible_children:
            self.assign_coordinates_vertical(child, current_x, node.y + node.height + 40)
            current_x += child.subtree_width

    def draw_node(self, g2d, node, level):
        if not self.should_show(node): return

        fg_color = UIManager.getColor("Label.foreground") or Color.WHITE
        bg_color = UIManager.getColor("Panel.background") or Color(60, 63, 65)
        node_bg = UIManager.getColor("TextField.background") or Color.DARK_GRAY
        border_color = UIManager.getColor("Component.borderColor") or Color.GRAY

        g2d.setColor(border_color)
        g2d.setStroke(BasicStroke(1.5))

        if self.is_vertical_layout:
            p_x = node.x + node.width / 2.0
            p_y = node.y + node.height
        else:
            p_x = node.x + node.width
            p_y = node.y + 22 

        visible_children = [] if getattr(node, 'collapsed', False) else [c for c in node.children if self.should_show(c)]
        for child in visible_children:
            path = Path2D.Float()
            path.moveTo(p_x, p_y)
            if self.is_vertical_layout:
                c_x = child.x + child.width / 2.0
                c_y = child.y
                ctrl_x1 = p_x
                ctrl_y1 = p_y + (c_y - p_y) / 2.0
                ctrl_x2 = c_x
                ctrl_y2 = p_y + (c_y - p_y) / 2.0
            else:
                c_x = child.x
                c_y = child.y + 22 
                ctrl_x1 = p_x + (c_x - p_x) / 2.0
                ctrl_y1 = p_y
                ctrl_x2 = p_x + (c_x - p_x) / 2.0
                ctrl_y2 = c_y
            path.curveTo(ctrl_x1, ctrl_y1, ctrl_x2, ctrl_y2, c_x, c_y)
            g2d.draw(path)

        if node.custom_color:
            g2d.setColor(node.custom_color)
        elif level == 0: 
            g2d.setColor(UIManager.getColor("Button.background") or Color.GRAY)
        else: 
            g2d.setColor(node_bg)

        nx, ny, nw, nh = int(node.x), int(node.y), int(node.width), int(node.height)
        g2d.fillRoundRect(nx, ny, nw, nh, 10, 10)

        severity_colors = {
            "High": Color(239, 68, 68), "Medium": Color(249, 115, 22), 
            "Low": Color(234, 179, 8), "Information": Color(59, 130, 246)
        }

        theme_border_color = BURP_ORANGE
        if getattr(self, 'current_theme', 'Default') == "Light":
            dracula = [
                Color(189, 147, 249), Color(80, 250, 123),  Color(139, 233, 253), 
                Color(255, 121, 198), Color(241, 250, 140), Color(255, 184, 108)
            ]
            theme_border_color = dracula[level % len(dracula)]

        elif getattr(self, 'current_theme', 'Default') == "Synthwave":
            ayu_dark = [
                Color(210, 168, 255), Color(57, 186, 230), Color(170, 217, 76), 
                Color(255, 180, 84),  Color(240, 113, 120), Color(89, 194, 255)
            ]
            theme_border_color = ayu_dark[level % len(ayu_dark)] 

        elif getattr(self, 'current_theme', 'Default') == "Vibrant":
            vibrant_colors = [
                Color(255,255,255), Color(0, 229, 255), Color(255, 42, 42), 
                Color(0, 255, 195), Color(213, 0, 255), Color(173, 255, 0)
            ]
            theme_border_color = vibrant_colors[level % len(vibrant_colors)]

        current_node_border_color = theme_border_color

        if node in self.selected_nodes:
            current_node_border_color = Color(59, 130, 246)
            g2d.setColor(current_node_border_color) 
            g2d.setStroke(BasicStroke(3.0))
        elif node.status == "Vulnerable":
            current_node_border_color = Color(245, 0, 0)
            g2d.setColor(current_node_border_color)    
            g2d.setStroke(BasicStroke(1.8))
        elif node.status == "Tested":
            current_node_border_color = Color(0, 245, 0)
            g2d.setColor(current_node_border_color)    
            g2d.setStroke(BasicStroke(1.8))
        elif node.status == "In Progress":
            current_node_border_color = Color(255, 245, 0)
            g2d.setColor(current_node_border_color)  
            g2d.setStroke(BasicStroke(1.8))
        elif node.severity in severity_colors:
            current_node_border_color = severity_colors[node.severity]
            g2d.setColor(current_node_border_color) 
            g2d.setStroke(BasicStroke(1.2))
        else:
            g2d.setColor(current_node_border_color) 
            g2d.setStroke(BasicStroke(1.2)) 

        g2d.drawRoundRect(nx, ny, nw, nh, 10, 10)

        if getattr(self, 'relate_source', None) == node:
            g2d.setColor(Color(255, 255, 255))
            g2d.setStroke(BasicStroke(2.0, BasicStroke.CAP_BUTT, BasicStroke.JOIN_BEVEL, 0, [5.0, 5.0], 0))
            g2d.drawRoundRect(nx - 4, ny - 4, nw + 8, nh + 8, 10, 10)

        show_params = hasattr(self, 'params_cb') and self.params_cb.isSelected() and node.params

        if show_params:
            g2d.drawLine(nx, ny + 44, nx + nw, ny + 44)

        if node.note:
            g2d.setColor(Color(250, 204, 21))
            poly = Polygon([nx + nw - 12, nx + nw, nx + nw], [ny, ny, ny + 12], 3)
            g2d.fillPolygon(poly)

        g2d.setColor(fg_color)
        base_font = UIManager.getFont("Label.font")
        g2d.setFont(base_font)
        metrics = g2d.getFontMetrics()

        display_text = node.text
        text_lines = self.wrap_text(display_text, metrics, node.width - 10)

        show_status = not hasattr(self, 'status_cb') or self.status_cb.isSelected()
        has_badges = bool(node.methods or (node.statuses and show_status))

        line_height = metrics.getHeight()

        if has_badges:
            start_y = int(node.y + 18)
            for i, line in enumerate(text_lines):
                lx = int(node.x + (node.width - metrics.stringWidth(line)) / 2)
                g2d.drawString(line, lx, start_y + (i * line_height))

            g2d.setFont(Font("SansSerif", Font.PLAIN, 10))
            badge_metrics = g2d.getFontMetrics()
            
            total_methods_width = sum([badge_metrics.stringWidth(m) for m in node.methods]) + (len(node.methods) - 1) * 4 if node.methods else 0
            
            st_text = ""
            if node.statuses and show_status:
                st_text = " [" + ",".join([str(s) for s in node.statuses]) + "]"
            
            total_badge_width = total_methods_width + badge_metrics.stringWidth(st_text)

            bx = int(node.x + (node.width - total_badge_width) / 2)
            by = int(start_y + (len(text_lines) * line_height) + 4)
            
            current_bx = bx
            if node.methods:
                for m in node.methods:
                    m_w = badge_metrics.stringWidth(m)
                    
                    if getattr(self, 'selected_method', None) == m and node in self.selected_nodes:
                        g2d.setColor(Color(17, 204, 212)) 
                    else:
                        g2d.setColor(Color.GRAY)
                    
                    g2d.drawString(m, current_bx, by)
                    
                    self.method_hitboxes.append((current_bx, by - 10, m_w, 14, node, m))
                    current_bx += m_w + 4
            
            if st_text:
                g2d.setColor(Color.GRAY)
                g2d.drawString(st_text, current_bx, by)
                
            g2d.setFont(base_font) 
        else:
            total_text_height = len(text_lines) * line_height
            start_y = int(node.y + (node.height / 2.0) - (total_text_height / 2.0) + metrics.getAscent() - 2)
            for i, line in enumerate(text_lines):
                lx = int(node.x + (node.width - metrics.stringWidth(line)) / 2)
                g2d.drawString(line, lx, start_y + (i * line_height))

        if show_params:
            g2d.setFont(Font("SansSerif", Font.PLAIN, 10))
            g2d.setColor(theme_border_color) 
            py = ny + 56
            for param in sorted(list(node.params)):
                px = nx + 12
                g2d.drawString(param, px, py)
                py += 14
            g2d.setFont(base_font)

        g2d.setColor(Color(59, 130, 246) if node in self.selected_nodes else border_color)
        rx, ry = int(node.x + node.width), int(node.y + node.height)
        g2d.drawLine(rx - 6, ry - 2, rx - 2, ry - 6)
        g2d.drawLine(rx - 10, ry - 2, rx - 2, ry - 10)

        has_potentially_visible_children = len([c for c in node.children if self.should_show(c)]) > 0
        if has_potentially_visible_children:
            bx = int(nx + nw / 2.0) if self.is_vertical_layout else int(nx + nw)
            by = int(ny + nh) if self.is_vertical_layout else int(ny + 22)

            r = 6 

            g2d.setColor(bg_color)
            g2d.fillOval(bx - r, by - r, r*2, r*2)

            g2d.setColor(current_node_border_color)
            g2d.setStroke(BasicStroke(1.2))
            g2d.drawOval(bx - r, by - r, r*2, r*2)

            g2d.setColor(fg_color)
            g2d.setStroke(BasicStroke(1.2))

            if getattr(node, 'collapsed', False):
                g2d.drawLine(bx - 3, by, bx + 3, by)
                g2d.drawLine(bx, by - 3, bx, by + 3)
            else:
                g2d.drawLine(bx - 3, by, bx + 3, by)

        for child in visible_children:
            self.draw_node(g2d, child, level + 1)

class UIBuilder(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        def style_btn(b, bg=Color(60, 63, 65), fg=Color.WHITE):
            b.setBackground(bg)
            b.setForeground(fg)
            b.setFocusPainted(False)
            b.setFont(Font("SansSerif", Font.PLAIN, 11))
            b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(bg.darker(), 1, True),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
            ))
            b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            return b

        def style_textfield(tf, border_color=Color.GRAY):
            tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(border_color, 1, True),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)
            ))
            tf.setMaximumSize(Dimension(Integer.MAX_VALUE, tf.getPreferredSize().height))
            return tf

        self.extender.mainPanel = JPanel(BorderLayout())

        topBar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 10))
        topBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.DARK_GRAY))

        loadScopeBtn = JButton("Load Scope & History")
        style_btn(loadScopeBtn, bg=BURP_ORANGE)
        loadScopeBtn.setFont(Font("SansSerif", Font.BOLD, 11))
        def do_load_scope(e):
            self.extender.target_roots = {}
            self.extender.tabbed_pane.removeAll()
            self.extender.activeRoot = None
            self.extender.load_scope_and_history()
        loadScopeBtn.addActionListener(do_load_scope)
        topBar.add(loadScopeBtn)

        fileBtn = JButton(u"File ▾")
        style_btn(fileBtn, bg=Color(43, 43, 43))
        file_menu = JPopupMenu()

        saveProjItem = JMenuItem(u"Save to Project")
        saveProjItem.addActionListener(lambda e: self.extender.save_project_state(e))
        file_menu.add(saveProjItem)

        loadProjItem = JMenuItem(u"Load from Project")
        loadProjItem.addActionListener(lambda e: self.extender.load_project_state(e))
        file_menu.add(loadProjItem)

        file_menu.addSeparator()

        exportJsonItem = JMenuItem(u"Export JSON")
        exportJsonItem.addActionListener(lambda e: self.extender.export_workspace_json(e))
        file_menu.add(exportJsonItem)

        importJsonItem = JMenuItem(u"Import JSON")
        importJsonItem.addActionListener(lambda e: self.extender.import_workspace_json(e))
        file_menu.add(importJsonItem)

        file_menu.addSeparator()

        exportExcelItem = JMenuItem(u"Export XLS")
        exportExcelItem.addActionListener(lambda e: self.extender.export_excel(e))
        file_menu.add(exportExcelItem)

        exportSvgItem = JMenuItem(u"Export SVG")
        exportSvgItem.addActionListener(lambda e: self.extender.export_svg(e))
        file_menu.add(exportSvgItem)

        exportCanvasItem = JMenuItem(u"Export Canvas (Obsidian)")
        exportCanvasItem.addActionListener(lambda e: self.extender.export_canvas(e))
        file_menu.add(exportCanvasItem)

        fileBtn.addActionListener(lambda e: file_menu.show(fileBtn, 0, fileBtn.getHeight()))
        topBar.add(fileBtn)

        self.extender.hideTestedBtn = JToggleButton(u"Hide Tested")
        style_btn(self.extender.hideTestedBtn)
        def toggle_hide_tested(e):
            self.extender.hide_tested = self.extender.hideTestedBtn.isSelected()
            self.extender.auto_arrange(None)
            if hasattr(self.extender, 'features_master_model'):
                self.extender.update_features_master_table()
        self.extender.hideTestedBtn.addActionListener(toggle_hide_tested)
        topBar.add(self.extender.hideTestedBtn)

        view_toggle_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        btn_grp = ButtonGroup()

        btn_map = JToggleButton("Visual Map")
        btn_grid = JToggleButton("Grid View")
        btn_features = JToggleButton("Features View")
        btn_map.setSelected(True)

        for b in [btn_map, btn_grid, btn_features]:
            style_btn(b)
            btn_grp.add(b)
            view_toggle_panel.add(b)

        topBar.add(view_toggle_panel)

        self.extender.grid_controls_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        self.extender.grid_controls_panel.setOpaque(False)
        self.extender.grid_controls_panel.setVisible(False) 

        addColBtn = JButton("[+] Add Col")
        style_btn(addColBtn)
        def add_col_action(e):
            name = JOptionPane.showInputDialog(self.extender.mainPanel, "Enter column name:")
            if name and name.strip():
                self.extender.custom_columns.append(name.strip())
                self.extender.table_model.addColumn(name.strip())
                self.extender.apply_grid_renderer()
                self.extender.save_state()
        addColBtn.addActionListener(add_col_action)
        self.extender.grid_controls_panel.add(addColBtn)

        remColBtn = JButton("[-] Del Col")
        style_btn(remColBtn)
        def rem_col_action(e):
            if not self.extender.custom_columns: return
            res = JOptionPane.showInputDialog(self.extender.mainPanel, "Column to delete:", "Delete Column", JOptionPane.PLAIN_MESSAGE, None, self.extender.custom_columns, self.extender.custom_columns[0])
            if res:
                idx = self.extender.custom_columns.index(res)
                self.extender.custom_columns.remove(res)
                self.extender.table_model.setColumnCount(0)
                for c in self.extender.table_model.base_cols + self.extender.custom_columns:
                    self.extender.table_model.addColumn(c)
                self.extender.apply_grid_renderer()
                self.extender.populate_grid()
                self.extender.save_state()
        remColBtn.addActionListener(rem_col_action)
        self.extender.grid_controls_panel.add(remColBtn)

        delRowBtn = JButton("[x] Del Row")
        style_btn(delRowBtn)
        def del_row_action(e):
            rows = self.extender.gridTable.getSelectedRows()
            if rows:
                # Update: get the node from the tuple at index 0
                nodes_to_del = [self.extender.table_model.row_data_map[r][0] for r in rows]
                for n in nodes_to_del:
                    self.extender.delete_nodes(n)
                self.extender.populate_grid()
        delRowBtn.addActionListener(del_row_action)
        self.extender.grid_controls_panel.add(delRowBtn)

        self.extender.grid_controls_panel.add(Box.createHorizontalStrut(10))
        filter_lbl = JLabel("Method:")
        filter_lbl.setForeground(Color.LIGHT_GRAY)
        self.extender.grid_controls_panel.add(filter_lbl)
        self.extender.grid_method_filter = style_textfield(JTextField("", 6), BURP_ORANGE)
        def trigger_grid_filter(e):
            self.extender.populate_grid()
        self.extender.grid_method_filter.addKeyListener(type("FilterKey", (KeyAdapter,), {"keyReleased": lambda s, e: trigger_grid_filter(e)})())
        self.extender.grid_controls_panel.add(self.extender.grid_method_filter)

        topBar.add(self.extender.grid_controls_panel)

        self.extender.toolsBtn = JButton(u"Tools")
        style_btn(self.extender.toolsBtn)
        def toggle_sidebar(e):
            is_vis = not self.extender.sidebarScroll.isVisible()
            self.extender.sidebarScroll.setVisible(is_vis)
            if is_vis and hasattr(self.extender, 'split_pane'): 
                w = self.extender.split_pane.getWidth()
                target_loc = w - 260 if w > 300 else int(w * 0.7)
                self.extender.split_pane.setDividerLocation(target_loc)
            self.extender.mainPanel.revalidate()
        self.extender.toolsBtn.addActionListener(toggle_sidebar)
        topBar.add(self.extender.toolsBtn)

        self.extender.toggleLayoutBtn = JButton(u"Toggle View")
        style_btn(self.extender.toggleLayoutBtn)
        def toggle_layout(e):
            self.extender.is_vertical_layout = not self.extender.is_vertical_layout
            self.extender.auto_arrange(None)
        self.extender.toggleLayoutBtn.addActionListener(toggle_layout)
        topBar.add(self.extender.toggleLayoutBtn)

        self.extender.relateBtn = JToggleButton(u"Relate Nodes")
        style_btn(self.extender.relateBtn)
        def toggle_relate(e):
            self.extender.is_relating = self.extender.relateBtn.isSelected()
            self.extender.relate_source = None
            if self.extender.is_relating:
                self.extender.map_label.setCursor(Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR))
            else:
                self.extender.map_label.setCursor(Cursor.getDefaultCursor())
            self.extender.render_map()
        self.extender.relateBtn.addActionListener(toggle_relate)
        topBar.add(self.extender.relateBtn)

        def switch_view(mode):
            try:
                self.extender.selected_nodes = set()
                self.extender.selected_method = None
                self.extender.selected_feature_req = None
                self.extender.current_view_mode = mode
                if hasattr(self.extender, 'close_feature_note'):
                    self.extender.close_feature_note()
                self.extender.update_toolbar()

                is_map = (mode == "map")
                self.extender.toolsBtn.setVisible(is_map)
                self.extender.toggleLayoutBtn.setVisible(is_map)
                self.extender.relateBtn.setVisible(is_map)

                is_grid = (mode == "grid")
                self.extender.grid_controls_panel.setVisible(is_grid)

                if mode == "features":
                    self.extender.mainPanel.remove(self.extender.tabbed_pane)
                    self.extender.mainPanel.add(self.extender.outer_split_pane, BorderLayout.CENTER)
                else:
                    self.extender.mainPanel.remove(self.extender.outer_split_pane)
                    self.extender.mainPanel.add(self.extender.tabbed_pane, BorderLayout.CENTER)
                    self.extender.on_tab_changed()

                if mode == "map":
                    self.extender.viewCards.show(self.extender.viewContainer, "canvas")
                    self.extender.render_map()
                elif mode == "grid":
                    self.extender.populate_grid()
                    self.extender.viewCards.show(self.extender.viewContainer, "grid")
                elif mode == "features":
                    self.extender.update_features_master_table()
                    self.extender.viewCards.show(self.extender.viewContainer, "features")

                self.extender.mainPanel.revalidate()
                self.extender.mainPanel.repaint()
            except Exception as ex:
                self.extender.callbacks.printError("Error in switch_view: " + str(ex))

        btn_map.addActionListener(lambda e: switch_view("map"))
        btn_grid.addActionListener(lambda e: switch_view("grid"))
        btn_features.addActionListener(lambda e: switch_view("features"))

        self.extender.mainPanel.add(topBar, BorderLayout.NORTH)

        self.extender.sidebar = JPanel()
        self.extender.sidebar.setLayout(BoxLayout(self.extender.sidebar, BoxLayout.Y_AXIS))
        self.extender.sidebar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 1, 0, 0, Color.DARK_GRAY),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ))

        self.extender.sidebarScroll = JScrollPane(self.extender.sidebar)
        self.extender.sidebarScroll.getVerticalScrollBar().setUnitIncrement(16) 
        self.extender.sidebarScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self.extender.sidebarScroll.setBorder(BorderFactory.createEmptyBorder())

        self.extender.sidebarScroll.setPreferredSize(Dimension(260, 0))
        self.extender.sidebarScroll.setMinimumSize(Dimension(180, 0))
        self.extender.sidebarScroll.setVisible(False)

        def add_sidebar_section(title, comp):
            p = JPanel(BorderLayout(0, 5))
            p.setAlignmentX(JComponent.LEFT_ALIGNMENT)
            p.setMaximumSize(Dimension(Integer.MAX_VALUE, comp.getPreferredSize().height + 30)) 
            l = JLabel(title)
            l.setFont(Font("SansSerif", Font.BOLD, 11))
            l.setForeground(Color.LIGHT_GRAY)
            p.add(l, BorderLayout.NORTH)
            p.add(comp, BorderLayout.CENTER)
            self.extender.sidebar.add(p)
            self.extender.sidebar.add(Box.createVerticalStrut(15))

        f_panel = JPanel(GridLayout(8, 1, 2, 5))
        f_panel.add(JLabel("Exclude Exts:"))
        self.extender.filterField = style_textfield(JTextField(".js, .css, .png, .jpg, .jpeg, .gif, .svg, .ico, .woff, .woff2"), BURP_ORANGE)
        self.extender.filterField.addActionListener(lambda e: self.extender.auto_arrange(None)) 
        f_panel.add(self.extender.filterField)

        f_panel.add(JLabel("Include Exts:"))
        self.extender.includeField = style_textfield(JTextField(""), BURP_ORANGE)
        self.extender.includeField.addActionListener(lambda e: self.extender.auto_arrange(None)) 
        f_panel.add(self.extender.includeField)

        f_panel.add(JLabel("Hide Status Codes (comma separated):"))
        self.extender.hide_status_field = style_textfield(JTextField("0, 404, 500, 302, 301"), BURP_ORANGE)
        self.extender.hide_status_field.addActionListener(lambda e: self.extender.auto_arrange(None))
        f_panel.add(self.extender.hide_status_field)

        f_panel.add(JLabel("Hide Content-Length (comma separated):"))
        self.extender.cl_filter_field = style_textfield(JTextField(""), BURP_ORANGE)
        self.extender.cl_filter_field.addActionListener(lambda e: self.extender.auto_arrange(None))
        f_panel.add(self.extender.cl_filter_field)

        add_sidebar_section("FILTERS", f_panel)

        s_panel = JPanel(GridLayout(5, 1, 2, 5)) 
        self.extender.live_sync_cb = JCheckBox("Live Sync (Proxy)")
        self.extender.live_sync_cb.setSelected(True) 
        self.extender.params_cb = JCheckBox("Show Query Params")
        self.extender.params_cb.addActionListener(lambda e: self.extender.auto_arrange(None))
        self.extender.status_cb = JCheckBox("Show Status Codes")
        self.extender.status_cb.setSelected(True)
        self.extender.status_cb.addActionListener(lambda e: self.extender.auto_arrange(None))
        self.extender.param_only_cb = JCheckBox("Only Show Parameterized")
        self.extender.param_only_cb.addActionListener(lambda e: self.extender.auto_arrange(None))
        self.extender.hide_get_cb = JCheckBox("Hide GET Requests")
        self.extender.hide_get_cb.addActionListener(lambda e: self.extender.auto_arrange(None))
        s_panel.add(self.extender.live_sync_cb)
        s_panel.add(self.extender.params_cb)
        s_panel.add(self.extender.status_cb)
        s_panel.add(self.extender.param_only_cb)
        s_panel.add(self.extender.hide_get_cb)
        add_sidebar_section("SETTINGS", s_panel)

        a_panel = JPanel(GridLayout(2, 2, 8, 8))
        undoBtn = style_btn(JButton("Undo"))
        undoBtn.addActionListener(lambda e: self.extender.undo(e))
        a_panel.add(undoBtn)
        redoBtn = style_btn(JButton("Redo"))
        redoBtn.addActionListener(lambda e: self.extender.redo(e))
        a_panel.add(redoBtn)
        self.extender.zoomBtn = style_btn(JButton("Zoom 100%"))
        self.extender.zoomBtn.addActionListener(lambda e: self.extender.set_zoom(1.0))
        a_panel.add(self.extender.zoomBtn)
        arrangeBtn = style_btn(JButton("Arrange"))
        arrangeBtn.addActionListener(lambda e: self.extender.auto_arrange(e))
        a_panel.add(arrangeBtn)
        add_sidebar_section("ACTIONS", a_panel)

        c_panel = JPanel(GridLayout(0, 2, 8, 8))
        colors = {
            "Red": Color(255, 0, 0), "Orange": Color(255, 165, 0), "Yellow": Color(255, 255, 0),
            "Green": Color(0, 255, 0), "Blue": Color(0, 100, 255), "Purple": Color(128, 0, 128), "Clear": None
        }
        for name, c in colors.items():
            btn = style_btn(JButton(name), bg=Color(80, 83, 85))
            def make_action(color_val): return lambda e: self.extender.apply_color_to_selection(color_val)
            btn.addActionListener(make_action(c))
            c_panel.add(btn)
        add_sidebar_section("COLORS", c_panel)

        t_panel = JPanel(GridLayout(4, 1, 2, 5))
        themes = ["Default", "Light", "Synthwave", "Vibrant"]
        for t_name in themes:
            btn = style_btn(JButton(t_name), bg=Color(80, 83, 85))
            def make_theme_action(name): return lambda e: self.extender.set_theme(name)
            btn.addActionListener(make_theme_action(t_name))
            t_panel.add(btn)
        add_sidebar_section("THEMES", t_panel)

        self.extender.sidebar.add(Box.createVerticalGlue())

        # View 1: Canvas Map
        self.extender.map_label = JLabel()
        self.extender.map_label.setHorizontalAlignment(JLabel.LEFT) 
        self.extender.map_label.setVerticalAlignment(JLabel.TOP)
        self.extender.map_label.setLayout(None) 

        self.extender.inline_edit_field = JTextArea()
        self.extender.inline_edit_field.setLineWrap(True)
        self.extender.inline_edit_field.setWrapStyleWord(True)
        self.extender.inline_edit_field.setVisible(False)
        self.extender.inline_edit_field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(59, 130, 246), 2, True),
            BorderFactory.createEmptyBorder(2, 5, 2, 5)
        ))

        edit_listener = EditFieldListener(self.extender)
        self.extender.inline_edit_field.addKeyListener(edit_listener)
        self.extender.inline_edit_field.addFocusListener(edit_listener)
        self.extender.map_label.add(self.extender.inline_edit_field)

        mouse_handler = MapMouseHandler(self.extender)
        self.extender.map_label.addMouseListener(mouse_handler)
        self.extender.map_label.addMouseMotionListener(mouse_handler)
        self.extender.map_label.addMouseWheelListener(mouse_handler) 

        self.extender.canvasScroll = JScrollPane(self.extender.map_label)
        self.extender.canvasScroll.getHorizontalScrollBar().setUnitIncrement(24)
        self.extender.canvasScroll.getVerticalScrollBar().setUnitIncrement(24)
        self.extender.canvasScroll.setBorder(BorderFactory.createEmptyBorder())
        self.extender.canvasScroll.setFocusable(True)
        self.extender.canvasScroll.setFocusTraversalKeysEnabled(False)

        # View 2: Grid View
        self.extender.table_model = MindMapTableModel(self.extender)
        self.extender.gridTable = JTable(self.extender.table_model)
        self.extender.gridTable.setRowHeight(25)
        self.extender.gridTable.setFillsViewportHeight(True)
        self.extender.gridTable.getTableHeader().setFont(Font("SansSerif", Font.BOLD, 12))
        
        self.extender.gridTable.getColumnModel().getColumn(0).setMinWidth(60)
        self.extender.gridTable.getColumnModel().getColumn(0).setMaxWidth(100)
        
        self.extender.gridTable.getColumnModel().getColumn(3).setMinWidth(40)
        self.extender.gridTable.getColumnModel().getColumn(3).setMaxWidth(60)
        
        priv_col = self.extender.gridTable.getColumnModel().getColumn(4)
        priv_col.setMinWidth(90)
        priv_col.setMaxWidth(130)
        priv_col.setPreferredWidth(110)
        priv_col.setCellEditor(create_privilege_editor())
        
        note_col = self.extender.gridTable.getColumnModel().getColumn(5)
        note_col.setPreferredWidth(250)

        # Apply Checkbox + Color Renderer
        self.extender.apply_grid_renderer()

        def row_selected(e):
            if e.getValueIsAdjusting(): return
            rows = self.extender.gridTable.getSelectedRows()
            if rows:
                nodes = [self.extender.table_model.row_nodes[r] for r in rows if r < len(self.extender.table_model.row_nodes)]
                self.extender.selected_nodes = set(nodes)
            else:
                self.extender.selected_nodes = set()
            self.extender.update_toolbar()
        self.extender.gridTable.getSelectionModel().addListSelectionListener(row_selected)

        def grid_key_pressed(e):
            if e.getKeyCode() == KeyEvent.VK_DELETE:
                if self.extender.gridTable.isEditing(): return
                rows = self.extender.gridTable.getSelectedRows()
                if rows:
                    nodes_to_del = [self.extender.table_model.row_nodes[r] for r in rows]
                    for n in nodes_to_del:
                        self.extender.delete_nodes(n)
                    self.extender.populate_grid()
                    e.consume()
        self.extender.gridTable.addKeyListener(type("GridKeyListener", (KeyAdapter,), {"keyPressed": lambda s, e: grid_key_pressed(e)})())
        self.extender.gridTable.addMouseListener(GridMouseHandler(self.extender))

        grid_wrapper = JPanel(BorderLayout())
        self.extender.gridScroll = JScrollPane(self.extender.gridTable)
        self.extender.gridScroll.setBorder(BorderFactory.createEmptyBorder())
        grid_wrapper.add(self.extender.gridScroll, BorderLayout.CENTER)

        # View 3: Features View
        features_wrapper = JPanel(BorderLayout())
        feat_toolbar = JPanel(FlowLayout(FlowLayout.LEFT))

        recordBtn = JToggleButton("Record Feature")
        style_btn(recordBtn)
        recordBtn.setForeground(Color(255, 80, 80))
        def toggle_record(e):
            if recordBtn.isSelected():
                self.extender.is_recording_feature = True
                self.extender.recorded_reqs = []
                recordBtn.setText("Recording... (Stop)")
                self.extender.features_master_table.clearSelection()
                self.extender.features_reqs_model.current_feature = None
                self.extender.update_features_detail_table()
            else:
                self.extender.is_recording_feature = False
                recordBtn.setText("Record Feature")
        recordBtn.addActionListener(toggle_record)
        feat_toolbar.add(recordBtn)

        saveFeatBtn = JButton("Save Feature")
        style_btn(saveFeatBtn)
        def save_feat_action(e):
            if not self.extender.recorded_reqs:
                JOptionPane.showMessageDialog(self.extender.mainPanel, "No requests recorded.")
                return
            name = JOptionPane.showInputDialog(self.extender.mainPanel, "Enter Feature Name:")
            if name and name.strip():
                new_feat = {
                    "id": str(uuid.uuid4()),
                    "name": name.strip(),
                    "requests": list(self.extender.recorded_reqs),
                    "notes": "",
                    "privilege": "",
                    "tested": False
                }
                self.extender.features.append(new_feat)
                self.extender.save_state()
                self.extender.recorded_reqs = []
                if recordBtn.isSelected():
                    recordBtn.doClick()
                self.extender.update_features_master_table()
                self.extender.update_features_detail_table()
        saveFeatBtn.addActionListener(save_feat_action)
        feat_toolbar.add(saveFeatBtn)

        delFeatBtn = JButton("Delete Feature")
        style_btn(delFeatBtn)
        def del_feat_action(e):
            row = self.extender.features_master_table.getSelectedRow()
            if row >= 0:
                feat = self.extender.visible_features[row]
                self.extender.features.remove(feat)
                self.extender.features_reqs_model.current_feature = None
                self.extender.save_state()
                self.extender.update_features_master_table()
                self.extender.update_features_detail_table()
        delFeatBtn.addActionListener(del_feat_action)
        feat_toolbar.add(delFeatBtn)

        features_wrapper.add(feat_toolbar, BorderLayout.NORTH)

        master_panel = JPanel(BorderLayout())
        self.extender.features_master_model = FeaturesMasterTableModel(self.extender)
        self.extender.features_master_table = JTable(self.extender.features_master_model)
        self.extender.features_master_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.extender.features_master_table.setFillsViewportHeight(True)
        self.extender.features_master_table.setRowHeight(25)

        feat_name_col = self.extender.features_master_table.getColumnModel().getColumn(0)
        feat_name_col.setPreferredWidth(180)
        
        feat_reqs_col = self.extender.features_master_table.getColumnModel().getColumn(1)
        feat_reqs_col.setMaxWidth(40)
        
        feat_tested_col = self.extender.features_master_table.getColumnModel().getColumn(2)
        feat_tested_col.setMaxWidth(60)
        
        feat_priv_col = self.extender.features_master_table.getColumnModel().getColumn(3)
        feat_priv_col.setMinWidth(90)
        feat_priv_col.setMaxWidth(130)
        feat_priv_col.setPreferredWidth(110)
        feat_priv_col.setCellEditor(create_privilege_editor())

        # Apply Feature Master Renderer
        feat_master_text_renderer = PrivilegeRowRenderer(lambda r: self.extender.visible_features[r].get("privilege", "") if r < len(self.extender.visible_features) else "")
        feat_master_bool_renderer = PrivilegeBoolRenderer(lambda r: self.extender.visible_features[r].get("privilege", "") if r < len(self.extender.visible_features) else "")
        
        for i in range(self.extender.features_master_table.getColumnCount()):
            if i == 2:
                self.extender.features_master_table.getColumnModel().getColumn(i).setCellRenderer(feat_master_bool_renderer)
            else:
                self.extender.features_master_table.getColumnModel().getColumn(i).setCellRenderer(feat_master_text_renderer)

        self.extender.feature_note_area = JTextArea()
        self.extender.feature_note_area.setLineWrap(True)
        self.extender.feature_note_area.setWrapStyleWord(True)
        self.extender.feature_note_area.setBackground(UIManager.getColor("TextField.background") or Color.DARK_GRAY)
        self.extender.feature_note_area.setForeground(UIManager.getColor("TextField.foreground") or Color.WHITE)

        self.extender.feature_note_scroll = JScrollPane(self.extender.feature_note_area)
        self.extender.feature_note_scroll.setBorder(BorderFactory.createTitledBorder("Feature Notes"))
        self.extender.feature_note_scroll.setPreferredSize(Dimension(0, 150))
        self.extender.feature_note_scroll.setVisible(False)

        master_panel.add(JScrollPane(self.extender.features_master_table), BorderLayout.CENTER)
        master_panel.add(self.extender.feature_note_scroll, BorderLayout.SOUTH)

        def close_feature_note():
            if getattr(self.extender, 'editing_feature', None):
                self.extender.editing_feature["notes"] = self.extender.feature_note_area.getText()
                self.extender.save_state()
                self.extender.editing_feature = None
            self.extender.feature_note_scroll.setVisible(False)

        self.extender.close_feature_note = close_feature_note
        self.extender.features_master_table.addMouseListener(FeatureMasterMouseHandler(self.extender))

        def feat_master_selected(e):
            if e.getValueIsAdjusting(): return
            row = self.extender.features_master_table.getSelectedRow()
            if row >= 0:
                self.extender.features_reqs_model.current_feature = self.extender.visible_features[row]
                self.extender.update_features_detail_table()
        self.extender.features_master_table.getSelectionModel().addListSelectionListener(feat_master_selected)

        self.extender.features_reqs_model = FeatureReqsTableModel(self.extender)
        self.extender.features_reqs_table = JTable(self.extender.features_reqs_model)
        self.extender.features_reqs_table.setFillsViewportHeight(True)
        self.extender.features_reqs_table.setRowHeight(25)

        method_col = self.extender.features_reqs_table.getColumnModel().getColumn(0)
        method_col.setMinWidth(65)
        method_col.setMaxWidth(85)
        method_col.setPreferredWidth(70)
        
        req_priv_col = self.extender.features_reqs_table.getColumnModel().getColumn(3)
        req_priv_col.setMinWidth(90)
        req_priv_col.setMaxWidth(130)
        req_priv_col.setPreferredWidth(110)
        req_priv_col.setCellEditor(create_privilege_editor())

        def get_feat_req_priv(r):
            if self.extender.features_reqs_model.current_feature:
                reqs = self.extender.features_reqs_model.current_feature["requests"]
                if r < len(reqs): return reqs[r].get("privilege", "")
            return ""

        # Apply Feature Reqs Renderer (no boolean columns here)
        feat_req_renderer = PrivilegeRowRenderer(get_feat_req_priv)
        for i in range(self.extender.features_reqs_table.getColumnCount()):
            self.extender.features_reqs_table.getColumnModel().getColumn(i).setCellRenderer(feat_req_renderer)

        def feat_req_selected(e):
            if e.getValueIsAdjusting(): return
            row = self.extender.features_reqs_table.getSelectedRow()
            if row >= 0:
                if self.extender.features_reqs_model.current_feature:
                    self.extender.selected_feature_req = self.extender.features_reqs_model.current_feature["requests"][row]
                else:
                    self.extender.selected_feature_req = self.extender.recorded_reqs[row]
                self.extender.update_toolbar()
        self.extender.features_reqs_table.getSelectionModel().addListSelectionListener(feat_req_selected)
        self.extender.features_reqs_table.addMouseListener(FeatureReqsMouseHandler(self.extender))

        def feat_req_key_pressed(e):
            if e.getKeyCode() == KeyEvent.VK_DELETE:
                if self.extender.features_reqs_table.isEditing(): return
                row = self.extender.features_reqs_table.getSelectedRow()
                if row >= 0:
                    if self.extender.features_reqs_model.current_feature:
                        del self.extender.features_reqs_model.current_feature["requests"][row]
                        self.extender.save_state()
                        self.extender.update_features_master_table()
                    else:
                        del self.extender.recorded_reqs[row]
                    self.extender.update_features_detail_table()
                    e.consume()
        self.extender.features_reqs_table.addKeyListener(type("FeatKeyListener", (KeyAdapter,), {"keyPressed": lambda s, e: feat_req_key_pressed(e)})())

        feat_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, master_panel, JScrollPane(self.extender.features_reqs_table))
        feat_split.setResizeWeight(0.3)
        features_wrapper.add(feat_split, BorderLayout.CENTER)

        self.extender.viewCards = CardLayout()
        self.extender.viewContainer = JPanel(self.extender.viewCards)
        self.extender.viewContainer.add(self.extender.canvasScroll, "canvas")
        self.extender.viewContainer.add(grid_wrapper, "grid")
        self.extender.viewContainer.add(features_wrapper, "features")

        input_map = self.extender.canvasScroll.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        action_map = self.extender.canvasScroll.getActionMap()

        delete_action = DeleteNodeAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "delete_node")
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "delete_node")
        action_map.put("delete_node", delete_action)

        ctrl_mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()

        copy_action = CopyAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, ctrl_mask), "copy_node")
        action_map.put("copy_node", copy_action)

        cut_action = CutAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_X, ctrl_mask), "cut_node")
        action_map.put("cut_node", cut_action)

        paste_action = PasteAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_V, ctrl_mask), "paste_node")
        action_map.put("paste_node", paste_action)

        repeater_action = SendToRepeaterAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, ctrl_mask), "send_repeater")
        action_map.put("send_repeater", repeater_action)

        intruder_action = SendToIntruderAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_I, ctrl_mask), "send_intruder")
        action_map.put("send_intruder", intruder_action)

        main_input_map = self.extender.mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        main_action_map = self.extender.mainPanel.getActionMap()
        main_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, ctrl_mask), "send_repeater")
        main_action_map.put("send_repeater", repeater_action)
        main_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_I, ctrl_mask), "send_intruder")
        main_action_map.put("send_intruder", intruder_action)

        grid_input_map = self.extender.gridTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        grid_action_map = self.extender.gridTable.getActionMap()
        grid_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, ctrl_mask), "send_repeater")
        grid_action_map.put("send_repeater", repeater_action)
        grid_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_I, ctrl_mask), "send_intruder")
        grid_action_map.put("send_intruder", intruder_action)

        undo_action = UndoAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, ctrl_mask), "undo_action")
        action_map.put("undo_action", undo_action)
        zoom_in_action = ZoomInAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, ctrl_mask), "zoom_in")
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_ADD, ctrl_mask), "zoom_in")
        action_map.put("zoom_in", zoom_in_action)
        zoom_out_action = ZoomOutAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, ctrl_mask), "zoom_out")
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_SUBTRACT, ctrl_mask), "zoom_out")
        action_map.put("zoom_out", zoom_out_action)
        zoom_reset_action = ZoomResetAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_0, ctrl_mask), "zoom_reset")
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_NUMPAD0, ctrl_mask), "zoom_reset")
        action_map.put("zoom_reset", zoom_reset_action)
        add_child_action = AddChildNodeAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0), "add_child")
        action_map.put("add_child", add_child_action)

        self.extender.split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.extender.viewContainer, self.extender.sidebarScroll)
        self.extender.split_pane.setResizeWeight(1.0) 
        self.extender.split_pane.setContinuousLayout(True)
        self.extender.split_pane.setBorder(BorderFactory.createEmptyBorder())

        self.extender.request_panel = JPanel(BorderLayout())
        self.extender.request_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.DARK_GRAY))

        title_panel = JPanel(BorderLayout())
        title_panel.setOpaque(False)
        title_lbl = JLabel(" Selected Node/Feature Traffic Preview:")
        title_lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        title_lbl.setForeground(Color.LIGHT_GRAY)
        title_panel.add(title_lbl, BorderLayout.CENTER)

        close_preview_btn = JButton("X")
        close_preview_btn.setMargin(Insets(0, 4, 0, 4))
        close_preview_btn.setFocusPainted(False)
        close_preview_btn.setContentAreaFilled(False)
        close_preview_btn.setForeground(Color.LIGHT_GRAY)
        close_preview_btn.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5))
        close_preview_btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        def hide_preview(e):
            self.extender.request_panel.setVisible(False)
        close_preview_btn.addActionListener(hide_preview)
        title_panel.add(close_preview_btn, BorderLayout.EAST)

        self.extender.request_panel.add(title_panel, BorderLayout.NORTH)

        self.extender.request_editor = self.extender.callbacks.createMessageEditor(None, False)
        req_panel = JPanel(BorderLayout())
        req_panel.setBorder(BorderFactory.createTitledBorder("Request"))
        req_panel.add(self.extender.request_editor.getComponent(), BorderLayout.CENTER)

        self.extender.response_editor = self.extender.callbacks.createMessageEditor(None, False)
        res_panel = JPanel(BorderLayout())
        res_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        res_panel.add(self.extender.response_editor.getComponent(), BorderLayout.CENTER)

        self.extender.traffic_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_panel, res_panel)
        self.extender.traffic_split.setResizeWeight(0.5)
        self.extender.traffic_split.setContinuousLayout(True)
        self.extender.traffic_split.setBorder(BorderFactory.createEmptyBorder())

        self.extender.request_panel.add(self.extender.traffic_split, BorderLayout.CENTER)
        self.extender.request_panel.setVisible(False)

        self.extender.outer_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.extender.split_pane, self.extender.request_panel)
        self.extender.outer_split_pane.setResizeWeight(0.40)
        self.extender.outer_split_pane.setContinuousLayout(True)
        self.extender.outer_split_pane.setBorder(BorderFactory.createEmptyBorder())

        self.extender.split_pane.setMinimumSize(Dimension(0, 0))
        self.extender.request_panel.setMinimumSize(Dimension(0, 0))

        self.extender.tabbed_pane = JTabbedPane()
        self.extender.tabbed_pane.addChangeListener(lambda e: self.extender.on_tab_changed())
        self.extender.mainPanel.add(self.extender.tabbed_pane, BorderLayout.CENTER)

        self.extender.callbacks.customizeUiComponent(self.extender.mainPanel)
        self.extender.callbacks.addSuiteTab(self.extender)
        self.extender.callbacks.printOutput("AllInMapping Loaded, ready to mapping!")
