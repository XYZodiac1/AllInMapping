# -*- coding: utf-8 -*-
"""Editing the node tree: clipboard, inline edit, add/delete, status, colour, notes."""
from javax.swing import JOptionPane, JScrollPane, JTextArea, SwingUtilities
from java.awt import Color, Font, Toolkit
from java.awt.datatransfer import DataFlavor, StringSelection
import uuid

from allinmapping.model import MindMapNode


class NodeOpsMixin(object):
    """Editing the node tree: clipboard, inline edit, add/delete, status, colour, notes."""

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

    def find_node_by_id(self, current_node, search_id):
        if not current_node: return None
        if getattr(current_node, 'id', None) == search_id: return current_node
        for child in current_node.children:
            res = self.find_node_by_id(child, search_id)
            if res: return res
        return None

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
