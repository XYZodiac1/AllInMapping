# -*- coding: utf-8 -*-
"""Keyboard-shortcut actions and the inline-edit listener."""
from javax.swing import AbstractAction, SwingUtilities
from java.awt.event import FocusListener, KeyAdapter, KeyEvent


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


class SendToFeatureAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        if self.extender.selected_nodes:
            SwingUtilities.invokeLater(lambda: self.extender.add_nodes_to_feature(list(self.extender.selected_nodes)))


class CutAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e): self.extender.cut_nodes()


# Master action handles CTRL+R for ALL views cleanly
class SendToRepeaterAction(AbstractAction):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        mode = getattr(self.extender, 'current_view_mode', 'map')
        if mode in ['map', 'grid']:
            if len(self.extender.selected_nodes) == 1:
                self.extender.send_to_repeater(list(self.extender.selected_nodes)[0])
        elif mode == 'features':
            if getattr(self.extender, 'selected_feature_req', None):
                self.extender.send_feature_req_to_repeater(self.extender.selected_feature_req)
            else:
                row = self.extender.features_master_table.getSelectedRow()
                if row >= 0:
                    feature = self.extender.visible_features[row]
                    self.extender.send_feature_to_repeater(feature)


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
