# -*- coding: utf-8 -*-
"""Mouse interaction on the visual map (select, drag, relate, zoom)."""
from javax.swing import SwingUtilities
from java.awt import BasicStroke, Cursor
from java.awt.event import MouseAdapter


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
