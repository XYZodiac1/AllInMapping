# -*- coding: utf-8 -*-
"""Visual map: layout, drawing, hit-testing, zoom and themes."""
from javax.swing import ImageIcon, JLabel, UIManager
from java.awt import BasicStroke, Color, Font, Polygon, RenderingHints
from java.awt.geom import Path2D
from java.awt.image import BufferedImage

from allinmapping.constants import BURP_ORANGE


class MapRenderMixin(object):
    """Visual map: layout, drawing, hit-testing, zoom and themes."""

    def set_theme(self, theme_name):
        self.current_theme = theme_name
        self.callbacks.saveExtensionSetting("MindMap_Theme", theme_name)
        self.render_map()

    def set_zoom(self, new_zoom):
        self.zoom_factor = max(0.2, min(5.0, new_zoom))
        if getattr(self, 'current_view_mode', 'map') == 'map':
            self.render_map()

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
