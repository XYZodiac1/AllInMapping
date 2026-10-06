# -*- coding: utf-8 -*-
"""Map -> .svg export."""
from javax.swing import JFileChooser, JOptionPane


class SvgExportMixin(object):
    """Map -> .svg export."""

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
            if getattr(node, 'custom_color', None):
                c = node.custom_color
                bg = "rgba({},{},{},{})".format(c.getRed(), c.getGreen(), c.getBlue(), c.getAlpha()/255.0)
            elif level == 0: bg = "gray"

            bc = "#e56a25" 
            if getattr(self, 'current_theme', '') == "Light": 
                dracula_hex = ["#bd93f9", "#50fa7b", "#8be9fd", "#ff79c6", "#f1fa8c", "#ffb86c"]
                bc = dracula_hex[level % len(dracula_hex)]
            elif getattr(self, 'current_theme', '') == "Synthwave": 
                ayu_hex = ["#d2a8ff", "#39bae6", "#aad94c", "#ffb454", "#f07178", "#59c2ff"]
                bc = ayu_hex[level % len(ayu_hex)]
            elif getattr(self, 'current_theme', '') == "Vibrant": 
                Vibrant_hex = ["#ffffff", "#00e5ff", "#ff2a2a", "#00ffc3", "#d500ff", "#adff00"]
                bc = Vibrant_hex[level % len(Vibrant_hex)]

            node_status = getattr(node, 'status', '')
            if node_status == "Vulnerable": bc = "red"
            elif node_status == "Tested": bc = "green"
            elif node_status == "In Progress": bc = "yellow"

            # 1. Draw the rounded rectangle
            lines.append('<rect x="{}" y="{}" width="{}" height="{}" rx="8" ry="8" fill="{}" stroke="{}" stroke-width="1.5"/>'.format(
                node.x, node.y, node.width, node.height, bg, bc))

            # 2. Safely Draw Text
            try:
                text_x = int(node.x + (node.width / 2.0))
                
                # --- EXTRACT METHODS AND STATUS CODES SAFELY ---
                sub_label_parts = []
                if getattr(node, 'methods', None):
                    try:
                        m_list = [str(m) for m in node.methods if m]
                        if m_list: sub_label_parts.append(" ".join(m_list))
                    except Exception: pass
                
                if getattr(node, 'statuses', None):
                    try:
                        s_list = [str(s) for s in node.statuses if s]
                        if s_list: sub_label_parts.append("[" + " ".join(s_list) + "]")
                    except Exception: pass
                    
                sub_label = " ".join(sub_label_parts).strip()
                
                # --- CALCULATE VERTICAL ALIGNMENT ---
                if sub_label:
                    text_y_primary = int(node.y + 18)
                    text_y_secondary = int(node.y + 32)
                else:
                    text_y_primary = int(node.y + 24)
                
                # --- DRAW PRIMARY TEXT ---
                raw_text = getattr(node, 'text', 'Unknown')
                if not raw_text: raw_text = "Unknown"
                
                try:
                    node_label = str(raw_text)
                except Exception:
                    try: node_label = raw_text.encode('utf-8', 'ignore')
                    except Exception: node_label = "Unknown"
                    
                node_label = node_label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
                
                lines.append('<text x="{}" y="{}" fill="#ffffff" font-size="12" font-family="sans-serif" text-anchor="middle">{}</text>'.format(
                    text_x, text_y_primary, node_label))
                    
                # --- DRAW SECONDARY TEXT (POST [200]) ---
                if sub_label:
                    sub_label = sub_label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
                    lines.append('<text x="{}" y="{}" fill="#888888" font-size="10" font-family="sans-serif" text-anchor="middle">{}</text>'.format(
                        text_x, text_y_secondary, sub_label))
                        
            except Exception:
                # If an extreme error occurs rendering text for a single node, 
                # ignore it so it doesn't crash the entire map.
                pass

            if getattr(node, 'collapsed', False): return 
            for child in node.children:
                draw_nodes(child, level + 1)

        draw_nodes(self.activeRoot, 0)
        lines.append('</svg>')
        return "\n".join(lines)