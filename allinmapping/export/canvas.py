# -*- coding: utf-8 -*-
"""Map -> Obsidian .canvas export."""
from javax.swing import JFileChooser, JOptionPane
import json
import uuid


class CanvasExportMixin(object):
    """Map -> Obsidian .canvas export."""

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
