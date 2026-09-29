# -*- coding: utf-8 -*-
"""The "Find:" box: matching nodes and jumping between matches."""
from javax.swing import JOptionPane, SwingUtilities
from java.awt import Rectangle


class SearchMixin(object):
    """The "Find:" box: matching nodes and jumping between matches."""

    def perform_search(self, event=None):
        if not hasattr(self, 'search_field') or not self.activeRoot: return
        query = self.search_field.getText().strip().lower()
        if not query:
            self.search_matches = []
            self.search_query = ""
            self.search_root = None
            self.search_index = -1
            self.update_search_counter()
            return

        # A repeat trigger (Enter again, or clicking Next) with the same query
        # against the same tab just advances to the next match. Anything else
        # (new text, or switching tabs) re-runs the search from scratch.
        is_repeat = (query == self.search_query and self.activeRoot is self.search_root)

        if not is_repeat:
            def node_matches(node):
                if node.text and query in node.text.lower(): return True
                try:
                    if query in node.get_full_url().lower(): return True
                except Exception:
                    pass
                if any(query in m.lower() for m in node.methods): return True
                if node.note and query in node.note.lower(): return True
                if any(query in p.lower() for p in node.params): return True
                return False

            matches = []
            def walk(node):
                if node_matches(node): matches.append(node)
                for child in node.children:
                    walk(child)
            walk(self.activeRoot)

            self.search_matches = matches
            self.search_query = query
            self.search_root = self.activeRoot
            self.search_index = -1

        if not self.search_matches:
            JOptionPane.showMessageDialog(self.mainPanel, u"No request found matching \"{0}\".".format(self.search_field.getText().strip()))
            self.update_search_counter()
            return

        self.search_index = (self.search_index + 1) % len(self.search_matches)
        self.update_search_counter()
        self.jump_to_match(self.search_matches[self.search_index])

    def update_search_counter(self):
        if not hasattr(self, 'search_count_label'): return
        if not self.search_matches:
            self.search_count_label.setText("")
        else:
            self.search_count_label.setText(u"{0}/{1}".format(self.search_index + 1, len(self.search_matches)))

    def jump_to_match(self, match):
        # Expand any collapsed ancestors so the match actually gets laid out
        # and rendered rather than being hidden inside a folded branch.
        ancestor = match.parent
        while ancestor is not None:
            ancestor.collapsed = False
            ancestor = ancestor.parent

        self.selected_nodes = {match}
        self.selected_method = None

        mode = getattr(self, 'current_view_mode', 'map')
        if mode == 'grid':
            self.select_node_in_grid(match)
        elif mode == 'features':
            JOptionPane.showMessageDialog(self.mainPanel,
                u"Found \"{0}\", but search doesn't cover Features view yet "
                u"(features aren't tied to a single map node) - switch to "
                u"Visual Map or Grid View to jump to it.".format(match.text))
        else:
            self.auto_arrange(None)
            self.update_toolbar()
            self.scroll_to_node(match)

    def scroll_to_node(self, node):
        if not hasattr(self, 'map_label'): return
        z = self.zoom_factor
        pad = 80
        x = int(node.x * z) - pad
        y = int(node.y * z) - pad
        w = int(node.width * z) + pad * 2
        h = int(node.height * z) + pad * 2
        rect = Rectangle(max(0, x), max(0, y), w, h)
        try:
            SwingUtilities.invokeLater(lambda: self.map_label.scrollRectToVisible(rect))
        except Exception:
            pass
