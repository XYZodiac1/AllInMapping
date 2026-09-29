# -*- coding: utf-8 -*-
"""Visibility rules shared by the map and grid (filters, hide-tested, statuses)."""


class FilteringMixin(object):
    """Visibility rules shared by the map and grid (filters, hide-tested, statuses)."""

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
