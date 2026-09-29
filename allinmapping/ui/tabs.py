# -*- coding: utf-8 -*-
"""Per-host target tabs."""
from javax.swing import BorderFactory, JLabel, JPanel, JTextField
from java.awt import BorderLayout, CardLayout, Cursor, Dimension, Font
from java.awt.event import FocusListener, MouseAdapter

from allinmapping.model import MindMapNode


class TabsMixin(object):
    """Per-host target tabs."""

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
