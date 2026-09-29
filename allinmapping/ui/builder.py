# -*- coding: utf-8 -*-
"""Constructs the extension tab (top bar, sidebar, the three views, preview pane)."""
from javax.swing import BorderFactory, Box, BoxLayout, ButtonGroup, JButton, JCheckBox, JComponent, JLabel, JMenuItem, JOptionPane, JPanel, JPopupMenu, JScrollPane, JSplitPane, JTabbedPane, JTable, JTextArea, JTextField, JToggleButton, KeyStroke, ListSelectionModel, UIManager
from java.awt import BorderLayout, CardLayout, Color, Component, Cursor, Dimension, FlowLayout, Font, GridLayout, Insets
from java.awt.event import KeyAdapter, KeyEvent, MouseAdapter
from java.lang import Integer, Runnable
import uuid

from allinmapping.constants import BURP_ORANGE
from allinmapping.ui.widgets import menu_shortcut_mask, style_btn, style_textfield
from allinmapping.views.actions import AddChildNodeAction, CopyAction, CutAction, DeleteNodeAction, EditFieldListener, PasteAction, SendToFeatureAction, SendToIntruderAction, SendToRepeaterAction, UndoAction, ZoomInAction, ZoomOutAction, ZoomResetAction
from allinmapping.views.features import FeatureMasterMouseHandler, FeatureReqsMouseHandler, FeatureReqsTableModel, FeaturesMasterTableModel
from allinmapping.views.grid import GridMouseHandler, MindMapTableModel
from allinmapping.views.map_input import MapMouseHandler
from allinmapping.views.privilege import PrivilegeBoolRenderer, PrivilegeRowRenderer, create_privilege_editor


class UIBuilder(Runnable):
    """Builds the whole Swing UI on the EDT.

    Every widget other code needs is stored on the extender (self.extender.*);
    run() only decides the build order, each _build_* method owns one panel.
    """
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender.mainPanel = JPanel(BorderLayout())
        self._build_topbar()
        self._build_sidebar()
        self._build_map_view()
        grid_wrapper = self._build_grid_view()
        features_wrapper = self._build_features_view()

        self.extender.viewCards = CardLayout()
        self.extender.viewContainer = JPanel(self.extender.viewCards)
        self.extender.viewContainer.add(self.extender.canvasScroll, "canvas")
        self.extender.viewContainer.add(grid_wrapper, "grid")
        self.extender.viewContainer.add(features_wrapper, "features")

        self._bind_canvas_shortcuts()
        self._build_split_panes()

        self.extender.tabbed_pane = JTabbedPane()
        self.extender.tabbed_pane.addChangeListener(lambda e: self.extender.on_tab_changed())
        self.extender.mainPanel.add(self.extender.tabbed_pane, BorderLayout.CENTER)

        self.extender.callbacks.customizeUiComponent(self.extender.mainPanel)
        self.extender.callbacks.addSuiteTab(self.extender)

        self._bind_global_shortcuts()

        if self.extender.auto_load_on_start:
            self.extender.load_project_state()

        self.extender.callbacks.printOutput("AllInMapping Loaded, ready to map!")

    # ---- top bar ---------------------------------------------------------

    def _build_topbar(self):
        topBar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 10))
        self._add_file_controls(topBar)
        view_buttons = self._add_view_toggles(topBar)
        self._add_grid_controls(topBar)
        search_panel = self._add_search_panel(topBar)
        self._add_map_tools(topBar)
        self._wire_view_switching(view_buttons, search_panel)

        self.extender.last_saved_label = JLabel("Last saved: never")
        self.extender.last_saved_label.setForeground(Color.GRAY)
        self.extender.last_saved_label.setFont(Font("SansSerif", Font.PLAIN, 10))

        rightBar = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 10))
        rightBar.add(self.extender.last_saved_label)

        topBarWrapper = JPanel(BorderLayout())
        topBarWrapper.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.DARK_GRAY))
        topBar.setBorder(None)
        
        # Wrap the topBar in a horizontal ScrollPane to make it dynamic and prevent squishing
        topBarScroll = JScrollPane(topBar)
        topBarScroll.setBorder(BorderFactory.createEmptyBorder())
        topBarScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER)
        topBarScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        
        topBarWrapper.add(topBarScroll, BorderLayout.CENTER)
        topBarWrapper.add(rightBar, BorderLayout.EAST)

        self.extender.mainPanel.add(topBarWrapper, BorderLayout.NORTH)

    def _add_file_controls(self, topBar):
        """Load Scope, File menu, settings, custom mapping, hide-tested."""
        loadScopeBtn = JButton("Load Scope & History")
        style_btn(loadScopeBtn, bg=BURP_ORANGE)
        loadScopeBtn.setFont(Font("SansSerif", Font.BOLD, 11))
        def do_load_scope(e):
            self.extender.load_scope_and_history()
            self.extender.auto_arrange(None)
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

        file_menu.addSeparator()

        clearMapItem = JMenuItem(u"Clear Map")
        def do_clear_map(e):
            confirm = JOptionPane.showConfirmDialog(
                self.extender.mainPanel,
                "This clears every tab and node from the map (in memory only - "
                "nothing on disk is touched). Continue?",
                "Clear Map",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if confirm != JOptionPane.YES_OPTION: return
            self.extender.save_state()
            self.extender.target_roots = {}
            self.extender.tabbed_pane.removeAll()
            self.extender.activeRoot = None
            self.extender.selected_nodes = set()
            self.extender.live_processed_urls = set()
            self.extender.tabbed_pane.revalidate()
            self.extender.tabbed_pane.repaint()
        clearMapItem.addActionListener(do_clear_map)
        file_menu.add(clearMapItem)

        fileBtn.addActionListener(lambda e: file_menu.show(fileBtn, 0, fileBtn.getHeight()))
        topBar.add(fileBtn)

        settingsBtn = JButton(u"⚙")
        style_btn(settingsBtn, bg=Color(43, 43, 43))
        settingsBtn.setToolTipText("Settings (autosave interval)")
        settingsBtn.addActionListener(lambda e: self.extender.open_settings_dialog(e))
        topBar.add(settingsBtn)

        customMapBtn = JButton(u"Custom Mapping")
        style_btn(customMapBtn)
        customMapBtn.addActionListener(lambda e: self.extender.open_custom_mapping_dialog(e))
        topBar.add(customMapBtn)

        self.extender.hideTestedBtn = JToggleButton(u"Hide Tested")
        style_btn(self.extender.hideTestedBtn)
        def toggle_hide_tested(e):
            self.extender.hide_tested = self.extender.hideTestedBtn.isSelected()
            self.extender.auto_arrange(None)
            if hasattr(self.extender, 'features_master_model'):
                self.extender.update_features_master_table()
        self.extender.hideTestedBtn.addActionListener(toggle_hide_tested)
        topBar.add(self.extender.hideTestedBtn)

    def _add_view_toggles(self, topBar):
        """Map / Grid / Features toggle buttons."""
        view_toggle_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        btn_grp = ButtonGroup()

        btn_map = JToggleButton("Visual Map")
        btn_grid = JToggleButton("Grid View")
        btn_features = JToggleButton("Features View")
        btn_map.setSelected(True)
        self.extender.btn_map = btn_map

        for b in [btn_map, btn_grid, btn_features]:
            style_btn(b)
            btn_grp.add(b)
            view_toggle_panel.add(b)

        topBar.add(view_toggle_panel)
        return btn_map, btn_grid, btn_features

    def _add_grid_controls(self, topBar):
        """Add/remove column, delete row and filters (Grid view only)."""
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
                nodes_to_del = [self.extender.table_model.row_data_map[r][0] for r in rows]
                for n in nodes_to_del:
                    self.extender.delete_nodes(n)
                self.extender.populate_grid()
        delRowBtn.addActionListener(del_row_action)
        self.extender.grid_controls_panel.add(delRowBtn)

        self.extender.grid_controls_panel.add(Box.createHorizontalStrut(10))
        
        gridFiltersBtn = JButton(u"Filters ⚙") # "Filters ▾"
        style_btn(gridFiltersBtn)
        
        grid_filter_popup = JPopupMenu()
        grid_filter_panel = JPanel()
        grid_filter_panel.setLayout(BoxLayout(grid_filter_panel, BoxLayout.Y_AXIS))
        grid_filter_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        
        def add_filter_row(label_text, tf):
            lbl = JLabel(label_text)
            lbl.setAlignmentX(Component.LEFT_ALIGNMENT)
            tf.setAlignmentX(Component.LEFT_ALIGNMENT)
            tf.setMaximumSize(Dimension(300, 28))
            grid_filter_panel.add(lbl)
            grid_filter_panel.add(Box.createVerticalStrut(2))
            grid_filter_panel.add(tf)
            grid_filter_panel.add(Box.createVerticalStrut(8))

        # Define the fields with default rule settings
        self.extender.grid_method_filter = style_textfield(JTextField("", 20), BURP_ORANGE)
        self.extender.grid_ext_filter = style_textfield(JTextField(".js, .json, .css, .map, .ttf, .mp3, .otf, .mp4, .png, .jpg, .jpeg, .gif, .svg, .ico, .woff, .woff2, ttf", 20), BURP_ORANGE)
        self.extender.grid_status_filter = style_textfield(JTextField("400, 403, 404", 20), BURP_ORANGE)

        def trigger_grid_filter(e):
            self.extender.populate_grid()
            
        fk_listener = type("FilterKey", (KeyAdapter,), {"keyReleased": lambda s, e: trigger_grid_filter(e)})()
        self.extender.grid_method_filter.addKeyListener(fk_listener)
        self.extender.grid_ext_filter.addKeyListener(fk_listener)
        self.extender.grid_status_filter.addKeyListener(fk_listener)

        add_filter_row("Exclude Methods (e.g. OPTIONS, HEAD):", self.extender.grid_method_filter)
        add_filter_row("Exclude Exts (e.g. .js, .css):", self.extender.grid_ext_filter)
        add_filter_row("Exclude Statuses (e.g. 404, 400):", self.extender.grid_status_filter)

        grid_filter_popup.add(grid_filter_panel)
        gridFiltersBtn.addActionListener(lambda e: grid_filter_popup.show(gridFiltersBtn, 0, gridFiltersBtn.getHeight()))
        
        self.extender.grid_controls_panel.add(gridFiltersBtn)

        topBar.add(self.extender.grid_controls_panel)

    def _add_search_panel(self, topBar):
        # Always-visible (not tied to Grid View, unlike grid_controls_panel above)
        # so you can jump to a request from the map itself, not just filter rows.
        search_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        search_panel.setOpaque(False)
        search_lbl = JLabel("Find:")
        search_lbl.setForeground(Color.LIGHT_GRAY)
        search_panel.add(search_lbl)
        self.extender.search_field = style_textfield(JTextField("", 16), BURP_ORANGE)
        self.extender.search_field.addActionListener(lambda e: self.extender.perform_search(e))
        search_panel.add(self.extender.search_field)

        self.extender.search_count_label = JLabel("")
        self.extender.search_count_label.setForeground(Color.LIGHT_GRAY)
        self.extender.search_count_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        self.extender.search_count_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self.extender.search_count_label.setToolTipText("Click to jump to the next match")
        self.extender.search_count_label.addMouseListener(type("SearchCounterClick", (MouseAdapter,), {
            "mouseClicked": lambda s, e: self.extender.perform_search(e)
        })())
        search_panel.add(self.extender.search_count_label)

        # Clicking the counter (or pressing Enter again) both just re-trigger
        # perform_search, which advances to the next match when the query
        # hasn't changed - so the stale count (from the previous search)
        # needs clearing as soon as the text does change.
        def on_search_typed(e):
            current = self.extender.search_field.getText().strip().lower()
            if current != self.extender.search_query:
                self.extender.search_count_label.setText("")
        self.extender.search_field.addKeyListener(type("SearchTypedListener", (KeyAdapter,), {"keyReleased": lambda s, e: on_search_typed(e)})())

        topBar.add(search_panel)
        return search_panel

    def _add_map_tools(self, topBar):
        """Tools sidebar toggle, layout toggle, relate mode (Map view only)."""
        self.extender.toolsBtn = JButton(u"Tools")
        style_btn(self.extender.toolsBtn)
        def toggle_sidebar(e):
            is_vis = not self.extender.sidebarScroll.isVisible()
            self.extender.sidebarScroll.setVisible(is_vis)
            if is_vis and hasattr(self.extender, 'split_pane'): 
                w = self.extender.split_pane.getWidth()
                target_loc = w - 330 if w > 300 else int(w * 0.7)
                self.extender.split_pane.setDividerLocation(target_loc)
            self.extender.mainPanel.revalidate()
        self.extender.toolsBtn.addActionListener(toggle_sidebar)
        topBar.add(self.extender.toolsBtn)

        self.extender.toggleLayoutBtn = JButton(u"Toggle View")
        style_btn(self.extender.toggleLayoutBtn)
        def toggle_layout(e):
            self.extender.is_vertical_layout = not self.extender.is_vertical_layout
            self.extender.callbacks.saveExtensionSetting("MindMap_VerticalLayout", str(self.extender.is_vertical_layout))
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

    def _wire_view_switching(self, view_buttons, search_panel):
        btn_map, btn_grid, btn_features = view_buttons

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
                
                # Force the sidebar to close if switching to Grid or Features view
                if not is_map and hasattr(self.extender, 'sidebarScroll'):
                    self.extender.sidebarScroll.setVisible(False)

                is_grid = (mode == "grid")
                self.extender.grid_controls_panel.setVisible(is_grid)

                # Search only covers Map and Grid - hide it in Features view
                # rather than showing a control that can't do anything there.
                search_panel.setVisible(mode != "features")

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

    # ---- panels ----------------------------------------------------------

    def _build_sidebar(self):
        """Map "Tools" sidebar: filters, settings, actions, colours, themes."""
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

        # Use -1 (or omit height constraint) instead of 0 to allow the layout manager 
        # to calculate the height dynamically without deforming the tools.
        self.extender.sidebarScroll.setPreferredSize(Dimension(330, -1))
        self.extender.sidebarScroll.setMinimumSize(Dimension(200, -1))
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

    def _build_map_view(self):
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

    def _build_grid_view(self):
        # View 2: Grid View
        self.extender.table_model = MindMapTableModel(self.extender)
        self.extender.gridTable = JTable(self.extender.table_model)
        self.extender.gridTable.setAutoCreateRowSorter(True)
        self.extender.gridTable.setRowHeight(24)
        self.extender.gridTable.setFillsViewportHeight(True)
        self.extender.gridTable.getTableHeader().setFont(Font("SansSerif", Font.BOLD, 12))
        
        # Method Column (0) - Tight fit for standard HTTP verbs
        self.extender.gridTable.getColumnModel().getColumn(0).setMinWidth(50)
        self.extender.gridTable.getColumnModel().getColumn(0).setMaxWidth(65)
        self.extender.gridTable.getColumnModel().getColumn(0).setPreferredWidth(55)
        
        # Tested Column (3) - Just enough for the checkbox
        self.extender.gridTable.getColumnModel().getColumn(3).setMinWidth(45)
        self.extender.gridTable.getColumnModel().getColumn(3).setMaxWidth(55)
        self.extender.gridTable.getColumnModel().getColumn(3).setPreferredWidth(50)
        
        # Privilege Column (4) - Tight fit for "High Privs" / "No Auth"
        priv_col = self.extender.gridTable.getColumnModel().getColumn(4)
        priv_col.setMinWidth(75)
        priv_col.setMaxWidth(90)
        priv_col.setPreferredWidth(85)
        priv_col.setCellEditor(create_privilege_editor())
        
        # Note Column (5) - Allow it to expand freely
        note_col = self.extender.gridTable.getColumnModel().getColumn(5)
        note_col.setPreferredWidth(250)

        # Apply Checkbox + Color Renderer
        self.extender.apply_grid_renderer()

        def row_selected(e):
            if e.getValueIsAdjusting(): return
            rows = self.extender.gridTable.getSelectedRows()
            if rows:
                nodes = [self.extender.table_model.row_data_map[r][0] for r in rows if r < len(self.extender.table_model.row_data_map)]
                self.extender.selected_nodes = set(nodes)
                
                col = self.extender.gridTable.getColumnModel().getSelectionModel().getLeadSelectionIndex()
                if col >= 0:
                    model_col = self.extender.gridTable.convertColumnIndexToModel(col)
                    if model_col in (3, 4, 5):
                        return
            else:
                self.extender.selected_nodes = set()
                self.extender.selected_method = None
            self.extender.update_toolbar()

        def grid_key_pressed(e):
            if e.getKeyCode() == KeyEvent.VK_DELETE:
                if self.extender.gridTable.isEditing(): return
                rows = self.extender.gridTable.getSelectedRows()
                if rows:
                    nodes_to_del = [self.extender.table_model.row_data_map[r][0] for r in rows]
                    for n in nodes_to_del:
                        self.extender.delete_nodes(n)
                    self.extender.populate_grid()
                    e.consume()
        self.extender.gridTable.addKeyListener(type("GridKeyListener", (KeyAdapter,), {"keyPressed": lambda s, e: grid_key_pressed(e)})())
        self.extender.gridTable.addMouseListener(GridMouseHandler(self.extender))
        self.extender.gridTable.getSelectionModel().addListSelectionListener(row_selected)

        grid_wrapper = JPanel(BorderLayout())
        self.extender.gridScroll = JScrollPane(self.extender.gridTable)
        self.extender.gridScroll.setBorder(BorderFactory.createEmptyBorder())
        grid_wrapper.add(self.extender.gridScroll, BorderLayout.CENTER)
        return grid_wrapper

    def _build_features_view(self):
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
                self.extender.recorded_reqs = []
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
        self.extender.features_master_table.setAutoCreateRowSorter(True)
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
        self.extender.features_reqs_table.setAutoCreateRowSorter(True)
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
        return features_wrapper

    def _build_split_panes(self):
        """Views + sidebar split, and the request/response preview below it."""
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
        self.extender.req_panel = req_panel

        self.extender.response_editor = self.extender.callbacks.createMessageEditor(None, False)
        res_panel = JPanel(BorderLayout())
        res_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        res_panel.add(self.extender.response_editor.getComponent(), BorderLayout.CENTER)
        self.extender.res_panel = res_panel

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

    # ---- keyboard shortcuts ----------------------------------------------

    def _bind_canvas_shortcuts(self):
        input_map = self.extender.canvasScroll.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        action_map = self.extender.canvasScroll.getActionMap()

        delete_action = DeleteNodeAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "delete_node")
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "delete_node")
        action_map.put("delete_node", delete_action)

        ctrl_mask = menu_shortcut_mask()

        copy_action = CopyAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, ctrl_mask), "copy_node")
        action_map.put("copy_node", copy_action)

        cut_action = CutAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_X, ctrl_mask), "cut_node")
        action_map.put("cut_node", cut_action)

        paste_action = PasteAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_V, ctrl_mask), "paste_node")
        action_map.put("paste_node", paste_action)

        intruder_action = SendToIntruderAction(self.extender)
        input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_I, ctrl_mask), "send_intruder")
        action_map.put("send_intruder", intruder_action)

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

    def _bind_global_shortcuts(self):
        ctrl_mask = menu_shortcut_mask()

        # Global CTRL+R Binding (works universally across the UI based on view mode)
        repeater_action = SendToRepeaterAction(self.extender)
        main_input_map = self.extender.mainPanel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        main_action_map = self.extender.mainPanel.getActionMap()
        main_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, ctrl_mask), "send_repeater")
        main_action_map.put("send_repeater", repeater_action)
        
        send_feature_action = SendToFeatureAction(self.extender)
        
        # 1. Global Main Panel Binding
        main_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_G, ctrl_mask), "send_feature")
        main_action_map.put("send_feature", send_feature_action)

        # 2. Map Canvas Binding
        canvas_in_map = self.extender.canvasScroll.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        canvas_act_map = self.extender.canvasScroll.getActionMap()
        canvas_in_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_G, ctrl_mask), "send_feature")
        canvas_act_map.put("send_feature", send_feature_action)

        # 3. Grid Table Binding
        grid_input_map = self.extender.gridTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        grid_action_map = self.extender.gridTable.getActionMap()
        grid_input_map.put(KeyStroke.getKeyStroke(KeyEvent.VK_G, ctrl_mask), "send_feature")
        grid_action_map.put("send_feature", send_feature_action)
