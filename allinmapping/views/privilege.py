# -*- coding: utf-8 -*-
"""Privilege-level colouring shared by the grid and features tables."""
from javax.swing import BorderFactory, DefaultCellEditor, JCheckBox, JComboBox, UIManager
from javax.swing.table import DefaultTableCellRenderer, TableCellRenderer
from java.awt import Color


def get_privilege_color(priv_level, is_selected, is_dark_theme):
    if not priv_level: return None
    
    pl = priv_level.strip().lower()
    if pl == "no auth":
        base = Color(38, 65, 105) if is_dark_theme else Color(173, 216, 230) # Medium Blue
    elif pl == "low privs":
        base = Color(38, 90, 50) if is_dark_theme else Color(144, 238, 144) # Medium Green
    elif pl == "high privs":
        base = Color(115, 42, 42) if is_dark_theme else Color(255, 182, 193) # Medium Red
    else:
        # Custom Privilege
        base = Color(32, 95, 105) if is_dark_theme else Color(224, 255, 255) # Medium Cyan

    if is_selected:
        return base.darker()
    return base


def create_privilege_editor():
    combo = JComboBox(["", "No Auth", "Low Privs", "High Privs"])
    combo.setEditable(True)
    editor = DefaultCellEditor(combo)
    editor.setClickCountToStart(1) # Start editing on single click
    return editor


class PrivilegeRowRenderer(DefaultTableCellRenderer):
    def __init__(self, data_source_callback):
        self.data_source_callback = data_source_callback
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        priv = self.data_source_callback(row)
        
        is_dark = UIManager.getColor("Panel.background").getRed() < 128
        bg_color = get_privilege_color(priv, isSelected, is_dark)
        
        if bg_color:
            c.setBackground(bg_color)
            if is_dark:
                c.setForeground(Color.WHITE if not isSelected else table.getSelectionForeground())
            else:
                c.setForeground(Color.BLACK if not isSelected else table.getSelectionForeground())
        else:
            c.setBackground(table.getSelectionBackground() if isSelected else table.getBackground())
            c.setForeground(table.getSelectionForeground() if isSelected else table.getForeground())
            
        return c


class PrivilegeBoolRenderer(JCheckBox, TableCellRenderer):
    def __init__(self, data_source_callback):
        self.data_source_callback = data_source_callback
        self.setHorizontalAlignment(JCheckBox.CENTER)
        self.setOpaque(True)
        self.setBorderPainted(True) # Fix for the missing vertical grid line
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        if value is not None:
            self.setSelected(bool(value))
        else:
            self.setSelected(False)
            
        priv = self.data_source_callback(row)
        is_dark = UIManager.getColor("Panel.background").getRed() < 128
        bg_color = get_privilege_color(priv, isSelected, is_dark)
        
        if bg_color:
            self.setBackground(bg_color)
        else:
            self.setBackground(table.getSelectionBackground() if isSelected else table.getBackground())
            
        # Restore standard JTable cell borders to draw the gridlines
        if hasFocus:
            border = UIManager.getBorder("Table.focusCellHighlightBorder")
        else:
            border = UIManager.getBorder("Table.cellNoFocusBorder")
            
        self.setBorder(border if border else BorderFactory.createEmptyBorder(1, 1, 1, 1))
        
        return self
