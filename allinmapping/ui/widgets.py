# -*- coding: utf-8 -*-
"""Small Swing styling helpers shared by the UI builder."""
from javax.swing import BorderFactory
from java.awt import Color, Cursor, Dimension, Font, Toolkit
from java.lang import Integer


def style_btn(b, bg=Color(60, 63, 65), fg=Color.WHITE):
    b.setBackground(bg)
    b.setForeground(fg)
    b.setFocusPainted(False)
    b.setFont(Font("SansSerif", Font.PLAIN, 11))
    b.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(bg.darker(), 1, True),
        BorderFactory.createEmptyBorder(4, 10, 4, 10)
    ))
    b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
    return b

def style_textfield(tf, border_color=Color.GRAY):
    tf.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(border_color, 1, True),
        BorderFactory.createEmptyBorder(4, 6, 4, 6)
    ))
    tf.setMaximumSize(Dimension(Integer.MAX_VALUE, tf.getPreferredSize().height))
    return tf


def menu_shortcut_mask():
    """Ctrl on Windows/Linux, Cmd on macOS."""
    return Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()
