# -*- coding: utf-8 -*-
"""AllInMapping Burp extension package.

Layout:
  extender.py      AllInMapping: the object registered with Burp; composes the mixins
  constants.py     build stamp and shared colours
  model.py         MindMapNode tree + restored request/response wrappers
  core/            behaviour not tied to one view (state, ingestion, node edits, search, Burp tools)
  views/           the three views: map (render + mouse), grid, features; shared renderers/actions
  ui/              Swing construction (builder), toolbar/context menu, tabs, dialogs
  export/          .xls, .svg and Obsidian .canvas exporters

Mixin methods all run against the same shared state (set up in
AllInMapping.registerExtenderCallbacks), so they call each other through
self regardless of which file they live in.
"""
