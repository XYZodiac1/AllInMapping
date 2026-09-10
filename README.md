# All In Mapping (Burp Suite Extension)

A highly interactive, visually-driven Burp Suite extension designed to streamline pentesting workflows. This tool transforms traditional flat-list target mapping into a dynamic, central hub featuring Visual MindMaps, customizable Data Grids, and Attack Chain Feature Recording.

## 🚀 Features

### 1. Visual MindMap View
* **Dynamic Node Generation:** Automatically builds a visual tree of endpoints as you browse targets in scope.
* **Custom Node Management:** Manually add, rename, copy, paste, or delete child boxes. 
* **Relate Nodes:** Draw customized, curved connection lines between different endpoints to map multi-step logic flows.
* **Status & Severity Tracking:** Right-click to assign custom colors, vulnerability severities, or testing statuses (e.g., *In Progress*, *Tested*, *Vulnerable*).
* **Inline Notes:** Double-click nodes to rename them, or attach pentester notes (indicated by a yellow visual corner tag).

### 2. Custom Grid View
* **Excel-style Table:** View your entire attack surface in a flat, sortable grid.
* **Dynamic Custom Columns:** Add (`+`) or remove (`-`) custom columns on the fly to track methodology checklists, parameters, or custom tags.
* **XLS Export:** Instantly export the Grid View to a perfectly formatted Excel (`.xls`) file for reporting.

### 3. Features View (Attack Chains)
* **Feature Recording:** Press "Record Feature" to intercept and queue in-scope HTTP requests. Perfect for mapping complex functionality like "Password Reset" or "Checkout Flow".
* **Dedicated Notes:** Each step in the recorded attack chain has an inline text editor for capturing parameters, payloads, or logic flaws.
* **Clean UI:** Disables clutter when active, providing a distraction-free split pane for managing your functional attack paths.

### 4. Quality of Life & Integrations
* **Live Traffic Preview:** Selecting any node or feature request brings up an instant split-pane preview of the HTTP Request/Response, complete with syntax highlighting.
* **Burp Suite Integration:** Send requests directly from nodes to *Repeater*, *Intruder*, or *Active Scan*. Use the global right-click menu anywhere in Burp to "Send to MindMap Playbook".
* **Persistent State Tracking:** 10-step Undo/Redo history.
* **Export Options:** Save the workspace state natively to your Burp Project file, export/import as JSON, or export the Map graphic as an SVG vector file.

## 🛠️ Installation
1. Ensure you have [Jython](https://www.jython.org/) loaded into Burp Suite (`Extender` > `Options` > `Python Environment`).
2. Go to the `Extensions` tab.
3. Click `Add`.
4. Select `Extension Type: Python`.
5. Locate and select the `MindMap.py` file.
6. Click `Next` and the extension will load a new tab named **Visual MindMap**.

## 🎨 Themes
Swap the UI aesthetic instantly using the built-in sidebar panel. Supported themes:
* **Default** (Burp Orange)
* **Light** (Dracula inspired)
* **Synthwave** (Ayu Dark inspired)
* **Vibrant** (High contrast neon)

## ⌨️ Shortcuts & Hotkeys
| Action | Keybinding |
| :--- | :--- |
| Delete Node/Row | `Del` / `Backspace` |
| Add Child Node | `Tab` |
| Copy | `Ctrl` + `C` |
| Cut | `Ctrl` + `X` |
| Paste | `Ctrl` + `V` |
| Send to Repeater | `Ctrl` + `R` |
| Undo | `Ctrl` + `Z` |
| Zoom In/Out/Reset | `Ctrl` + `+` / `-` / `0` |
| Mouse Wheel Zoom | `Ctrl` + `Scroll` |
