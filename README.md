# All In Mapping (Burp Suite Extension)

All In Mapping is a highly interactive, visually-driven Burp Suite extension built to streamline web application pentesting and bug bounty workflows. Instead of relying entirely on Burp's default flat-list site map, this tool acts as your central command center—transforming raw HTTP traffic into dynamic visual nodes, customizable data grids, and recorded attack chains. It helps you visualize complex application logic, track your testing coverage, and build comprehensive attack playbooks without ever leaving Burp Suite.

## 📋 Requirements

Before installing, ensure you have the following set up in your Burp Suite environment:
* **Burp Suite:** Professional or Community Edition.
* **Jython Standalone:** Required to run Python extensions in Burp. 
  1. Download the `jython-standalone-x.x.x.jar` from the [official Jython website](https://www.jython.org/download).
  2. In Burp Suite, navigate to **Extensions** > **Extension Settings** > **Python Environment**.
  3. Set the "Location of Jython standalone JAR file" to your downloaded file.

## 🛠️ Installation

1. Go to the **Extensions** tab in Burp Suite.
2. Click **Add** under the "Installed" tab.
3. Set the **Extension Type** to **Python**.
4. Click **Select file...** and choose your downloaded `AllInMapping.py` file.
5. Click **Next**. The extension will load and a new tab named **Visual MindMap** will appear in your top navigation bar.

## 💡 Examples of Use (Workflows)

Here is how All In Mapping actively improves a standard pentest:

* **Visualizing the Attack Surface (The MindMap):** As you proxy traffic through Burp, the extension automatically builds a branching visual tree of the application's structure (e.g., branching `/api/` into `/users/` and `/payments/`). You can visually spot orphaned endpoints, tag highly privileged routes in red, and draw relationship lines connecting an authentication endpoint to a restricted dashboard.
* **Methodology Tracking (Grid View):** You are auditing 50 different API endpoints for IDOR. Using the Grid View, you click **[+] Add Col** to create custom columns like "IDOR Tested" and "SQLi Checked". As you test each endpoint, you update the grid, keeping perfect track of your methodology coverage. When finished, you export the entire grid to `.xls` for your final report.
* **Building Attack Chains (Features View):** You need to test a multi-step checkout vulnerability. You click **Record Feature**, name it "Checkout Race Condition", and perform the flow in your browser. The tool isolates and saves the exact sequence of requests (Add to Cart -> Apply Promo -> Process Payment). You can add custom notes to each step and assign privilege levels (e.g., "Low Privs"), creating a repeatable playbook.

---

## 🚀 Core Features

### 1. Visual MindMap View
* **Dynamic Node Generation:** Automatically builds a visual tree of endpoints as you browse targets in scope.
* **Custom Node Management:** Manually add, rename, copy, paste, or delete child boxes. 
* **Relate Nodes:** Draw customized, curved connection lines between different endpoints to map multi-step logic flows.
* **Status & Privilege Tracking:** Right-click nodes to assign specific testing statuses (*In Progress*, *Tested*, *Vulnerable*) or privilege levels (*No Auth*, *Low Privs*, *High Privs*) which automatically color-code the nodes.
* **Inline Notes:** Double-click nodes to rename them, or attach pentester notes (indicated by a yellow visual corner tag).

### 2. Custom Grid View
* **Excel-style Table:** View your entire attack surface in a flat, sortable grid that automatically separates different HTTP methods (GET, POST, PUT) into their own distinct rows.
* **Dynamic Custom Columns:** Add or remove custom columns on the fly to track methodology checklists, parameters, or custom tags.
* **XLS Export:** Instantly export the Grid View to a perfectly formatted Excel (`.xls`) file for client reporting.

### 3. Features View (Attack Chains)
* **Feature Recording:** Intercept and queue in-scope HTTP requests. Perfect for mapping complex functionality like password resets or logical workflows.
* **Dedicated Notes & Privilege Mapping:** Each step in the recorded attack chain has an inline text editor and privilege dropdown for capturing parameters, payloads, or session requirements.
* **Clean UI:** Disables clutter when active, providing a distraction-free split pane for managing functional attack paths.

### 4. Quality of Life & Integrations
* **Live Traffic Preview:** Selecting any node or feature request brings up an instant split-pane preview of the HTTP Request/Response, complete with syntax highlighting.
* **Burp Suite Integration:** Send requests directly from nodes to *Repeater*, *Intruder*, or *Active Scan*. Use the global right-click menu anywhere in Burp to "Send to MindMap Playbook".
* **Persistent State Tracking:** Features a robust 10-step Undo/Redo history.
* **Export Options:** Save the workspace state natively to your Burp Project file, export/import as JSON, export to Obsidian Canvas (`.canvas`), or export the Map graphic as an SVG vector file.

---

## 🎨 Themes
Swap the UI aesthetic instantly using the built-in sidebar panel so it perfectly matches your Burp Suite setup. Supported themes:
* **Default** (Burp Orange)
* **Light** (Dracula inspired)
* **Synthwave** (Ayu Dark inspired)
* **Vibrant** (High contrast neon)

## ⌨️ Shortcuts & Hotkeys

| Action | Keybinding |
| :--- | :--- |
| **Delete Node/Row** | `Del` / `Backspace` |
| **Add Child Node** | `Tab` |
| **Copy** | `Ctrl` + `C` |
| **Cut** | `Ctrl` + `X` |
| **Paste** | `Ctrl` + `V` |
| **Send to Repeater** | `Ctrl` + `R` |
| **Send to Intruder** | `Ctrl` + `I` |
| **Undo** | `Ctrl` + `Z` |
| **Zoom In/Out/Reset** | `Ctrl` + `+` / `-` / `0` |
| **Mouse Wheel Zoom** | `Ctrl` + `Scroll` |
