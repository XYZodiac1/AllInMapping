# -*- coding: utf-8 -*-
"""Turning Burp traffic (live proxy, site map/history, "Send to map") into map nodes."""
from javax.swing import JLabel, JMenuItem, JOptionPane, SwingUtilities
from java.awt import Color
import uuid
from java.util import ArrayList

from allinmapping.model import MindMapNode, RestoredReqRes


class IngestMixin(object):
    """Turning Burp traffic (live proxy, site map/history, "Send to map") into map nodes."""

    def get_content_length(self, response):
        if not response: return 0
        info = self.helpers.analyzeResponse(response)
        for header in info.getHeaders():
            if header.lower().startswith("content-length:"):
                try: return int(header.split(":")[1].strip())
                except: pass
        return len(response) - info.getBodyOffset()

    def extract_custom_mapping_value(self, rule, raw_text):
        start = rule.get("start", "")
        end = rule.get("end", "")
        if not start or not end: return None

        # Collect every place "start" occurs, since it can legitimately repeat
        # (nested objects, repeated field names, nearby headers) and a naive
        # "first occurrence" search would then anchor on the wrong one
        # depending on what else happens to be in that particular request.
        candidates = []
        search_from = 0
        while True:
            start_idx = raw_text.find(start, search_from)
            if start_idx == -1: break
            value_start = start_idx + len(start)
            end_idx = raw_text.find(end, value_start)
            if end_idx != -1:
                candidates.append((start_idx, raw_text[value_start:end_idx]))
            search_from = start_idx + 1

        if not candidates: return None

        ratio = rule.get("sample_offset_ratio")
        if ratio is not None and len(candidates) > 1:
            target_pos = ratio * len(raw_text)
            _, raw_value = min(candidates, key=lambda c: abs(c[0] - target_pos))
        else:
            _, raw_value = candidates[0]

        value = raw_value.strip()
        value = u" ".join(value.split())
        if not value: return None
        if len(value) > 80: value = value[:77] + u"..."
        return value

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            item = JMenuItem("Send to MindMap Playbook")
            messages = invocation.getSelectedMessages()
            if messages:
                item.addActionListener(lambda e: self.handle_global_send_to_map(messages[0]))
                menu_list.add(item)
        return menu_list

    def handle_global_send_to_map(self, reqRes):
        if getattr(self, 'is_prompting', False): return 
        self.is_prompting = True

        try:
            info = self.helpers.analyzeRequest(reqRes)
            url_obj = info.getUrl()
            host = url_obj.getHost()

            if host not in self.target_roots:
                self.add_target_tab(host)

            target_root = self.target_roots[host]

            node_title = JOptionPane.showInputDialog(self.mainPanel, "Enter a title for this Attack Box:", "Test for XYZ attack")
            if not node_title or not node_title.strip():
                return

            self.save_state()

            new_node = MindMapNode(node_title.strip(), parent=target_root)
            new_node.is_playbook_node = True
            
            method = info.getMethod()
            new_node.methods.add(method)
            new_node.method_requests[method] = self.callbacks.saveBuffersToTempFiles(reqRes)
            new_node.linked_request = new_node.method_requests[method]

            dummy_label = JLabel()
            fm = dummy_label.getFontMetrics(dummy_label.getFont())
            new_node.width = max(90, fm.stringWidth(new_node.text) + 24)
            new_node.custom_color = Color(0, 127, 255, 51)

            target_root.children.append(new_node)
            self.selected_nodes = {new_node}

            if self.activeRoot != target_root:
                for i in range(self.tabbed_pane.getTabCount()):
                    panel = self.tabbed_pane.getComponentAt(i)
                    if panel.getClientProperty("target_root") == target_root:
                        self.tabbed_pane.setSelectedIndex(i)
                        break

            self.auto_arrange(None)
        finally:
            SwingUtilities.invokeLater(lambda: setattr(self, 'is_prompting', False))

    def serialize_req_res(self, reqRes):
        req_b64 = ""
        res_b64 = ""
        svc_data = None
        req = reqRes.getRequest()
        if req: req_b64 = self.helpers.bytesToString(self.helpers.base64Encode(req))
        res = reqRes.getResponse()
        if res: res_b64 = self.helpers.bytesToString(self.helpers.base64Encode(res))
        svc = reqRes.getHttpService()
        if svc:
            svc_data = {
                "host": svc.getHost(),
                "port": svc.getPort(),
                "protocol": svc.getProtocol()
            }
        return req_b64, res_b64, svc_data

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest: return

        if self.is_recording_feature and toolFlag == self.callbacks.TOOL_PROXY:
            info = self.helpers.analyzeRequest(messageInfo)
            if info and info.getUrl() and self.callbacks.isInScope(info.getUrl()):
                req_b64, res_b64, svc_data = self.serialize_req_res(messageInfo)
                self.recorded_reqs.append({
                    "id": str(uuid.uuid4()),
                    "method": info.getMethod(),
                    "url": unicode(info.getUrl()),
                    "notes": "",
                    "privilege": "",
                    "req_b64": req_b64,
                    "res_b64": res_b64,
                    "svc_data": svc_data
                })
                if hasattr(self, 'features_reqs_model') and self.features_reqs_model.current_feature is None:
                    SwingUtilities.invokeLater(lambda: self.update_features_detail_table())

        if toolFlag not in [self.callbacks.TOOL_PROXY, self.callbacks.TOOL_REPEATER]: return
        if not hasattr(self, 'live_sync_cb') or not self.live_sync_cb.isSelected(): return

        # Snapshot right here, synchronously, on Burp's own calling thread -
        # not inside the deferred lambda below. messageInfo can be a live,
        # mutable object (e.g. a reused Proxy connection buffer or a
        # Repeater tab); if several messages arrive in a burst (a page load
        # pulling in many static assets at once) the invokeLater queue can
        # back up, and by the time a queued call actually runs, Burp may
        # have already repurposed this same object for a later message -
        # pairing this node with someone else's response. Snapshotting now,
        # while messageInfo is still guaranteed to be this exact message,
        # avoids that race entirely.
        saved_req_res = self.callbacks.saveBuffersToTempFiles(messageInfo)
        SwingUtilities.invokeLater(lambda: self.process_live_request(saved_req_res, toolFlag))

    def process_live_request(self, reqRes, toolFlag, bypass_live_sync_check=False):
        # Snapshot reqRes to temp files immediately, before touching it any
        # other way, and do all further analysis from this frozen copy.
        # reqRes itself can be a live, mutable Burp object - a Repeater tab
        # is reused/updated in place across resends, and a proxy history
        # entry can be mutated afterwards (e.g. by a session-handling rule
        # that auto-retries on a redirect/invalid-session response). Reading
        # it again later in this function (as this code used to, for the
        # custom-mapping text and for the saved artifact) could pick up a
        # different response than the one actually classified below, so the
        # node's status badge and its stored/displayed request-response
        # pair could end up mismatched.
        saved_req_res = self.callbacks.saveBuffersToTempFiles(reqRes)
        request_bytes = saved_req_res.getRequest()

        info = self.helpers.analyzeRequest(saved_req_res)
        if not info or not info.getUrl(): return

        # saveBuffersToTempFiles() can occasionally hand back a persisted
        # snapshot whose response hasn't actually finished being written to
        # its backing temp file yet - getResponse() then comes back empty
        # even though reqRes (the object just snapshotted from) already has
        # it. This shows up mostly under load_scope_and_history(), which
        # snapshots a whole batch of history entries back to back. Fall
        # back to reading straight off the original object before giving up.
        response = saved_req_res.getResponse() or reqRes.getResponse()
        if not response or len(response) == 0: return
        if not request_bytes:
            request_bytes = reqRes.getRequest()

        resp_info = self.helpers.analyzeResponse(response)
        status_code = resp_info.getStatusCode()

        if status_code in self.get_hidden_statuses(): return 

        url_obj = info.getUrl()
        url_str_full = unicode(url_obj)

        if not bypass_live_sync_check:
            if url_str_full in self.live_processed_urls and toolFlag != self.callbacks.TOOL_REPEATER: return
            self.live_processed_urls.add(url_str_full)

        matched_target = url_obj.getHost()

        if matched_target not in self.target_roots:
            if self.callbacks.isInScope(url_obj):
                self.add_target_tab(matched_target)
            else:
                return 

        targetRoot = self.target_roots[matched_target]
        cl = self.get_content_length(response)
        method = info.getMethod()

        params = set()
        for p in info.getParameters():
            if p.getType() == 0: 
                params.add(p.getName())

        path = url_obj.getPath()
        current_node = targetRoot
        is_new_data = False

        path = url_obj.getPath()
        current_node = targetRoot
        is_new_data = False

        # Helper to identify if a segment is an ID (numeric or UUID)
        if path and path != "/":
            parts = path.split("/")
            for part in parts:
                if not part: continue
                    
                next_node = current_node.find_child(part)
                if next_node is None:
                    # Prevent forged paths in Repeater from creating new junk nodes
                    if toolFlag == self.callbacks.TOOL_REPEATER:
                        return 
                        
                    next_node = MindMapNode(part, parent=current_node)
                    current_node.children.append(next_node)
                    is_new_data = True
                current_node = next_node

        applicable_rules = [r for r in self.custom_mappings if r.get("host") in (matched_target.lower(), "*")]
        if applicable_rules:
            raw_text = None
            try:
                raw_text = self.helpers.bytesToString(request_bytes)
            except Exception:
                raw_text = None

            if raw_text:
                for rule in applicable_rules:
                    value = self.extract_custom_mapping_value(rule, raw_text)
                    if not value: continue
                    label = u"[{0}] {1}".format(rule.get("name") or "Match", value)
                    next_node = current_node.find_child(label)
                    if next_node is None:
                        next_node = MindMapNode(label, parent=current_node)
                        next_node.is_custom_mapping = True
                        current_node.children.append(next_node)
                        is_new_data = True
                    current_node = next_node

        before_m = len(current_node.methods)
        current_node.methods.add(method)
        if len(current_node.methods) > before_m: is_new_data = True

        if status_code:
            before_s = len(current_node.statuses)
            current_node.statuses.add(status_code)
            if len(current_node.statuses) > before_s: is_new_data = True

        if cl is not None:
            before_cl = len(current_node.content_lengths)
            current_node.content_lengths.add(cl)
            if len(current_node.content_lengths) > before_cl: is_new_data = True

        before_p = len(current_node.params)
        current_node.params.update(params)
        if len(current_node.params) > before_p: is_new_data = True

        # Store a plain, immutable wrapper around the bytes already
        # validated above rather than saved_req_res itself - this node may
        # not get clicked (and its getRequest()/getResponse() actually
        # called) until long after this function returns, and it should
        # never be possible for that later read to come back different
        # from what was just validated here.
        stable_req_res = RestoredReqRes(request_bytes, response, saved_req_res.getHttpService() or reqRes.getHttpService())
        current_node.method_requests[method] = stable_req_res
        current_node.linked_request = stable_req_res

        if toolFlag == self.callbacks.TOOL_REPEATER:
            if current_node.status != "Tested":
                current_node.status = "Tested"
                is_new_data = True

        if is_new_data and targetRoot == self.activeRoot:
            self.auto_arrange(None)

    def load_scope_and_history(self):
        all_requests = list(self.callbacks.getProxyHistory()) + list(self.callbacks.getSiteMap(None))
        for reqRes in all_requests:
            try:
                if not reqRes.getResponse(): continue
                info = self.helpers.analyzeRequest(reqRes)
                if not info: continue
                url_obj = info.getUrl()
                if self.callbacks.isInScope(url_obj):
                    self.process_live_request(reqRes, self.callbacks.TOOL_PROXY, bypass_live_sync_check=True)
            except Exception as e:
                # One malformed/unusual entry must not silently abort every
                # remaining request in the batch - without this, a single
                # exception here would stop the for-loop entirely, leaving
                # every request after the failing one (alphabetically or by
                # history order, e.g. robots.txt sorting before other
                # assets) never processed for this run.
                try:
                    bad_url = unicode(self.helpers.analyzeRequest(reqRes).getUrl())
                except Exception:
                    bad_url = "<unknown URL>"
                self.callbacks.printError(u"load_scope_and_history: failed on {0}: {1}".format(bad_url, e))

    def rebuild_map_from_history(self):
        self.target_roots = {}
        self.tabbed_pane.removeAll()
        self.activeRoot = None
        self.load_scope_and_history()
