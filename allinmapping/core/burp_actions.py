# -*- coding: utf-8 -*-
"""Handing requests to other Burp tools (Repeater, Intruder, Scanner) and the clipboard."""
from javax.swing import JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.net import URL


class BurpActionsMixin(object):
    """Handing requests to other Burp tools (Repeater, Intruder, Scanner) and the clipboard."""

    def build_http_request(self, node):
        url_str = node.get_full_url()
        if not url_str: return None, None, None, None
        try:
            url_obj = URL(url_str)
            host = url_obj.getHost()
            use_https = (url_obj.getProtocol().lower() == "https")
            port = url_obj.getPort()
            if port == -1: port = 443 if use_https else 80
            req = self.helpers.buildHttpRequest(url_obj)
            return host, port, use_https, req
        except Exception as e:
            return None, None, None, None

    def send_to_intruder(self, node):
        if node.linked_request:
            service = node.linked_request.getHttpService()
            self.callbacks.sendToIntruder(service.getHost(), service.getPort(), (service.getProtocol().lower() == "https"), node.linked_request.getRequest())
        else:
            host, port, use_https, req = self.build_http_request(node)
            if req: self.callbacks.sendToIntruder(host, port, use_https, req)

    def send_to_repeater(self, node):
        req_res = None
        if getattr(self, 'selected_method', None):
            req_res = node.method_requests.get(self.selected_method)
        
        if not req_res:
            req_res = node.linked_request

        if req_res:
            service = req_res.getHttpService()
            self.callbacks.sendToRepeater(
                service.getHost(), service.getPort(), (service.getProtocol().lower() == "https"),
                req_res.getRequest(), node.text
            )
        else:
            host, port, use_https, req = self.build_http_request(node)
            if req: self.callbacks.sendToRepeater(host, port, use_https, req, node.text)

    def send_feature_req_to_repeater(self, req_data, tab_name=None):
        req_b64 = req_data.get("req_b64")
        svc_data = req_data.get("svc_data")
        if not req_b64 or not svc_data: return
        
        req = self.helpers.base64Decode(req_b64)
        name = tab_name if tab_name else req_data.get("url", "Feature Req")
        
        self.callbacks.sendToRepeater(
            svc_data["host"], svc_data["port"], (svc_data["protocol"].lower() == "https"),
            req, name
        )

    def send_feature_to_repeater(self, feature):
        for idx, req_data in enumerate(feature.get("requests", [])):
            tab_name = "{} - {}".format(feature["name"], idx + 1)
            self.send_feature_req_to_repeater(req_data, tab_name)

    def do_active_scan(self, node):
        host, port, use_https, req = self.build_http_request(node)
        if req:
            self.callbacks.doActiveScan(host, port, use_https, req)
            JOptionPane.showMessageDialog(self.mainPanel, "Sent to Active Scanner!")

    def copy_node_url(self, target_node):
        nodes = self.selected_nodes if target_node in self.selected_nodes else [target_node]
        urls = [n.get_full_url() for n in nodes if n.get_full_url()]
        if urls:
            selection = StringSelection("\n".join(urls))
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)
