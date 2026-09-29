# -*- coding: utf-8 -*-
"""Plain data objects: the map node tree and restored Burp request/response wrappers."""
from burp import IHttpService, IMessageEditorController
import uuid


class RestoredHttpService(IHttpService):
    # Explicitly implements IHttpService (rather than just duck-typing it)
    # because instances of this class can be returned from
    # IMessageEditorController.getHttpService(), whose declared Java return
    # type is IHttpService - an object that only duck-types the same method
    # names is not guaranteed to satisfy that at the Java call boundary.
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol
    def getHost(self): return self._host
    def getPort(self): return self._port
    def getProtocol(self): return self._protocol


class RestoredReqRes:
    def __init__(self, req, res, svc):
        self.req = req
        self.res = res
        self.svc = svc
    def getRequest(self): return self.req
    def getResponse(self): return self.res
    def getHttpService(self): return self.svc


class SimpleMessageEditorController(IMessageEditorController):
    # A standalone IMessageEditor created with controller=None has been
    # observed failing to render certain responses in Burp's own editor
    # component (confirmed correct, unmodified bytes; Burp's native Proxy
    # History viewer displays the same bytes fine, so it's specific to
    # editors created without a controller). Burp's docs call for a real
    # controller rather than None - this is the minimal implementation.
    def __init__(self, http_service, request_bytes, response_bytes):
        self.http_service = http_service
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes
    def getHttpService(self): return self.http_service
    def getRequest(self): return self.request_bytes
    def getResponse(self): return self.response_bytes


class MindMapNode:
    def __init__(self, text, parent=None):
        self.id = str(uuid.uuid4())
        self.text = text
        self.children = []
        self.parent = parent  
        self.x = 0
        self.y = 0
        self.width = 0
        self.height = 44  
        self.subtree_height = 0
        self.subtree_width = 0

        self.methods = set()
        self.method_requests = {} 
        self.statuses = set()
        self.content_lengths = set()
        self.severity = None 
        self.note = ""
        self.privilege = ""
        self.custom_color = None
        self.status = "" 
        self.params = set()
        self.collapsed = False 

        self.is_playbook_node = False
        self.is_custom_mapping = False
        self.is_manual = False
        self.manual_resize = False 
        self.linked_request = None 
        self.custom_cols = {}

    def find_child(self, text):
        for child in self.children:
            if child.text == text:
                return child
        return None

    def get_full_url(self):
        parts = []
        current = self

        while current is not None:
            if current.text:
                parts.insert(0, current.text)
            current = current.parent

        if not parts: return ""

        base = parts[0]
        if not base.startswith("http"):
            base = "https://" + base

        if len(parts) > 1:
            path = "/".join(parts[1:])
            path = "/".join(filter(None, path.split("/"))) 
            if base.endswith("/"): base = base[:-1]
            return base + "/" + path

        return base
