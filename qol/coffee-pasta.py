# -*- coding: utf-8 -*-
#
# Burp Suite extension (Jython 2.7)
# Right-click a request -> copy Host / Path / Params to the clipboard,
# formatted for pasting straight into Excel.
#
# Works on GET, POST (urlencoded, multipart, JSON, XML) and anything else
# Burp's parser understands. Falls back to the raw body if no params parse.

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList

import traceback

# ---------------------------------------------------------------- settings --
INCLUDE_COOKIES = False       # set True to include cookie params
INCLUDE_HEADER_ROW = False     # emit a header line
PARAM_SEPARATOR = "; "        # how params are joined inside one cell
# ---------------------------------------------------------------------------

PARAM_TYPES = {
    0: "URL",
    1: "BODY",
    2: "COOKIE",
    3: "XML",
    4: "XML_ATTR",
    5: "MULTIPART_ATTR",
    6: "JSON",
}


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Copy Host / Path / Params")
        callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()
        print("[+] Copy Host / Path / Params loaded")

    # ------------------------------------------------------------- menu ----
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return None

        menu = ArrayList()
        menu.add(JMenuItem(
            "Copy host/path/params (TSV - paste into Excel)",
            actionPerformed=lambda e, m=messages: self.copy_rows(m, "\t")))
        menu.add(JMenuItem(
            "Copy host/path/params (CSV)",
            actionPerformed=lambda e, m=messages: self.copy_rows(m, ",")))
        menu.add(JMenuItem(
            "Copy expanded - one row per param (TSV)",
            actionPerformed=lambda e, m=messages: self.copy_expanded(m, "\t")))
        return menu

    # ------------------------------------------------------------ actions --
    def copy_rows(self, messages, delim):
        try:
            out = []
            if INCLUDE_HEADER_ROW:
                out.append(delim.join(["Host", "Path", "Params"]))
            for msg in messages:
                host, path, params = self.parse(msg)
                cell = PARAM_SEPARATOR.join(
                    ["%s=%s" % (n, v) for (n, v, t) in params])
                out.append(delim.join([
                    esc(host, delim), esc(path, delim), esc(cell, delim)]))
            self.to_clipboard("\n".join(out))
            print("[+] copied %d request(s)" % len(messages))
        except Exception:
            print(traceback.format_exc())

    def copy_expanded(self, messages, delim):
        try:
            out = []
            if INCLUDE_HEADER_ROW:
                out.append(delim.join(
                    ["Host", "Path", "Param", "Value", "Type"]))
            for msg in messages:
                host, path, params = self.parse(msg)
                if not params:
                    out.append(delim.join([
                        esc(host, delim), esc(path, delim), "", "", ""]))
                    continue
                for (name, value, ptype) in params:
                    out.append(delim.join([
                        esc(host, delim), esc(path, delim),
                        esc(name, delim), esc(value, delim), ptype]))
            self.to_clipboard("\n".join(out))
            print("[+] copied %d request(s), expanded" % len(messages))
        except Exception:
            print(traceback.format_exc())

    # ------------------------------------------------------------ parsing --
    def parse(self, msg):
        """Return (host, path, [(name, value, type), ...])."""
        request = msg.getRequest()
        if request is None:
            svc = msg.getHttpService()
            return (svc.getHost() if svc else "", "", [])

        info = self._helpers.analyzeRequest(msg)
        url = info.getUrl()

        if url is not None:
            host = url.getHost()
            path = url.getPath()
        else:
            svc = msg.getHttpService()
            host = svc.getHost() if svc else ""
            path = ""

        params = []
        for p in info.getParameters():
            ptype = p.getType()
            if ptype == 2 and not INCLUDE_COOKIES:
                continue
            params.append((
                p.getName(),
                p.getValue(),
                PARAM_TYPES.get(ptype, str(ptype)),
            ))

        # Fallback: body present but Burp parsed nothing (raw JSON blob,
        # GraphQL, protobuf-ish, custom content types...)
        if not params:
            body_off = info.getBodyOffset()
            body = self._helpers.bytesToString(request[body_off:]).strip()
            if body:
                params.append(("<raw_body>", body, "RAW"))

        return (host, path, params)

    # ---------------------------------------------------------- clipboard --
    def to_clipboard(self, text):
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            StringSelection(text), None)


# ------------------------------------------------------------------ utils --
def esc(value, delim):
    """Quote a field so Excel/CSV readers keep it in one cell."""
    if value is None:
        return ""
    value = unicode(value)
    # collapse newlines so a single request stays on a single row
    value = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    if delim == "\t":
        return value.replace("\t", " ")
    if any(c in value for c in [delim, '"']):
        return '"%s"' % value.replace('"', '""')
    return value
              
