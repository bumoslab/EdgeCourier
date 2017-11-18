﻿'''
------------------------------------------------------------------------------
 Copyright (c) 2015 Microsoft Corporation

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
------------------------------------------------------------------------------
'''
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from SimpleHTTPServer import SimpleHTTPRequestHandler as BaseHTTPRequestHandler
    from SocketServer import TCPServer as HTTPServer

try:
    from urllib.parse import urlparse, parse_qs, unquote
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import unquote

import threading
import webbrowser


def get_auth_token(auth_url, redirect_uri):
    """Easy way to get the auth token. Wraps up all the threading
    and stuff. Does block main thread.

    Args:
        auth_url (str): URL of auth server, including query params
            needed to get access token.
        redirect_uri (str): Redirect URI, as set for the app. Should be 
            something like "http://localhost:8080" for this to work.

    Returns: 
        str: A string representing the auth code, sent back by the server
    """
    url_netloc = urlparse(redirect_uri).netloc
    if ':' not in url_netloc:
        host_address = url_netloc
        port = 80 # default port
    else:
        host_address, port = url_netloc.split(':')
        port = int(port)
    # Set up HTTP server and thread
    token_acquired = threading.Event()
    s = GetAccessTokenServer((host_address, port), token_acquired, GetAccessTokenRequestHandler)
    th = threading.Thread(target=s.serve_forever)
    th.start()
    webbrowser.open(auth_url)
    # At this point the browser will open and the code
    # will be extracted by the server
    token_acquired.wait()  # First wait for the response from the auth server
    auth_token = s.authentication_token
    s.shutdown()
    th.join()
    return auth_token


class GetAccessTokenServer(HTTPServer, object):

    def __init__(self, server_address, stop_event, RequestHandlerClass):
        super(HTTPServer, self).init(server_address, RequestHandlerClass)
        self._stop_event = stop_event
        self._access_token = None
        self._authentication_token = None

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value
        if value is not None:
            self._stop_event.set()

    @property
    def authentication_token(self):
        return self._authentication_token

    @authentication_token.setter
    def authentication_token(self, value):
        self._authentication_token = value
        if value is not None:
            self._stop_event.set()


class GetAccessTokenRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        if "access_token" in params:
            # Extract the access token query param
            self.server.access_token = params["access_token"][0]
        if "authentication_token" in params:
            # Extract the auth token query param
            self.server.authentication_token = params["authentication_token"][0]
        if "error" in params:
            error_msg, error_desc = (unquote(params["error"][0]),
                                     unquote(params["error_description"][0]))
            raise RuntimeError("The server returned an error: {} - {}"
                               .format(error_msg, error_desc))
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(
            '<script type="text/javascript">window.close()</script>'
            .encode("utf-8")))
