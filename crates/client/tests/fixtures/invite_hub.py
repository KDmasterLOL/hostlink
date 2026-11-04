import http.server, json, ssl, sys
root, cert, key = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def handle_request(self):
        with open(root + '/requests', 'a') as f: f.write(self.command + ' ' + self.path + '\n')
        if self.headers.get('Authorization') != 'Bearer fixture-operator-token':
            self.send_error(401); return
        if self.command == 'GET' and self.path == '/v2/info':
            with open(root + '/info.json') as f: body = json.load(f)
        elif self.command == 'POST' and self.path == '/v2/invites':
            self.rfile.read(int(self.headers['Content-Length']))
            body = {'token': 'a' * 64, 'expires_at': 4102444800}
        else:
            self.send_error(404); return
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)
    do_GET = handle_request
    do_POST = handle_request
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
