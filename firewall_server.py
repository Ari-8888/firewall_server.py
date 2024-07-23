from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse

host = "localhost"
port = 8000

# Handle the response here
def block_request(self):
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request blocked by firewall"}')

def handle_request(self):
    # Parse the URL and extract query parameters
    length = int(self.headers['Content-Length'])
    post_data = self.rfile.read(length)
    parsed_data = urlparse.parse_qs(post_data.decode('utf-8'))
    
    # Check for malicious patterns in the request data
    if "class.module.classLoader.resources.context.parent.pipeline.first.pattern" in parsed_data:
        block_request(self)
    else:
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message": "Request allowed"}')

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        handle_request(self)

if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
