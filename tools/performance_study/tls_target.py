"""Concurrent local TLS origin for handshake-target fixtures."""
import argparse
import socketserver
import ssl


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request,server_side=True) as session:
                print(session.version(),session.cipher()[0],session.session_reused,flush=True)
                session.settimeout(12)
                session.recv(1024)
        except (TimeoutError, OSError):
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("port",type=int)
    p.add_argument("cert")
    p.add_argument("key")
    p.add_argument("mode",choices=["tls12","tls13","tls13-no-tickets"])
    a=p.parse_args()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    version=ssl.TLSVersion.TLSv1_2 if a.mode=="tls12" else ssl.TLSVersion.TLSv1_3
    context.minimum_version=context.maximum_version=version
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(a.cert,a.key)
    if a.mode=="tls13-no-tickets":
        context.num_tickets=0
    with Server(("127.0.0.1",a.port),Handler) as listener:
        listener.context=context
        print("listening",flush=True)
        listener.serve_forever()
