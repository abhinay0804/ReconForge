import socket
import ssl


def grab_banner(target, port):
    try:
        if port == 443:
            context = ssl.create_default_context()
            sock = socket.create_connection((target, port), timeout=3)
            ssl_sock = context.wrap_socket(sock, server_hostname=target)

            tls_version = ssl_sock.version()
            cipher = ssl_sock.cipher()

            cert = ssl_sock.getpeercert()

            ssl_sock.send(
                b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
            )

            data = ssl_sock.recv(4096).decode(errors="ignore")
            ssl_sock.close()

            headers = data.split("\r\n\r\n")[0]

            cn = None
            if cert:
                for item in cert.get("subject", []):
                    for key, value in item:
                        if key == "commonName":
                            cn = value

            banner = ""
            if cn:
                banner += f"[TLS CN: {cn}]\n"
            if tls_version:
                banner += f"[TLS Version: {tls_version}]\n"
            if cipher:
                banner += f"[Cipher: {cipher[0]}]\n"

            banner += headers.strip()

            return banner

        # ---------- HTTP ----------
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))

        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")

        data = sock.recv(2048).decode(errors="ignore")
        sock.close()

        if port == 80:
            return data.split("\r\n\r\n")[0].strip()

        return data.strip()

    except:
        return ""

