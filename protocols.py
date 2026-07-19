import socket


def analyze_http(host, port):

    http_info = {}

    # appending or lets say HTTP headers.

    connection = socket.create_connection((host, port))

    request = f"HEAD / HTTP/1.1\r\n" f"Host: {host}\r\n" "Connection: close\r\n" "\r\n"

    connection.sendall(request.encode())
    response = connection.recv(4096)

    rs = response.decode()

    for line in rs.splitlines():
        if line.startswith("Server"):
            value = line.split(":", 1)[1]

            value = value.strip()

            http_info["server"] = value
        elif line.startswith("Date"):
            value = line.split(":", 1)[1]
            value = value.strip()
            http_info["date"] = value

        elif line.startswith("Content-Type"):
            value = line.split(":", 1)[1]
            value = value.strip()
            http_info["content_type"] = value
        elif line.startswith("HTTP/"):
            parts = line.split()

            http_info["http_version"] = parts[0]
            http_info["status"] = parts[1]
            http_info["status_message"] = parts[2]
    connection.close()

    return http_info
