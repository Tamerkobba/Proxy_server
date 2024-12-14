import sys
import time
import datetime
import socket
import threading
import os
import select

class ProxyServer:

    DEFAULT_TTL = 60  # time-to-live in seconds if no max-age is found

    def __init__(self, blocked_sites=None, allowed_sites=None):
        self.blocked_sites = blocked_sites if blocked_sites else []
        self.allowed_sites = allowed_sites if allowed_sites else []
        self.log_file_path = "log/log.txt"
        if not os.path.exists("log"):
            os.makedirs("log")
        if not os.path.exists("cache"):
            os.makedirs("cache")

    def log_message(self, message):
        """Opens the file specified by self.log_file_path in append mode (a+), ensuring that
        each message is added to the end of the file without overwriting existing logs."""

        timestamped_message = self.current_timestamp() + " " + message
        # Write to log file
        with open(self.log_file_path, "a+", encoding="utf-8") as f:
            f.write(timestamped_message + "\n")
        # Also print to console
        print(timestamped_message)

    def current_timestamp(self):
        return "[" + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + "]"

    def start(self, max_connections=5, buffer_size=4096, listen_port=8080):
        """max_connections: Maximum number of clients that can connect simultaneously.
           buffer_size: The size (in bytes) of the data chunks the server reads/writes.
           listen_port: The port number the server listens on (default is 8080)."""

        self.log_message("\n\nStarting the Proxy Server\n")
        try:
            self.listen_for_clients(max_connections, buffer_size, listen_port)
        except KeyboardInterrupt:
            print(self.current_timestamp(), "Server interrupted by user.")
            self.log_message("Server interrupted by user.")
            time.sleep(0.5)
        finally:
            print(self.current_timestamp(), "Shutting down the server...")
            self.log_message("Shutting down the server.")

            # Print the entire log file contents
            self.print_log_file()

            sys.exit()

    def print_log_file(self):
        # Read and print out the entire log file
        if os.path.exists(self.log_file_path):
            print("\n--- Full Log File Contents ---")
            with open(self.log_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    print(line.strip())
            print("--- End of Log File ---\n")

    def listen_for_clients(self, max_conn, buffer_size, port):
        """AF_INET: Specifies IPv4 addressing
           SOCK_STREAM: Indicates TCP protocol.
        """
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(('', port))
            listener.listen(max_conn)
            self.log_message(f"Proxy is now listening on port {port}")
            self.log_message("Initialized socket and listening on port " + str(port))
        except Exception as err:
            self.log_message("Error: Unable to start listening - " + str(err))
            sys.exit(1)

        while True:
            try:
                client_conn, client_addr = listener.accept()
                self.log_message("Received connection from " + client_addr[0] + ":" + str(client_addr[1]))
                client_thread = threading.Thread(target=self.handle_client_request, args=(client_conn, client_addr, buffer_size))
                client_thread.daemon = True
                client_thread.start()
            except Exception as err:
                self.log_message("Error: Could not accept connection - " + str(err))
                sys.exit(1)

    def handle_client_request(self, connection, address, buff_size):
        try:
            method, url, headers = self.parse_http_request(connection, buff_size)
            if method is None or url is None:
                # Malformed request
                self.send_error_response(connection, 400, "Bad Request")
                connection.close()
                return

            webserver, port, requested_file = self.parse_host_port_from_url(url)
            if not webserver:
                self.send_error_response(connection, 400, "Bad Request")
                connection.close()
                return

            # Check domain-based filters (with revised logic)
            if not self.is_allowed_website(webserver):
                self.log_message("Target domain not whitelisted: " + webserver.decode('utf-8', errors='ignore'))
                self.send_error_response(connection, 403, "Forbidden")
                connection.close()
                return

            if self.is_blocked_website(webserver):
                self.log_message("Blocked website: " + webserver.decode('utf-8', errors='ignore'))
                self.send_error_response(connection, 403, "Forbidden")
                connection.close()
                return

            # Distinguish between HTTPS and other HTTP methods
            if method.upper() == "CONNECT":
                # HTTPS tunnel
                self.log_message("HTTPS request detected (CONNECT)")
                print(self.current_timestamp(), "Handling HTTPS request...")
                self.handle_https(webserver, port, connection, buff_size, requested_file)
            else:
                # Modify headers: set Host, remove Proxy-Connection, set Connection
                host_str = webserver.decode('utf-8', errors='ignore')
                headers['host'] = host_str
                if 'proxy-connection' in headers:
                    del headers['proxy-connection']
                headers['connection'] = 'close'

                self.log_message(f"HTTP request detected: {method.upper()} {url}")
                print(self.current_timestamp(), "Handling HTTP request...")
                self.handle_http(webserver, port, connection, method, url, headers, address, buff_size, requested_file)
        except Exception as err:
            self.log_message("Error while reading client request: " + str(err))
            self.send_error_response(connection, 500, "Internal Server Error")
            connection.close()

    def parse_http_request(self, connection, buff_size):
        """This function is responsible for parsing an HTTP request from a network connection
         and extracting key components like the HTTP method, URL, and headers"""
        data = b''
        connection.settimeout(3)
        try:
            while b'\r\n\r\n' not in data:
                chunk = connection.recv(buff_size)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            return None, None, None

        parts = data.split(b'\r\n\r\n', 1)
        if len(parts) < 2:# if parts has less than two elements, the function returns (None, None, None) as the request is malformed
            return None, None, None
        header_data = parts[0].split(b'\r\n')
        if len(header_data) == 0:
            return None, None, None
        #The first line contains the HTTP method, URL, and version.
        request_line = header_data[0].decode('utf-8', errors='replace')
        segments = request_line.split(' ')
        if len(segments) < 3:#If it's malformed, returns None.
            return None, None, None
        method, url, version = segments[0], segments[1], segments[2]

        if not method or not url or not version:
            return None, None, None

        headers_lines = header_data[1:]
        headers = {}
        for line in headers_lines:
            line_str = line.decode('utf-8', errors='replace')
            if ':' in line_str:
                key, val = line_str.split(':', 1)
                headers[key.strip().lower()] = val.strip()

        return method, url, headers

    def parse_host_port_from_url(self, url):
        """This function extracts the host, port,
         and sanitized version of the requested file from a URL"""
        protocol_index = url.find("://")
        if protocol_index == -1:
            temp_url = url
        else:
            temp_url = url[protocol_index + 3:]

        temp_url = temp_url.strip('/')

        port = 80
        webserver = ''
        requested_file = url.encode('utf-8', errors='ignore')

        if ':' in temp_url:
            parts = temp_url.split(':', 1)
            host_part = parts[0]
            if '/' in parts[1]:
                port_str, _ = parts[1].split('/', 1)
                port = int(port_str)
            else:
                port = int(parts[1])
            webserver = host_part.encode('utf-8', errors='ignore')
        else:
            if '/' in temp_url:
                host_part, _ = temp_url.split('/', 1)
                webserver = host_part.encode('utf-8', errors='ignore')
            else:
                webserver = temp_url.encode('utf-8', errors='ignore')

        requested_file = requested_file.replace(b"http://", b"").replace(b"https://", b"").replace(b"/", b"_").replace(b".", b"_")
        return webserver, port, requested_file

    def is_blocked_website(self, webserver):
        try:
            clean_ws = webserver.replace(b"http://", b"").replace(b"https://", b"")
            domain_parts = clean_ws.split(b".")
            if len(domain_parts) > 1:
                domain = domain_parts[-2].decode('utf-8', errors='ignore')
            else:
                domain = domain_parts[0].decode('utf-8', errors='ignore')
            if domain in self.blocked_sites:
                return True
        except:
            pass
        return False

    def is_allowed_website(self, webserver):
        if len(self.allowed_sites) > 0:
            try:
                clean_ws = webserver.replace(b"http://", b"").replace(b"https://", b"")
                domain_parts = clean_ws.split(b".")
                if len(domain_parts) > 1:
                    domain = domain_parts[-2].decode('utf-8', errors='ignore')
                else:
                    domain = domain_parts[0].decode('utf-8', errors='ignore')
                return domain in self.allowed_sites
            except:
                return False
        return True

    def handle_http(self, webserver, port, conn, method, url, headers, client_addr, buffer_size, requested_file):
        cache_path = os.path.join("cache", requested_file.decode('utf-8', errors='ignore'))
        meta_path = cache_path + ".meta"

        if os.path.exists(cache_path) and os.path.exists(meta_path):
            self.log_message("Cache file found for " + requested_file.decode('utf-8', errors='ignore'))
            if self.is_cache_fresh(meta_path):
                self.log_message("Cache hit for " + requested_file.decode('utf-8', errors='ignore'))
                with open(cache_path, "rb") as cached_file:
                    cached_data = cached_file.read()
                conn.sendall(cached_data)
                conn.close()
                return
            else:
                self.log_message("Cache stale for " + requested_file.decode('utf-8', errors='ignore'))
                os.remove(cache_path)
                os.remove(meta_path)

        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((webserver, port))

            req_line = f"{method} {url} HTTP/1.1\r\n"
            forward_headers = ""
            for k, v in headers.items():
                forward_headers += f"{k}: {v}\r\n"
            forward_headers += "\r\n"

            remote_socket.sendall(req_line.encode('utf-8') + forward_headers.encode('utf-8'))

            remote_socket.settimeout(5)
            response_chunks = []
            while True:
                try:
                    data = remote_socket.recv(buffer_size)
                    if not data:
                        break
                    conn.sendall(data)
                    response_chunks.append(data)
                except socket.timeout:
                    break

            response_data = b''.join(response_chunks)
            self.cache_response(cache_path, meta_path, response_data)

            remote_socket.close()
            conn.close()
            self.log_message("Completed request for client " + client_addr[0])
        except Exception as err:
            self.log_message("Error forwarding HTTP request: " + str(err))
            self.send_error_response(conn, 502, "Bad Gateway")
            conn.close()

    def cache_response(self, cache_path, meta_path, response_data):
        with open(cache_path, "wb") as cached_file:
            cached_file.write(response_data)

        expiration_time = time.time() + self.DEFAULT_TTL
        headers_end = response_data.find(b"\r\n\r\n")
        if headers_end != -1:
            header_block = response_data[:headers_end].decode('utf-8', errors='ignore').lower()
            if "cache-control:" in header_block:
                for line in header_block.split("\r\n"):
                    if "cache-control:" in line and "max-age=" in line:
                        parts = line.split("max-age=", 1)
                        if len(parts) > 1:
                            val = parts[1].split(',', 1)[0].strip()
                            if val.isdigit():
                                expiration_time = time.time() + int(val)
                                break

        with open(meta_path, "w", encoding="utf-8") as meta_file:
            meta_file.write(str(expiration_time))

    def is_cache_fresh(self, meta_path):
        with open(meta_path, "r", encoding="utf-8") as meta_file:
            expiration_str = meta_file.read().strip()

        try:
            expiration_time = float(expiration_str)
            return time.time() < expiration_time
        except ValueError:
            return False

    def handle_https(self, webserver, port, client_conn, buffer_size, requested_file):
        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((webserver, port))
            reply = "HTTP/1.0 200 Connection established\r\nProxy-agent: Proxy\r\n\r\n"
            client_conn.sendall(reply.encode("utf-8"))

            client_conn.setblocking(False)
            remote_socket.setblocking(False)

            self.log_message("HTTPS tunnel established with " + webserver.decode('utf-8', errors='ignore'))

            while True:
                read_sockets, _, error_sockets = select.select([client_conn, remote_socket], [], [client_conn, remote_socket], 5)
                if error_sockets:
                    break

                if not read_sockets:
                    pass

                if client_conn in read_sockets:
                    try:
                        data_from_client = client_conn.recv(buffer_size)
                        if data_from_client:
                            remote_socket.sendall(data_from_client)
                        else:
                            break
                    except:
                        pass

                if remote_socket in read_sockets:
                    try:
                        data_from_server = remote_socket.recv(buffer_size)
                        if data_from_server:
                            client_conn.sendall(data_from_server)
                        else:
                            break
                    except:
                        pass

            remote_socket.close()
            client_conn.close()
        except Exception as err:
            self.log_message("Error in HTTPS tunneling: " + str(err))
            self.send_error_response(client_conn, 502, "Bad Gateway")
            client_conn.close()

    def send_error_response(self, conn, code, message):
        response = f"HTTP/1.1 {code} {message}\r\nServer: Proxy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            conn.sendall(response.encode('utf-8'))
        except:
            pass

if __name__ == "__main__":
    blocked_sites = []
    allowed_sites = []

    proxy = ProxyServer(blocked_sites=blocked_sites, allowed_sites=allowed_sites)
    proxy.start()