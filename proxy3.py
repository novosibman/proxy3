#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proxy3 - small intercepting (MITM) HTTP/HTTPS proxy, Python 3 port of proxy2.

Logging:
  default   one INFO line per CONNECT / request and warnings/errors
  --debug   everything: full request/response dumps (print_info), tunnel hex
            dumps + pcap text files, TLS/cert details, tracebacks.
            WARNING: debug output contains cookies, Authorization headers and
            bodies in clear text.
"""
import argparse
import base64
import gzip
import html
import io
import ipaddress
import itertools
import json
import logging
import os
import re
import secrets
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ET
import zlib
import http.client as httplib
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit, parse_qsl

log = logging.getLogger('proxy3')

HOSTNAME_RE = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$')
SUPPORTED_ENCODINGS = ('identity', 'gzip', 'x-gzip', 'deflate')
HOP_BY_HOP = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
              'proxy-connection', 'te', 'trailer', 'trailers', 'transfer-encoding', 'upgrade')
CA_URLS = ('http://proxy2.test/', 'http://proxy3.test/')
CERT_DAYS = 365
MAX_REQUEST_BODY = 256 * 1024 * 1024
SNIFF_TIMEOUT = 3  # seconds to wait for the first client bytes after CONNECT


def with_color(c, s):
    if not sys.stderr.isatty():
        return s
    return "\x1b[%dm%s\x1b[0m" % (c, s)


def set_header(headers, name, value):
    """Replace a header. email.message.Message.__setitem__ appends, so delete first."""
    del headers[name]
    headers[name] = value


def wait_readable(sock, timeout):
    with selectors.DefaultSelector() as sel:
        sel.register(sock, selectors.EVENT_READ)
        return bool(sel.select(timeout))


def safe_url(url):
    """URL without query string / fragment (queries often carry tokens)."""
    u = urlsplit(url)
    s = u._replace(query='', fragment='').geturl()
    return s + '?...' if u.query else s


class ProxyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class SocketWriter(io.BufferedIOBase):
    """Unbuffered writer that always sends everything (sendall)."""

    def __init__(self, sock):
        super().__init__()
        self._sock = sock

    def writable(self):
        return True

    def write(self, b):
        self._sock.sendall(b)
        return len(b)


class ProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, server_address, handler_class):
        if ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(server_address, handler_class)

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is not None and issubclass(cls, OSError):  # includes ssl.SSLError, timeouts, resets
            log.debug('connection error from %s: %s: %s', client_address, cls.__name__, e)
        else:
            log.error('unhandled error from %s:\n%s', client_address,
                      traceback.format_exc())


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 30  # don't want to close the sockets faster than GP keepalive
    lock = threading.Lock()       # certificate generation / context cache
    save_lock = threading.Lock()  # serialises save_handler
    ctx_cache = {}
    relay_warned = False
    tunnel_counter = itertools.count(1)

    # set by test()
    args = None
    debug = False
    upstream_ctx = None

    def __init__(self, *args, **kwargs):
        self.conns = {}      # upstream keep-alive connections, per client connection
        self.address = None  # (host, port) set after CONNECT
        super().__init__(*args, **kwargs)

    def finish(self):
        for conn in list(self.conns.values()):
            try:
                conn.close()
            except Exception:
                pass
        self.conns.clear()
        try:
            super().finish()
        finally:
            if isinstance(self.connection, ssl.SSLSocket):
                try:
                    self.connection.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------ logging
    def log_message(self, format, *args):
        try:
            log.debug('%s - %s', self.address_string(), format % args)
        except Exception:
            pass

    def log_error(self, format, *args):
        # suppress "Request timed out: timeout('timed out',)" (idle keep-alive)
        if args and isinstance(args[0], socket.timeout):
            return
        try:
            log.warning('%s - %s', self.address_string(), format % args)
        except Exception:
            pass

    # ------------------------------------------------------------------ CONNECT
    def can_intercept(self):
        return (all(os.path.isfile(p) for p in (self.cakey, self.cacert, self.certkey))
                and os.path.isdir(self.certdir))

    def parse_connect_target(self):
        target = self.path.strip()
        m = re.match(r'^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$', target)
        if m:
            host, port = m.group(1), m.group(2)
        else:
            if target.count(':') > 1:
                raise ValueError('bad CONNECT target')
            host, _, port = target.partition(':')
        port = int(port) if port else 443
        if not 0 < port < 65536:
            raise ValueError('bad port')
        host = host.rstrip('.').lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not HOSTNAME_RE.match(host) or '..' in host:
                raise ValueError('bad host')
        return host, port

    def do_CONNECT(self):
        try:
            host, port = self.parse_connect_target()
        except ValueError as e:
            self.send_error(400, 'Bad CONNECT target', str(e))
            return
        log.info('CONNECT %s:%d', host, port)

        if self.can_intercept():
            self.connect_intercept(host, port)
        else:
            if not type(self).relay_warned:
                type(self).relay_warned = True
                log.warning(with_color(31, 'Relaying proxy traffic rather than intercepting it.\n'
                                           '*** THIS IS PROBABLY NOT WHAT YOU WANT!! ***\n'
                                           'You need to create the CA certificate files to allow this proxy to\n'
                                           'act as a man-in-the-middle (MITM) to intercept and decode HTTPS\n'
                                           'traffic. Run ./setup_https_intercept.sh and restart proxy.'))
            self.open_relay(host, port)

    @staticmethod
    def cert_basename(host):
        try:
            return 'ip-' + str(ipaddress.ip_address(host)).replace(':', '_')
        except ValueError:
            return host

    def generate_cert(self, host, certpath):
        log.info('Generating certificate for %s', host)
        try:
            san = 'IP:%s' % ipaddress.ip_address(host)
        except ValueError:
            san = 'DNS:%s' % host
        ext = ('basicConstraints=CA:FALSE\n'
               'keyUsage=digitalSignature,keyEncipherment\n'
               'extendedKeyUsage=serverAuth\n'
               'subjectAltName=%s\n') % san
        cn = host if len(host) <= 64 else 'proxy3'  # CN is limited to 64 chars, SAN has the real name
        tmp_ext = tmp_cert = None
        try:
            r1 = subprocess.run(['openssl', 'req', '-new', '-key', self.certkey, '-subj', '/CN=%s' % cn],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if r1.returncode != 0:
                raise RuntimeError('openssl req failed: %s' % r1.stderr.decode(errors='replace').strip())
            fd, tmp_ext = tempfile.mkstemp(suffix='.ext', dir=self.certdir)
            with os.fdopen(fd, 'w') as f:
                f.write(ext)
            fd, tmp_cert = tempfile.mkstemp(suffix='.tmp', dir=self.certdir)
            os.close(fd)
            r2 = subprocess.run(['openssl', 'x509', '-req', '-days', str(CERT_DAYS),
                                 '-CA', self.cacert, '-CAkey', self.cakey,
                                 '-set_serial', str(secrets.randbits(63) or 1),
                                 '-extfile', tmp_ext, '-out', tmp_cert],
                                input=r1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if r2.returncode != 0 or os.path.getsize(tmp_cert) == 0:
                raise RuntimeError('openssl x509 failed: %s' % r2.stderr.decode(errors='replace').strip())
            os.replace(tmp_cert, certpath)  # atomic: never leaves a half-written cert behind
            tmp_cert = None
            log.debug('Wrote %s (%s)', certpath, san)
        finally:
            for p in (tmp_ext, tmp_cert):
                if p:
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    def get_server_context(self, host):
        certpath = os.path.join(self.certdir, self.cert_basename(host) + '.crt')
        with self.lock:
            ctx = self.ctx_cache.get(certpath)
            if ctx is not None:
                return ctx
            if not os.path.isfile(certpath) or os.path.getsize(certpath) == 0:
                self.generate_cert(host, certpath)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certpath, self.certkey)
            self.ctx_cache[certpath] = ctx
            return ctx

    def connect_intercept(self, host, port):
        try:
            ctx = self.get_server_context(host)
        except Exception as e:
            log.error('Cannot create certificate for %s: %s', host, e, exc_info=self.debug)
            self.send_error(502, 'Bad Gateway', 'Cannot create certificate for %s' % host)
            return

        self.send_response(200, 'Connection Established')
        self.end_headers()

        # Decide what the client speaks. TLS ClientHello starts with 0x16. Server-first protocols
        # (ssh, smtp, ...) send nothing, so after a short wait we fall back to a plain relay.
        if not wait_readable(self.connection, SNIFF_TIMEOUT):
            log.debug('no client data after CONNECT %s:%d, relaying', host, port)
            self.open_relay(host, port, send_ok=False)
            return
        first = self.connection.recv(1, socket.MSG_PEEK)
        if not first:
            self.close_connection = True
            return
        if first[0] != 0x16:
            if 0x41 <= first[0] <= 0x5a:  # looks like an HTTP method: plain HTTP inside the tunnel
                log.debug('plain HTTP inside CONNECT %s:%d', host, port)
                self.address = (host, port)
                self.close_connection = False
            else:
                log.debug('non-TLS, non-HTTP traffic in CONNECT %s:%d, relaying', host, port)
                self.open_relay(host, port, send_ok=False)
            return

        try:
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log.warning('TLS handshake with client failed for %s: %s (does the client trust %s?)',
                        host, e, self.cacert)
            self.close_connection = True
            return
        log.debug('TLS established with client for %s (%s, %s)', host, tls.version(), tls.cipher()[0])

        self.connection = tls
        self.rfile = tls.makefile('rb', self.rbufsize)
        self.wfile = SocketWriter(tls)
        self.address = (host, port)
        self.close_connection = False

    def open_relay(self, host, port, send_ok=True):
        try:
            s = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as e:
            log.warning('Cannot connect to %s:%d: %s', host, port, e, exc_info=self.debug)
            if send_ok:
                self.send_error(502, 'Bad Gateway', 'Cannot connect to %s:%d: %s' % (host, port, e))
            self.close_connection = True
            return
        try:
            if send_ok:
                self.send_response(200, 'Connection Established')
                self.end_headers()
            self.close_connection = True  # the tunnel owns the socket from now on
            self.relay_loop(self.connection, s)
        except OSError as e:
            log.debug('relay %s:%d ended: %s', host, port, e)
        finally:
            s.close()

    def relay_loop(self, client, upstream, on_data=None):
        """Copy bytes both ways until EOF/error/idle timeout. Uses selectors (no FD_SETSIZE limit)."""
        with selectors.DefaultSelector() as sel:
            sel.register(client, selectors.EVENT_READ, upstream)
            sel.register(upstream, selectors.EVENT_READ, client)
            while True:
                events = sel.select(self.timeout)
                if not events:
                    log.debug('tunnel idle for %ss, closing', self.timeout)
                    return
                for key, _ in events:
                    src, dst = key.fileobj, key.data
                    data = src.recv(65536)
                    if not data:
                        return
                    # TLS sockets can hold decrypted bytes that select() cannot see
                    while isinstance(src, ssl.SSLSocket) and src.pending():
                        data += src.recv(src.pending())
                    dst.sendall(data)
                    if on_data:
                        on_data(src is client, data)

    # ------------------------------------------------------------------ GP tunnel
    def do_TUNNEL(self):
        host, port = self.address
        log.info('Tunnel to %s (%s:%d)', self.path, host, port)
        s = c = None
        try:
            s = socket.create_connection(self.address, timeout=self.timeout)
            c = self.upstream_ctx.wrap_socket(s, server_hostname=host)
        except (OSError, ssl.SSLError) as e:
            if s is not None:
                s.close()
            hint = ' (try --insecure or --cafile for self-signed gateways)' if isinstance(e, ssl.SSLError) else ''
            log.warning('Tunnel upstream %s:%d failed: %s%s', host, port, e, hint, exc_info=self.debug)
            self.send_error(502, 'Bad Gateway', 'Tunnel upstream failed: %s' % e)
            return

        dumpfile = None
        if self.debug:
            name = os.path.join(self.args.dump_dir, 'tunnel-%s-%d.pcap.txt' % (
                time.strftime('%Y%m%d_%H%M%S'), next(self.tunnel_counter)))
            try:
                dumpfile = open(name, 'w')
                log.debug('Dumping to %s', name)
                dumpfile.write('#run this through text2pcap as: text2pcap -t:%%s -Dn %s %s\n' % (name, name[:-4]))
            except OSError as e:
                log.warning('Cannot open dump file %s: %s', name, e)

        def on_data(from_client, data):
            log.debug('%s %s', '>' if from_client else '<', data.hex())
            if dumpfile is None:
                return
            if data.startswith(b'\x1a\x2b\x3c\x4d'):
                # 4 magic (1a2b3c4d), 2 ethertype (0800), 2 inner length, 8 int64le = 1, inner packet
                raweth2 = b'\0' * 12 + data[4:6] + data[16:]
                dumpfile.write('%s:%d\n' % ('O' if from_client else 'I', time.time()))
                dumpfile.write('00000000' + ''.join(' %02x' % b for b in raweth2) + '\n')
            else:
                dumpfile.write('# %r\n' % data)

        self.close_connection = True
        try:
            lines = ['%s %s %s\r\n' % (self.command, self.path, self.request_version)]
            lines += ['%s: %s\r\n' % kv for kv in self.headers.items()]
            lines.append('\r\n')
            c.sendall(''.join(lines).encode('latin-1'))
            log.debug('Conveyed %d headers', len(self.headers))
            self.relay_loop(self.connection, c, on_data if self.debug else None)
        except OSError as e:
            log.debug('tunnel ended: %s', e)
        finally:
            if dumpfile:
                dumpfile.write('# connection closed\n')
                dumpfile.close()
            c.close()

    # ------------------------------------------------------------------ HTTP requests
    def do_GET(self):
        if self.path in CA_URLS:
            self.send_cacert()
            return
        if self.address and self.path.startswith(self.args.tunnel_path):
            self.do_TUNNEL()
            return
        try:
            self.proxy_request()
        except ProxyError as e:
            self.send_error(e.code, e.message)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def build_url(self):
        target = self.path
        if target.startswith('/'):
            if not self.address:
                raise ProxyError(400, 'Not a proxy request (no CONNECT and target is not an absolute URL)')
            scheme = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
            host = self.headers.get('Host')
            if not host:
                h, p = self.address
                if ':' in h:
                    h = '[%s]' % h
                host = h if p == (443 if scheme == 'https' else 80) else '%s:%d' % (h, p)
            return '%s://%s%s' % (scheme, host, target)
        u = urlsplit(target)
        if u.scheme not in ('http', 'https') or not u.netloc:
            raise ProxyError(400, 'Unsupported request target')
        return target

    def read_chunked(self):
        chunks, total = [], 0
        while True:
            line = self.rfile.readline(65537)
            if not line:
                raise ProxyError(400, 'Truncated chunked body')
            try:
                size = int(line.split(b';', 1)[0].strip(), 16)
            except ValueError:
                raise ProxyError(400, 'Bad chunk size')
            if size == 0:
                while self.rfile.readline(65537) not in (b'\r\n', b'\n', b''):  # trailers
                    pass
                break
            total += size
            if total > MAX_REQUEST_BODY:
                raise ProxyError(413, 'Request body too large')
            chunks.append(self.rfile.read(size))
            self.rfile.readline(65537)  # CRLF after chunk
        return b''.join(chunks)

    def read_request_body(self):
        if 'chunked' in (self.headers.get('Transfer-Encoding') or '').lower():
            return self.read_chunked()
        cl = self.headers.get('Content-Length')
        if not cl:
            return None
        try:
            n = int(cl)
        except ValueError:
            raise ProxyError(400, 'Bad Content-Length')
        if n < 0:
            raise ProxyError(400, 'Bad Content-Length')
        if n > MAX_REQUEST_BODY:
            raise ProxyError(413, 'Request body too large')
        return self.rfile.read(n) if n else None

    def get_conn(self, scheme, hostport):
        key = (scheme, hostport)
        conn = self.conns.get(key)
        if conn is None:
            if scheme == 'https':
                conn = httplib.HTTPSConnection(hostport, timeout=self.timeout, context=self.upstream_ctx)
            else:
                conn = httplib.HTTPConnection(hostport, timeout=self.timeout)
            self.conns[key] = conn
        return conn

    def drop_conn(self, key):
        conn = self.conns.pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def proxy_request(self):
        req = self
        url = self.build_url()
        req.path = url
        req_body = self.read_request_body()

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified

        u = urlsplit(url)
        scheme = u.scheme
        hostport = u.netloc.rpartition('@')[2]  # drop any user:pass@
        path = (u.path or '/') + ('?' + u.query if u.query else '')
        set_header(req.headers, 'Host', hostport)
        self.filter_headers(req.headers, request=True)
        if req_body is not None:  # also covers de-chunked bodies (Transfer-Encoding was removed)
            set_header(req.headers, 'Content-Length', str(len(req_body)))

        key = (scheme, hostport)
        res = res_body = None
        try:
            for attempt in (0, 1):
                reused = key in self.conns
                conn = self.get_conn(scheme, hostport)
                try:
                    conn.request(self.command, path, req_body, req.headers)
                    res = conn.getresponse()
                    res_body = res.read()
                    break
                except (httplib.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                    self.drop_conn(key)
                    if attempt == 0 and reused:  # stale keep-alive connection: retry once on a fresh one
                        log.debug('stale upstream connection to %s, retrying', hostport)
                        continue
                    raise
        except Exception as e:
            self.drop_conn(key)
            hint = ' (try --insecure or --cafile)' if isinstance(e, ssl.SSLError) else ''
            log.warning('%s %s failed: %s: %s%s', self.command, safe_url(url), type(e).__name__, e, hint,
                        exc_info=self.debug)
            self.send_error(502, 'Bad Gateway', '%s: %s' % (type(e).__name__, e))
            return

        res_headers = res.headers
        res_version = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}.get(res.version, 'HTTP/1.1')
        setattr(res, 'response_version', res_version)
        bodyless = (self.command == 'HEAD' or res.status in (204, 304) or 100 <= res.status < 200)

        content_encoding = res_headers.get('Content-Encoding', 'identity')
        res_body_plain = b'' if not res_body else None
        if res_body:
            try:
                res_body_plain = self.decode_content_body(res_body, content_encoding)
            except Exception as e:
                log.warning('Cannot decode body (Content-Encoding: %s): %s - passing it through untouched',
                            content_encoding, e)

        if res_body_plain is not None:
            try:
                res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
            except Exception as e:
                log.warning('response_handler failed: %s', e, exc_info=self.debug)
                res_body_modified = None
            if res_body_modified is False:
                self.send_error(403)
                return
            elif res_body_modified is not None:
                res_body_plain = res_body_modified
                res_body = self.encode_content_body(res_body_plain, content_encoding)

        self.filter_headers(res_headers, request=False)
        if not bodyless:
            # Transfer-Encoding was stripped, so the client needs an explicit length (keep-alive!)
            set_header(res_headers, 'Content-Length', str(len(res_body)))

        self.send_response_only(res.status, res.reason or '')
        for k, v in res_headers.items():
            self.send_header(k, v)
        self.end_headers()
        if not bodyless:
            self.wfile.write(res_body)
        self.wfile.flush()

        log.info('%s %s -> %d (%d bytes)', self.command, safe_url(url), res.status, len(res_body))
        try:
            with self.save_lock:
                self.save_handler(req, req_body, res, res_body_plain)
        except Exception as e:
            log.warning('save_handler failed: %s', e, exc_info=self.debug)

    # ------------------------------------------------------------------ headers / encodings
    @staticmethod
    def filter_accept_encoding(ae):
        keep = [p.strip() for p in ae.split(',') if p.split(';')[0].strip().lower() in SUPPORTED_ENCODINGS]
        return ', '.join(keep) or 'identity'

    def filter_headers(self, headers, request=True):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        named = set()
        for v in headers.get_all('Connection', []):
            named.update(t.strip().lower() for t in v.split(',') if t.strip())
        named -= {'content-length', 'host'}
        for k in set(HOP_BY_HOP) | named:
            del headers[k]

        if request:
            del headers['Expect']  # 100-continue was already answered to the client
            ae = headers.get('Accept-Encoding')
            if ae is not None:  # accept only supported encodings
                set_header(headers, 'Accept-Encoding', self.filter_accept_encoding(ae))
        return headers

    @staticmethod
    def parse_encodings(encoding):
        return [e.strip().lower() for e in (encoding or '').split(',') if e.strip()]

    def encode_content_body(self, text, encoding):
        for enc in self.parse_encodings(encoding):  # applied in listed order
            if enc == 'identity':
                pass
            elif enc in ('gzip', 'x-gzip'):
                text = gzip.compress(text)
            elif enc == 'deflate':
                text = zlib.compress(text)
            else:
                raise ValueError("Unknown Content-Encoding: %s" % enc)
        return text

    def decode_content_body(self, data, encoding):
        for enc in reversed(self.parse_encodings(encoding)):
            if enc == 'identity':
                pass
            elif enc in ('gzip', 'x-gzip'):
                data = gzip.decompress(data)
            elif enc == 'deflate':
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
            else:
                raise ValueError("Unknown Content-Encoding: %s" % enc)
        return data

    def send_cacert(self):
        try:
            with open(self.cacert, 'rb') as f:
                data = f.read()
        except OSError:
            self.send_error(404, 'CA certificate not found')
            return
        self.send_response(200, 'OK')
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------------ debug dump
    def print_info(self, req, req_body, res, res_body):
        """Full request/response dump. Only called with --debug."""
        try:
            log.debug('\n%s', self.format_info(req, req_body, res, res_body))
        except Exception as e:
            log.debug('print_info failed: %s', e, exc_info=True)

    @staticmethod
    def _pretty_json(text):
        try:
            json_str = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            return text
        lines = json_str.splitlines()
        if len(lines) < 50:
            return json_str
        return "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))

    def format_info(self, req, req_body, res, res_body):
        def qsl_text(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in parse_qsl(s, keep_blank_values=True))

        def to_text(b):
            return b.decode('utf-8', 'replace') if isinstance(b, (bytes, bytearray)) else str(b)

        def fmt_headers(h):
            return ''.join('%s: %s\n' % kv for kv in h.items())

        out = []
        out.append(with_color(33, "%s %s %s\n%s" % (req.command, req.path, req.request_version,
                                                    fmt_headers(req.headers))))

        u = urlsplit(req.path)
        if u.query:
            out.append(with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % qsl_text(u.query)))

        cookie = req.headers.get('Cookie', '')
        if cookie:
            out.append(with_color(32, "==== COOKIE ====\n%s\n" % qsl_text(re.sub(r';\s*', '&', cookie))))

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            try:
                token = base64.b64decode(auth.split()[1]).decode('utf-8', 'replace')
                out.append(with_color(31, "==== BASIC AUTH ====\n%s\n" % token))
            except Exception:
                pass

        if req_body:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')
            text = to_text(req_body)
            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = qsl_text(text)
            elif content_type.startswith('application/json'):
                req_body_text = self._pretty_json(text)
            elif len(req_body) < 1024 and b'\0' not in req_body:
                req_body_text = text
            if req_body_text:
                out.append(with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text))

        out.append(with_color(36, "%s %d %s\n%s" % (res.response_version, res.status, res.reason,
                                                    fmt_headers(res.headers))))

        cookies = res.headers.get_all('Set-Cookie')
        if cookies:
            out.append(with_color(31, "==== SET-COOKIE ====\n%s\n" % '\n'.join(cookies)))

        if res_body:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')
            if content_type.startswith('application/json'):
                res_body_text = self._pretty_json(to_text(res_body))
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', to_text(res_body[:65536]), re.I)
                if m:
                    out.append(with_color(32, "==== HTML TITLE ====\n%s\n" % html.unescape(m.group(1))))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = to_text(res_body)
            elif content_type.startswith('application/xml') and len(res_body) < 65536:
                res_body_text = to_text(res_body)
            if res_body_text:
                out.append(with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text))

        return '\n'.join(out)

    # ------------------------------------------------------------------ hooks
    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        ct = res.headers.get('Content-Type', '')
        if ct.startswith('application/xml') and res_body.lstrip().startswith(b'<'):
            try:
                r = ET.fromstring(res_body)
            except ET.ParseError:
                return None
            if r.tag == 'policy':
                changed = False
                for entry in r.findall('./gateways/external/list/entry[@name]'):
                    # stupid GP client doesn't know how to resolve the
                    # gateway address while connected through a proxy
                    hp = entry.attrib['name'].split(':', 1)
                    h, p = hp[0], ((':' + hp[1]) if len(hp) == 2 else '')
                    try:
                        entry.attrib['name'] = socket.gethostbyname(h) + p
                        changed = True
                    except OSError as e:
                        log.warning('Cannot resolve gateway %s: %s', h, e)
                if changed:
                    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(r)
        return None

    def save_handler(self, req, req_body, res, res_body):
        if self.debug:
            self.print_info(req, req_body, res, res_body)


def build_upstream_context(args):
    ctx = ssl.create_default_context(cafile=args.cafile) if args.cafile else ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    return ctx


def test(HandlerClass=ProxyRequestHandler, ServerClass=ProxyServer, protocol="HTTP/1.1"):
    p = argparse.ArgumentParser(description='Intercepting HTTP/HTTPS proxy')
    p.add_argument('-p', '--port', type=int, default=8080)
    p.add_argument('-b', '--bind', default='127.0.0.1',
                   help='address to listen on (default: 127.0.0.1; the proxy is unauthenticated)')
    p.add_argument('-t', '--tunnel-path', default='/ssl-tunnel-connect.sslvpn')
    p.add_argument('-d', '--debug', action='store_true',
                   help='verbose logging: full request/response dumps, tunnel hex dumps and pcap text files, '
                        'tracebacks. Output contains cookies/credentials!')
    p.add_argument('--dump-dir', default='.', help='where --debug writes tunnel-*.pcap.txt (default: .)')
    g = p.add_argument_group('Upstream TLS')
    g.add_argument('--cafile', help='CA bundle used to verify upstream servers (default: system store)')
    g.add_argument('--insecure', action='store_true', help='do not verify upstream server certificates')
    g = p.add_argument_group('Client certificate')
    g.add_argument('--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    args = p.parse_args()
    if args.key and not args.cert:
        p.error("--key without --cert doesn't make sense")

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(levelname)s [%(threadName)s] %(message)s' if args.debug
        else '%(asctime)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S')

    if args.bind not in ('127.0.0.1', '::1', 'localhost'):
        log.warning('Listening on %s: this proxy has NO authentication and holds a trusted CA key', args.bind)
    if args.insecure:
        log.warning('Upstream certificate verification is DISABLED (--insecure)')

    HandlerClass.protocol_version = protocol
    HandlerClass.args = args
    HandlerClass.debug = args.debug
    HandlerClass.upstream_ctx = build_upstream_context(args)

    httpd = ServerClass((args.bind, args.port), HandlerClass)
    sa = httpd.socket.getsockname()
    log.info("Serving HTTP Proxy on %s port %d (debug %s)...", sa[0], sa[1], 'ON' if args.debug else 'off')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info('Shutting down')
    finally:
        httpd.server_close()


if __name__ == '__main__':
    test()
