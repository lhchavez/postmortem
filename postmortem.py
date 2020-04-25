#!/usr/bin/python3

"""A tiny gdb frontend. This is intended for post-mortem debugging."""

import argparse
import base64
import functools
import http.server
import json
import logging
import os
import pty
import re
import socketserver
import subprocess
import sys
import threading
from typing import (Any, Callable, Dict, Iterable, List, Optional, Sequence,
                    Tuple, TypeVar, Type, Union)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'simple-websocket-server'))

# pylint: disable=import-error,wrong-import-position
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket  # type: ignore

import cfg


class GdbConnection:  # pylint: disable=too-few-public-methods
    """Represents a gdb connection with the gdb/mi protocol."""

    def __init__(self, gdb_path: str, gdb_args: Sequence[str], ws: WebSocket):
        self._ws = ws
        self._ptm, self._pts = pty.openpty()
        self._p = subprocess.Popen(
            (gdb_path, '--nx', '--quiet', '--interpreter=mi',
             '--tty=%s' % os.ttyname(self._pts)) + tuple(gdb_args),
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE)
        for message in self._read_response():
            self._ws.sendMessage(json.dumps(message))
        self.send(b'-enable-frame-filters')

    def send(self,
            *args: bytes,
             token: Optional[int] = None) -> Iterable[Dict[str, Any]]:
        """Sends a command to gdb."""
        payload = b''
        if token is not None:
            payload += b'%d' % token
        payload += b' '.join(args) + b'\n'
        logging.debug('Wrote %s', payload)
        self._p.stdin.write(payload)
        self._p.stdin.flush()
        yield from self._read_response()

    @staticmethod
    def _parse_const(line: bytes, value_idx: int) -> Tuple[str, int]:
        assert line[value_idx] == ord('"')
        value_idx += 1
        value = ''
        while line[value_idx] != ord('"'):
            if line[value_idx] == ord('\\'):
                value_idx += 1
                if line[value_idx] == ord('n'):
                    value += '\n'
                elif line[value_idx] == ord('r'):
                    value += '\r'
                elif line[value_idx] == ord('t'):
                    value += '\t'
                elif line[value_idx] == ord('f'):
                    value += '\f'
                elif line[value_idx] == ord('b'):
                    value += '\b'
                elif line[value_idx] == ord('\\'):
                    value += '\\'
                elif line[value_idx] == ord('"'):
                    value += '"'
                else:
                    raise Exception('Unknown escape code: %s' %
                                    chr(line[value_idx]))
            else:
                value += str(chr(line[value_idx]))
            value_idx += 1
        return value, value_idx + 1

    @staticmethod
    def _parse_list(line: bytes, value_idx: int) -> Tuple[List[Any], int]:
        result: List[Any] = []
        assert line[value_idx] == ord('[')
        if line[value_idx+1] == ord(']'):
            return result, value_idx + 2
        while line[value_idx] != ord(']'):
            value, value_idx = GdbConnection._parse_value(line, value_idx + 1)
            result.append(value)
        return result, value_idx + 1

    @staticmethod
    def _parse_tuple(
        line: bytes,
        value_idx: int,
        opening: int = ord('{'),
        closing: int = ord('}')
    ) -> Tuple[Dict[str, Any], int]:
        result: Dict[str, Any] = {}
        assert line[value_idx] == opening
        if line[value_idx+1] == closing:
            return result, value_idx + 2
        while line[value_idx] != closing:
            variable_idx = value_idx + 1
            value_idx = line.index(b'=', variable_idx)
            variable = line[variable_idx:value_idx].decode('utf-8')
            result[variable], value_idx = GdbConnection._parse_value(
                line, value_idx + 1)
        return result, value_idx + 1

    @staticmethod
    def _parse_value(line: bytes, value_idx: int) -> Tuple[Any, int]:
        if line[value_idx] == ord('['):
            return GdbConnection._parse_list(line, value_idx)
        if line[value_idx] == ord('{'):
            return GdbConnection._parse_tuple(line, value_idx)
        if line[value_idx] == ord('"'):
            return GdbConnection._parse_const(line, value_idx)
        # Old-style tuple.
        return GdbConnection._parse_value(line, line.find(b'=', value_idx) + 1)

    @staticmethod
    def _parse_class(line: bytes, value_idx: int) -> Tuple[str, int]:
        result_idx = line.find(b',', value_idx)
        if result_idx == -1:
            return line[value_idx:].decode('utf-8'), len(line)
        return line[value_idx:result_idx].decode('utf-8'), result_idx

    @staticmethod
    def _parse_record(line: bytes, result_idx: int) -> Tuple[str, Dict[str, str]]:
        result: Dict[str, str] = {}
        class_name, result_idx = GdbConnection._parse_class(line, result_idx)
        while result_idx < len(line):
            variable_idx = result_idx + 1
            value_idx = line.index(b'=', variable_idx)
            variable = line[variable_idx:value_idx].decode('utf-8')
            result[variable], result_idx = GdbConnection._parse_value(
                line, value_idx+1)
        return class_name, result

    @staticmethod
    def _parse_token(line: bytes) -> Tuple[Optional[int], int]:
        result_idx = 0
        token = 0
        while ord('0') <= line[result_idx] <= ord('9'):
            token = 10 * token + line[result_idx] - ord('0')
            result_idx += 1
        if result_idx == 0:
            return None, result_idx
        return token, result_idx

    @staticmethod
    def _parse_line(line: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {}

        token, result_idx = GdbConnection._parse_token(line)
        if token is not None:
            result['token'] = token
        if line[result_idx] == ord('^'):
            result['type'] = 'result'
        elif line[result_idx] == ord('*'):
            result['type'] = 'exec-async'
        elif line[result_idx] == ord('+'):
            result['type'] = 'status-async'
        elif line[result_idx] == ord('='):
            result['type'] = 'notify-async'
        elif line[result_idx] == ord('~'):
            result['type'] = 'console-stream'
        elif line[result_idx] == ord('@'):
            result['type'] = 'target-stream'
        elif line[result_idx] == ord('&'):
            result['type'] = 'log-stream'
        else:
            logging.error('unknown character %s', chr(line[result_idx]))
            return result

        result_idx += 1
        if result['type'].endswith('-stream'):
            result['payload'], _ = GdbConnection._parse_const(line, result_idx)
        elif result['type'].endswith('-async'):
            result['class'], result['output'] = GdbConnection._parse_record(
                line, result_idx)
        else:
            result['class'], result['record'] = GdbConnection._parse_record(
                line, result_idx)

        return result

    def _read_response(self) -> Iterable[Dict[str, Any]]:
        """Reads a response from gdb."""
        while True:
            line = self._p.stdout.readline()
            logging.debug('Read %s', line)
            if not line or line == b'(gdb) \n':
                break
            yield GdbConnection._parse_line(line.rstrip())


class GdbServer(WebSocket):
    """A WebSocket connection to the browser."""

    # pylint: disable=too-many-arguments
    def __init__(self, gdb_path: str, gdb_args: Sequence[str], *args: Any):
        super().__init__(*args)
        self._gdb_path = gdb_path
        self._gdb_args = gdb_args
        self._connection: Optional[GdbConnection] = None

    def _handle_run_message(self,
                            command: bytes,
                            token: Optional[int] = None) -> None:
        assert self._connection is not None
        for message in self._connection.send(command, token=token):
            self.sendMessage(json.dumps(message))

    def _handle_interpreter_exec(self, command: bytes) -> None:
        assert self._connection is not None
        for message in self._connection.send(b'-interpreter-exec', b'console',
                                             command):
            self.sendMessage(json.dumps(message))

    def _handle_get_source(self,
                           filename: str,
                           token: Optional[int] = None) -> None:
        record = None
        try:
            with open(filename, 'r') as f:
                record = f.read()
        except:  # pylint: disable=bare-except
            logging.exception('Failed to read %s', filename)
        self.sendMessage(
            json.dumps({
                'type': 'result',
                'record': record,
                'token': token
            }))

    def _handle_disassemble_graph(self,
                                  isa: str,
                                  address_range: Tuple[int, int],
                                  token: Optional[int] = None) -> None:
        assert self._connection is not None
        for message in self._connection.send(
                b'-data-read-memory-bytes', b'0x%x' % address_range[0],
                b'%d' % (address_range[1] - address_range[0] + 32)):
            if message['type'] == 'result':
                graph = cfg.Disassembler(isa).disassemble(
                    base64.b16decode(message['record']['memory'][0]['contents'],
                                     casefold=True),
                    address_range)
                self.sendMessage(json.dumps({
                    'type': 'result',
                    'record': graph,
                    'token': token,
                }))
            else:
                self.sendMessage(json.dumps(message))

    def _handle_info_functions(self, token: Optional[int] = None) -> None:
        assert self._connection is not None
        symbol_re = re.compile(r'^(0x[0-9a-f]+)\s+([^\n]+)\n$')

        functions = []
        for message in self._connection.send(
                b'-interpreter-exec',
                b'console',
                b'"info functions"'):
            if message['type'] != 'console-stream':
                continue
            match = symbol_re.match(message['payload'])
            if not match:
                continue
            functions.append({
                'address': match.group(1),
                'name': match.group(2),
            })
        functions.sort(key=lambda x: x['address'])
        self.sendMessage(json.dumps({
            'type': 'result',
            'record': functions,
            'token': token,
        }))

    def handleMessage(self) -> None:  # pylint: disable=invalid-name
        """Handles one WebSockets message."""
        try:
            data = json.loads(self.data)
            token = None
            if 'token' in data:
                token = int(data['token'])
            if data['method'] == 'run':
                self._handle_run_message(data['command'].encode('utf-8'),
                                         token=token)
                return
            if data['method'] == 'interpreter-exec':
                self._handle_interpreter_exec(data['command'].encode('utf-8'))
                return
            if data['method'] == 'get-source':
                self._handle_get_source(data['filename'].encode('utf-8'),
                                        token=token)
                return
            if data['method'] == 'disassemble-graph':
                self._handle_disassemble_graph(
                    data['isa'], (data['startAddress'], data['endAddress']),
                    token=token)
                return
            if data['method'] == 'info-functions':
                self._handle_info_functions(token=token)
                return
        except:  # pylint: disable=bare-except
            logging.exception('Error handling request')

    def handleConnected(self) -> None:  # pylint: disable=invalid-name
        """Handles the WebSocket connected event."""
        logging.info('%s connected', self.address)
        self._connection = GdbConnection(self._gdb_path, self._gdb_args, self)

    def handleClose(self) -> None:  # pylint: disable=invalid-name
        """Handles the WebSocket close event."""
        logging.info('%s closed', self.address)
        if self._connection is None:
            return
        self._connection.send(b'-gdb-exit')
        self._connection = None


class HTTPHandler(http.server.SimpleHTTPRequestHandler):
    """A SimpleHTTPRequestHandler that serves from root instead of CWD."""

    def __init__(self, root: str, *args: Any):
        self._cwd = os.getcwd()
        self._root = root
        super().__init__(*args)

    def translate_path(self, path: str) -> str:
        """Returns a path translated to the chosen directory."""
        path = http.server.SimpleHTTPRequestHandler.translate_path(self, path)
        return os.path.join(self._root, os.path.relpath(path, self._cwd))


FactoryType = TypeVar('FactoryType')


def _factory(cls: Type[FactoryType], *cls_args: Any,
             **cls_kwargs: Any) -> Callable[..., FactoryType]:
    """Factory for GdbServer websocket support."""
    @functools.wraps(cls)
    def _wrapped_factory(*args: Any, **kwargs: Any) -> FactoryType:
        merged_args = cls_args + args
        merged_kwargs = {}
        for src in (cls_kwargs, kwargs):
            for key, val in src.items():
                merged_kwargs[key] = val
        return cls(*merged_args, *merged_kwargs)
    return _wrapped_factory


def main() -> None:
    """Main entrypoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--http-port', default=0, type=int,
                        help='TCP port for the web server.')
    parser.add_argument('--ws-port', default=0, type=int,
                        help='TCP port for the WebSockets.')
    parser.add_argument('--no-launch', dest='launch', action='store_false',
                        help='Automatically launch a browser.')
    parser.add_argument('--gdb-path', default='/usr/bin/gdb',
                        help='Path to the gdb binary')
    parser.add_argument('gdb_args', metavar='GDB-ARG', type=str, nargs='+',
                        help='Argument to gdb')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    gdb_server = SimpleWebSocketServer('localhost', args.ws_port,
                                       _factory(GdbServer, args.gdb_path,
                                                args.gdb_args))
    gdb_server_port = gdb_server.serversocket.getsockname()[1]
    websocket_thread = threading.Thread(target=gdb_server.serveforever,
                                        daemon=True)
    websocket_thread.start()

    socketserver.TCPServer.allow_reuse_address = True
    http_server = socketserver.TCPServer(
        ('localhost', args.http_port),
        _factory(HTTPHandler, os.path.dirname(os.path.realpath(__file__))))
    http_port = http_server.socket.getsockname()[1]
    threading.Thread(target=http_server.serve_forever, daemon=True).start()

    payload = base64.b64encode(
        json.dumps({'websocketPort': gdb_server_port}).encode('utf-8'))
    url = 'http://localhost:%d#%s' % (http_port, payload.decode('utf-8'))
    if args.launch:
        subprocess.check_call(['/usr/bin/xdg-open', url])
    else:
        print('Ready. Navigate to %s' % url)

    websocket_thread.join()


if __name__ == '__main__':
    main()

# vi: tabstop=4 shiftwidth=4
