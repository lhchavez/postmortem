#!/usr/bin/python3

"""A tiny gdb frontend. This is intended for post-mortem debugging."""

import argparse
import base64
import collections
import http.server
import json
import logging
import os
import pty
import socketserver
import subprocess
import sys
import threading

import capstone

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'simple-websocket-server'))

# pylint: disable=import-error,wrong-import-position
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

_UNCONDITIONAL_JUMP_MNEMONICS = ['jmp']
_HALT_MNEMONICS = ['hlt']


def _parse_int(s):
    if s.startswith('0x'):
        return int(s[2:], 16)
    return int(s)


def _calculate_edges(disassembler, code, address_range):
    cuts = set([address_range[0]])
    edges = collections.defaultdict(list)
    for i in disassembler.disasm(code, address_range[0]):
        if capstone.CS_GRP_JUMP in i.groups:
            cuts.add(i.address + i.size)
            cuts.add(i.operands[0].value.imm)
            if i.mnemonic in _UNCONDITIONAL_JUMP_MNEMONICS:
                edges[i.address] = [(i.operands[0].value.imm, 'unconditional')]
            else:
                edges[i.address] = [(i.address + i.size, 'fallthrough'),
                                    (i.operands[0].value.imm, 'jump')]
        elif capstone.CS_GRP_RET in i.groups or i.mnemonic in _HALT_MNEMONICS:
            cuts.add(i.address + i.size)
        else:
            edges[i.address] = [(i.address + i.size, 'unconditional')]
        # Some amount of padding was added to the code to ensure that the last
        # instruction is read fully.
        if i.address >= address_range[1]:
            break
    return cuts, edges


def _fill_basic_blocks(disassembler, code, cuts, edges, address_range):
    blocks = collections.defaultdict(lambda: {'edges': [], 'instructions': []})

    current_block = None
    for i in disassembler.disasm(code, address_range[0]):
        if i.address in cuts:
            current_block = blocks['%x' % i.address]
        if i.address in edges:
            for dst, edgetype in edges[i.address]:
                if dst not in cuts:
                    continue
                current_block['edges'].append({'type': edgetype,
                                               'target': '%x' % dst})
        current_block['instructions'].append({
            'address': '%x' % i.address,
            'bytes': [x for x in i.bytes],
            'mnemonic': i.mnemonic,
            'op': i.op_str,
        })
        # Some amount of padding was added to the code to ensure that the last
        # instruction is read fully.
        if i.address >= address_range[1]:
            break
    return blocks


def _prune_unreachable(blocks, address_range):
    reachable = set()
    queue = ['%x' % address_range[0]]
    while queue:
        addr = queue.pop()
        if addr in reachable:
            continue
        reachable.add(addr)
        for edge in blocks[addr]['edges']:
            queue.append(edge['target'])

    for unreachable in sorted(set(blocks.keys()) - reachable):
        del blocks[unreachable]


def _disassemble(isa, memory, address_range):
    if isa == 'x86':
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif isa == 'x86_64':
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif isa == 'aarch64':
        disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_64)
    elif isa == 'arm':
        disassembler = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_32)
    else:
        logging.error('Unknown ISA: %s', isa)
        return {}
    disassembler.detail = True
    disassembler.syntax = capstone.CS_OPT_SYNTAX_ATT
    code = base64.b16decode(memory, casefold=True)

    cuts, edges = _calculate_edges(disassembler, code, address_range)
    blocks = _fill_basic_blocks(disassembler, code, cuts, edges, address_range)
    _prune_unreachable(blocks, address_range)

    return blocks


class GdbConnection(object):  # pylint: disable=too-few-public-methods
    """Represents a gdb connection with the gdb/mi protocol."""

    def __init__(self, gdb_path, gdb_args, ws):
        self._ws = ws
        self._ptm, self._pts = pty.openpty()
        self._p = subprocess.Popen(
            [gdb_path, '--nx', '--quiet', '--interpreter=mi',
             '--tty=%s' % os.ttyname(self._pts)] + gdb_args,
            stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        for message in self._read_response():
            self._ws.sendMessage(json.dumps(message))
        self.send(b'-enable-frame-filters')

    def send(self, *args, token=None):
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
    def _parse_const(line, value_idx):
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
    def _parse_list(line, value_idx):
        result = []
        assert line[value_idx] == ord('[')
        if line[value_idx+1] == ord(']'):
            return result, value_idx + 2
        while line[value_idx] != ord(']'):
            value, value_idx = GdbConnection._parse_value(line, value_idx + 1)
            result.append(value)
        return result, value_idx + 1

    @staticmethod
    def _parse_tuple(line, value_idx, opening=ord('{'), closing=ord('}')):
        result = {}
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
    def _parse_value(line, value_idx):
        if line[value_idx] == ord('['):
            return GdbConnection._parse_list(line, value_idx)
        if line[value_idx] == ord('{'):
            return GdbConnection._parse_tuple(line, value_idx)
        if line[value_idx] == ord('"'):
            return GdbConnection._parse_const(line, value_idx)
        # Old-style tuple.
        return GdbConnection._parse_value(line, line.find(b'=', value_idx) + 1)

    @staticmethod
    def _parse_class(line, value_idx):
        result_idx = line.find(b',', value_idx)
        if result_idx == -1:
            return line[value_idx:].decode('utf-8'), len(line)
        return line[value_idx:result_idx].decode('utf-8'), result_idx

    @staticmethod
    def _parse_record(line, result_idx):
        result = {}
        class_name, result_idx = GdbConnection._parse_class(line, result_idx)
        while result_idx < len(line):
            variable_idx = result_idx + 1
            value_idx = line.index(b'=', variable_idx)
            variable = line[variable_idx:value_idx].decode('utf-8')
            result[variable], result_idx = GdbConnection._parse_value(
                line, value_idx+1)
        return class_name, result

    @staticmethod
    def _parse_token(line):
        result_idx = 0
        token = 0
        while ord('0') <= line[result_idx] <= ord('9'):
            token = 10 * token + line[result_idx] - ord('0')
            result_idx += 1
        if result_idx == 0:
            return None, result_idx
        return token, result_idx

    @staticmethod
    def _parse_line(line):
        result = {}

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

    def _read_response(self):
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
    def __init__(self, gdb_path, gdb_args, server, sock, address):
        super().__init__(server, sock, address)
        self._gdb_path = gdb_path
        self._gdb_args = gdb_args
        self._connection = None

    def _handle_run_message(self, command, token=None):
        for message in self._connection.send(command, token=token):
            self.sendMessage(json.dumps(message))

    def _handle_interpreter_exec(self, command):
        for message in self._connection.send(b'-interpreter-exec', b'console',
                                             command):
            self.sendMessage(json.dumps(message))

    def _handle_get_source(self, filename, token=None):
        record = None
        try:
            with open(filename, 'r') as f:
                record = f.read()
        except:  # pylint: disable=bare-except
            logging.exception('Failed to read %s', filename)
        self.sendMessage(json.dumps({'type': 'result',
                                     'record': record,
                                     'token': token}))

    def _handle_disassemble_graph(self, isa, address_range, token=None):
        for message in self._connection.send(
                b'-data-read-memory-bytes',
                b'0x%x' % address_range[0],
                b'%d' % (address_range[1] - address_range[0] + 32)):
            if message['type'] == 'result':
                graph = _disassemble(
                    isa, message['record']['memory'][0]['contents'],
                    address_range)
                self.sendMessage(json.dumps({'type': 'result',
                                             'record': graph,
                                             'token': token}))
            else:
                self.sendMessage(json.dumps(message))

    def handleMessage(self):  # pylint: disable=invalid-name
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
            logging.error('unhandled method %s', data)
        except:  # pylint: disable=bare-except
            logging.exception('Error handling request')

    def handleConnected(self):  # pylint: disable=invalid-name
        """Handles the WebSocket connected event."""
        logging.info('%s connected', self.address)
        self._connection = GdbConnection(self._gdb_path, self._gdb_args, self)

    def handleClose(self):  # pylint: disable=invalid-name
        """Handles the WebSocket close event."""
        logging.info('%s closed', self.address)
        self._connection.send(b'-gdb-exit')


class HTTPHandler(http.server.SimpleHTTPRequestHandler):
    """A SimpleHTTPRequestHandler that serves from root instead of CWD."""

    def __init__(self, root, server, sock, address):
        self._cwd = os.getcwd()
        self._root = root
        super().__init__(server, sock, address)

    def translate_path(self, path):
        """Returns a path translated to the chosen directory."""
        path = http.server.SimpleHTTPRequestHandler.translate_path(self, path)
        return os.path.join(self._root, os.path.relpath(path, self._cwd))


def _factory(cls, *cls_args, **cls_kwargs):
    """Factory for GdbServer websocket support."""
    def _wrapped_factory(*args, **kwargs):
        merged_args = cls_args + args
        merged_kwargs = {}
        for src in (cls_kwargs, kwargs):
            for key, val in src.items():
                merged_kwargs[key] = val
        return cls(*merged_args, *merged_kwargs)
    return _wrapped_factory


def main():
    """Main entrypoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--gdb-path', default='/usr/bin/gdb',
                        help='Path to the gdb binary')
    parser.add_argument('gdb_args', metavar='GDB-ARG', type=str, nargs='+',
                        help='Argument to gdb')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    gdb_server = SimpleWebSocketServer('localhost', 0,
                                       _factory(GdbServer, args.gdb_path,
                                                args.gdb_args))
    gdb_server_port = gdb_server.serversocket.getsockname()[1]
    websocket_thread = threading.Thread(target=gdb_server.serveforever,
                                        daemon=True)
    websocket_thread.start()

    socketserver.TCPServer.allow_reuse_address = True
    http_server = socketserver.TCPServer(
        ('localhost', 0),
        _factory(HTTPHandler, os.path.dirname(os.path.realpath(__file__))))
    http_port = http_server.socket.getsockname()[1]
    threading.Thread(target=http_server.serve_forever, daemon=True).start()

    payload = base64.b64encode(
        json.dumps({'websocketPort': gdb_server_port}).encode('utf-8'))
    subprocess.check_call([
        '/usr/bin/xdg-open',
        'http://localhost:%d#%s' % (http_port, payload.decode('utf-8'))])

    websocket_thread.join()


if __name__ == '__main__':
    main()

# vi: tabstop=4 shiftwidth=4
