#!/usr/bin/python3

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

sys.path.append('simple-websocket-server')

import capstone
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket


def _parse_int(x):
  if x.startswith('0x'):
    return int(x[2:], 16)
  return int(x)


def _disassemble(memory, startAddress, endAddress):
  cuts = set([startAddress])
  raw_edges = collections.defaultdict(list)
  block_edges = collections.defaultdict(set)
  blocks = collections.defaultdict(lambda: {'edges': [], 'instructions': []})

  md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
  md.detail = True

  code = base64.b16decode(memory, casefold=True)

  for i in md.disasm(code, startAddress):
    if capstone.CS_GRP_JUMP in i.groups:
      cuts.add(i.address + i.size)
      cuts.add(i.operands[0].value.imm)
      if i.mnemonic == 'jmp':
        raw_edges[i.address] = [(i.operands[0].value.imm, 'unconditional')]
      else:
        raw_edges[i.address] = [(i.address + i.size, 'fallthrough'),
                                (i.operands[0].value.imm, 'jump')]
    elif capstone.CS_GRP_RET not in i.groups:
      raw_edges[i.address] = [(i.address + i.size, 'unconditional')]
    # Some amount of padding was added to the code to ensure that the last
    # instruction is read fully.
    if i.address == endAddress:
      break

  current_block = None
  for i in md.disasm(code, startAddress):
    if i.address in cuts:
      current_block = blocks['%x' % i.address]
    if i.address in raw_edges:
      for dst, edgetype in raw_edges[i.address]:
        if dst not in cuts:
          continue
        current_block['edges'].append({'type': edgetype, 'target': '%x' % dst})
    current_block['instructions'].append({
      'address': '%x' % i.address,
      'bytes': [x for x in i.bytes],
      'mnemonic': i.mnemonic,
      'op': i.op_str,
    })

  reachable = set()
  queue = ['%x' % startAddress]
  while queue:
    addr = queue.pop()
    if addr in reachable:
      continue
    reachable.add(addr)
    for edge in blocks[addr]['edges']:
      queue.append(edge['target'])

  for unreachable in sorted(set(blocks.keys()) - reachable):
    del blocks[unreachable]

  return blocks


class GdbConnection(object):
  def __init__(self, binary, core, ws):
    self._ws = ws
    self._ptm, self._pts = pty.openpty()
    self._p = subprocess.Popen(
        ['/usr/bin/gdb', '--nx', '--quiet', '--interpreter=mi',
         '--tty=%s' % os.ttyname(self._pts), binary, core],
        stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    self._ws.sendMessage(json.dumps(self.readResponse()))
    self.send(b'-enable-frame-filters')

  def send(self, *args, token=None):
    payload = b''
    if token is not None:
      payload += b'%d' % token
    payload += b' '.join(args) + b'\n'
    logging.debug('Wrote %s', payload)
    self._p.stdin.write(payload)
    self._p.stdin.flush()
    return self.readResponse()

  @staticmethod
  def _parseConst(line, value_idx):
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
          raise Exception('Unknown escape code: %s' % chr(line[value_idx]))
      else:
        value += str(chr(line[value_idx]))
      value_idx += 1
    return value, value_idx + 1

  @staticmethod
  def _parseList(line, value_idx):
    result = []
    assert line[value_idx] == ord('[')
    if line[value_idx+1] == ord(']'):
      return result, value_idx + 2
    while line[value_idx] != ord(']'):
      value, value_idx = GdbConnection._parseValue(line, value_idx + 1)
      result.append(value)
    return result, value_idx + 1

  @staticmethod
  def _parseTuple(line, value_idx, opening=ord('{'), closing=ord('}')):
    result = {}
    assert line[value_idx] == opening
    if line[value_idx+1] == closing:
      return result, value_idx + 2
    while line[value_idx] != closing:
      variable_idx = value_idx + 1
      value_idx = line.index(b'=', variable_idx)
      variable = line[variable_idx:value_idx].decode('utf-8')
      result[variable], value_idx = GdbConnection._parseValue(line, value_idx+1)
    return result, value_idx + 1

  @staticmethod
  def _parseValue(line, value_idx):
    if line[value_idx] == ord('['):
      return GdbConnection._parseList(line, value_idx)
    elif line[value_idx] == ord('{'):
      return GdbConnection._parseTuple(line, value_idx)
    elif line[value_idx] == ord('"'):
      return GdbConnection._parseConst(line, value_idx)
    else:
      # Old-style tuple.
      return GdbConnection._parseValue(line, line.find(b'=', value_idx) + 1)

  @staticmethod
  def _parseClass(line, value_idx):
    result_idx = line.find(b',', value_idx)
    if result_idx == -1:
      return line[value_idx:].decode('utf-8'), len(line)
    return line[value_idx:result_idx].decode('utf-8'), result_idx

  @staticmethod
  def _parseRecord(line, result_idx):
    result = {}
    className, result_idx = GdbConnection._parseClass(line, result_idx)
    while result_idx < len(line):
      variable_idx = result_idx + 1
      value_idx = line.index(b'=', variable_idx)
      variable = line[variable_idx:value_idx].decode('utf-8')
      result[variable], result_idx = GdbConnection._parseValue(line, value_idx+1)
    return className, result

  @staticmethod
  def _parseToken(line):
    result_idx = 0
    token = 0
    while ord('0') <= line[result_idx] <= ord('9'):
      token = 10 * token + line[result_idx] - ord('0')
      result_idx += 1
    if result_idx == 0:
      return None, result_idx
    return token, result_idx

  @staticmethod
  def _parseLine(line):
    result = {}

    token, result_idx = GdbConnection._parseToken(line)
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
      result['payload'], _ = GdbConnection._parseConst(line, result_idx)
    elif result['type'].endswith('-async'):
      result['class'], result['output'] = GdbConnection._parseRecord(line, result_idx)
    else:
      result['class'], result['record'] = GdbConnection._parseRecord(line, result_idx)

    return result

  def readResponse(self):
    response = []
    while True:
      line = self._p.stdout.readline()
      logging.debug('Read %s', line)
      if not line or line == b'(gdb) \n':
        break
      response.append(GdbConnection._parseLine(line.rstrip()))
    return response


class GdbServer(WebSocket):
  def __init__(self, binary, core, server, sock, address):
    super(self.__class__, self).__init__(server, sock, address)
    self._binary = binary
    self._core = core
    self._connection = None

  def handleMessage(self):
    try:
      data = json.loads(self.data)
      token = None
      if 'token' in data:
        token = int(data['token'])
      if data['method'] == 'run':
        self.sendMessage(json.dumps(self._connection.send(data['command'].encode('utf-8'), token=token)))
      elif data['method'] == 'interpreter-exec':
        self.sendMessage(json.dumps(self._connection.send(b'-interpreter-exec', b'console', data['command'].encode('utf-8'))))
      elif data['method'] == 'get-source':
        try:
          with open(data['filename'], 'r') as f:
            self.sendMessage(json.dumps([{'type':'result','record':f.read(),'token':token}]))
        except:
          self.sendMessage(json.dumps([{'type':'result','record':None,'token':token}]))
      elif data['method'] == 'disassemble-graph':
        graph = _disassemble(data['memory'], data['startAddress'], data['endAddress'])
        self.sendMessage(json.dumps([{'type':'result','record':graph,'token':token}]))
      else:
        logging.error('unhandled method %s', data)
    except:
      logging.exception('something failed')

  def handleConnected(self):
    logging.info('%s connected', self.address)
    self._connection = GdbConnection(self._binary, self._core, self)

  def handleClose(self):
    logging.info('%s closed', self.address)
    self._connection.send(b'-gdb-exit')


def GdbServerFactory(binary, core):
  def factory(*args, **kwargs):
    return GdbServer(binary, core, *args, **kwargs)
  return factory


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--verbose', '-v', action='store_true')
  parser.add_argument('binary', type=str)
  parser.add_argument('core', type=str)

  args = parser.parse_args()

  if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.INFO)

  gdb_server = SimpleWebSocketServer('localhost', 8001, GdbServerFactory(args.binary, args.core))
  websocket_thread = threading.Thread(target=lambda: gdb_server.serveforever(), daemon=True)
  websocket_thread.start()

  socketserver.TCPServer.allow_reuse_address = True
  http_server = socketserver.TCPServer(('localhost', 8000), http.server.SimpleHTTPRequestHandler)
  threading.Thread(target=lambda: http_server.serve_forever(), daemon=True).start()

  subprocess.check_call(['/usr/bin/xdg-open', 'http://localhost:8000'])

  websocket_thread.join()


if __name__ == '__main__':
  main()

# vi: tabstop=2 shiftwidth=2
