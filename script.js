function Deferred() {
  this.resolve = null;
  this.reject = null;
  this.promise = new Promise(function(resolve, reject) {
    this.resolve = resolve;
    this.reject = reject;
  }.bind(this));
  Object.freeze(this);
}

function createSVGNode(type, attributes) {
  const svgNS = 'http://www.w3.org/2000/svg';

  let node = document.createElementNS(svgNS, type);
  if (!attributes) {
    return node;
  }
  for (const key in attributes) {
    node.setAttributeNS(null, key, attributes[key]);
  }
  return node;
}

Prism.languages.assembly = {
  'comment' : /#.*/,
  'immediate' : {
    pattern : /\$0x[0-9a-fA-F]+/,
    alias : 'number',
  },
  'register' : {
    pattern : /%[a-z0-9]+/,
    alias : 'function',
  },
  'address' : {
    pattern : /-?0x[0-9a-fA-F]+/,
    alias : 'string',
  },
  'symbol' : /<.*>/,
  'opcode' : {
    pattern : /[a-z][a-z0-9.]+/,
    alias : 'keyword',
  },
  'number' : /[0-9]+/,
  'operator' : /[(),]/,
};

class Graph {
  constructor(svg) {
    this.svg = svg;
    this.visible = false;
    this.maxWidth = this.svg.clientWidth;
    this.maxHeight = this.svg.clientHeight;
    this.viewport = {
      x : 0,
      y : 0,
      width : this.svg.clientWidth,
      height : this.svg.clientHeight,
    };
    this.mousedown = false;
    this.mouseanchor = null;
    this.svg.addEventListener('wheel', ev => this.__onWheel(ev));
    this.svg.addEventListener('mousemove', ev => this.__onMouseMove(ev));
    this.svg.addEventListener('mousedown', ev => this.__onMouseDown(ev));
    this.svg.addEventListener('mouseup', ev => this.__onMouseUp(ev));
  }

  show() {
    this.svg.style.display = 'block';
    this.visible = true;
    this.maxWidth = this.svg.clientWidth;
    this.maxHeight = this.svg.clientHeight;
    this.viewport = {
      x : 0,
      y : 0,
      width : this.svg.clientWidth,
      height : this.svg.clientHeight,
    };
		this.__render(this.data);
  }

  hide() {
    this.svg.style.display = 'none';
    this.visible = false;
  }

  render(data) {
		this.data = data;
		this.dirty = true;
		if (!this.visible) {
			return;
		}
		this.__render(this.data);
  }

  __render(data) {
    if (!this.dirty) {
      return;
		}
		this.dirty = false;
    let offsetY = 20;
    let blocks = {};
    let g = new dagre.graphlib.Graph();
    g.setGraph({});
    let graphNode = document.querySelector('svg g[class="graph"]');
    while (graphNode.lastChild) {
      graphNode.removeChild(graphNode.lastChild);
      }
    for (const addr in data) {
      const block = data[addr];
      let blockElm = createSVGNode('g');
      let blockTextElm = createSVGNode('text');
      blockElm.appendChild(blockTextElm);
      let addressWidth = 0;
      let mnemonicWidth = 0;
      let opWidth = 0;
      for (let i = 0; i < block.instructions.length; i++) {
        let ins = block.instructions[i];

        addressWidth = Math.max(addressWidth, ins.address.length);
        mnemonicWidth = Math.max(mnemonicWidth, ins.mnemonic.length);
        opWidth = Math.max(opWidth, ins.op.length);
        }
      for (let i = 0; i < block.instructions.length; i++) {
        let ins = block.instructions[i];

        let addressSpan = createSVGNode('tspan', {
          x : 0,
          y : i + 'em',
        });
        addressSpan.setAttribute('class', 'address');
        addressSpan.appendChild(document.createTextNode(ins.address));
        blockTextElm.appendChild(addressSpan);

        let mnemonicSpan = createSVGNode('tspan', {
          x : (addressWidth + 2) + 'ex',
          y : i + 'em',
        });
        mnemonicSpan.setAttribute('class', 'mnemonic');
        mnemonicSpan.appendChild(document.createTextNode(ins.mnemonic));
        blockTextElm.appendChild(mnemonicSpan);

        let registerSpan = createSVGNode('tspan', {
          x : (addressWidth + mnemonicWidth + 5) + 'ex',
          y : i + 'em',
        });
        registerSpan.setAttribute('class', 'register');
        registerSpan.appendChild(document.createTextNode(ins.op));
        blockTextElm.appendChild(registerSpan);
      }
      graphNode.appendChild(blockElm);
      let blockTextBBox = blockElm.getBBox();
      let rectElm = createSVGNode('rect', {
        x : blockTextBBox.x - 5,
        y : blockTextBBox.y - 5,
        width : blockTextBBox.width + 10,
        height : blockTextBBox.height + 10,
      });
      rectElm.setAttribute('class', 'block');
      blockElm.insertBefore(rectElm, blockTextElm);
      blocks[addr] = {
        label : addr,
        width : blockTextBBox.width + 10,
        height : blockTextBBox.height + 10,
        element : blockElm,
      };
      g.setNode(addr, blocks[addr]);
      for (let i = 0; i < block.edges.length; i++) {
        g.setEdge(addr, block.edges[i].target, {type : block.edges[i].type});
      }
    }

    dagre.layout(g);
    g.nodes().forEach(function(v) {
      let block = g.node(v);
      block.element.setAttributeNS(null, 'transform',
                                   'translate(' +
                                       (5 + block.x - block.width / 2) + ', ' +
                                       (18 + block.y - block.height / 2) + ')');
    });
    g.edges().forEach(function(e) {
      let edge = g.edge(e);
      let points = '';
      for (let i = 0; i < edge.points.length; i++) {
        if (i == 0) {
          points += 'M';
        } else {
          points += 'L';
        }
        points += edge.points[i].x + ',' + edge.points[i].y;
        }
      let lineElm = createSVGNode('path', {
        d : points,
      });
      lineElm.setAttribute('class', 'edge ' + edge.type);
      graphNode.appendChild(lineElm);
    });
    this.maxWidth = this.svg.getBBox().width;
    this.maxHeight = this.svg.getBBox().height;
  }

  __onWheel(ev) {
    this.viewport.width = Math.max(this.svg.clientWidth, this.viewport.width - ev.wheelDelta);
    this.viewport.height =
        Math.max(this.svg.clientHeight, this.viewport.height - ev.wheelDelta);
    this.svg.setAttribute('viewBox',
                     this.viewport.x + ' ' + this.viewport.y + ' ' + this.viewport.width +
                         ' ' + this.viewport.height);
  }

  __onMouseMove(ev) {
    if (!this.mousedown)
      return;
    let scale = 1.0;
    if (this.svg.clientWidth) {
      scale = this.viewport.width / this.svg.clientWidth;
    }
    this.viewport.x =
        Math.min(Math.max(0, this.viewport.x - scale * (ev.offsetX - this.mouseanchor.x)),
                 this.maxWidth - this.svg.clientWidth / scale);
    this.viewport.y =
        Math.min(Math.max(0, this.viewport.y - scale * (ev.offsetY - this.mouseanchor.y)),
                 this.maxHeight - this.svg.clientWidth / scale);
    this.svg.setAttribute('viewBox',
                     this.viewport.x + ' ' + this.viewport.y + ' ' + this.viewport.width +
                         ' ' + this.viewport.height);
    this.mouseanchor = {
      x : ev.offsetX,
      y : ev.offsetY,
    };
  }

  __onMouseDown(ev) {
    ev.preventDefault();
    this.mousedown = true;
    this.mouseanchor = {
      x : ev.offsetX,
      y : ev.offsetY,
    };
  }

  __onMouseUp(ev) {
    ev.preventDefault();
    this.mousedown = false;
    this.mouseanchor = null;
  }
};

function main() {
  let graph = new Graph(document.getElementById('svg'));

  function appendConsoleNode(contents, className) {
    let consoleDiv = document.querySelector('.gdb-console');
    let node = document.createElement('span');
    node.className = className;
    node.appendChild(document.createTextNode(contents));
    consoleDiv.appendChild(node);
    node.scrollIntoView();
    }

  let sourceEditor = document.querySelector('#source-editor>pre>code');
  let assemblyEditor = document.querySelector('#assembly-editor>pre>code');

  let socket = new WebSocket('ws://localhost:8001');
  let currentFrame = {
    fullname : null,
    line : null,
    address : null,
  };
  let payloadCount = 0;
  let promiseMapping = {};

  function socketSend(payload) {
    payload.token = ++payloadCount;
    socket.send(JSON.stringify(payload));
    promiseMapping[payload.token] = new Deferred();
    return promiseMapping[payload.token].promise;
    }
  let sourceCache = {};
  function onSourceReady() {
    sourceEditor.innerText = sourceCache[currentFrame.fullname];
    document.querySelector('#source-editor>pre')
        .setAttribute('data-line', currentFrame.line);
    Prism.highlightElement(sourceEditor);
    document.querySelector('#source-editor .line-highlight').scrollIntoView();
    }
  function onAssemblyReady(currentAddress, insns) {
    let contents = '';
    let activeLine = 0;
    for (let i = 0; i < insns.length; i++) {
      contents += insns[i].address + ' ' + insns[i].inst + '\n';
      if (insns[i].address == currentAddress) {
        activeLine = i;
      }
    }
    assemblyEditor.innerText = contents;
    document.querySelector('#assembly-editor>pre')
        .setAttribute('data-line', activeLine + 1);
    Prism.highlightElement(assemblyEditor);
    document.querySelector('#assembly-editor .line-highlight').scrollIntoView();
    let startAddress = parseInt(insns[0].address.substr(2), 16);
    let endAddress = parseInt(insns[insns.length - 1].address.substr(2), 16);
    socketSend({
      method : 'disassemble-graph',
      startAddress : startAddress,
      endAddress : endAddress
    }).then(function(record) { graph.render(record); });
    }
  function onThreadSelected(frame) {
    currentFrame = frame;
    let cmd = '-data-disassemble -f ' + currentFrame.fullname + ' -l ' +
              currentFrame.line + ' -n -1 -- 0';
    socketSend({method : 'run', 'command' : cmd}).then(function(record) {
      onAssemblyReady(currentFrame.addr, record.asm_insns);
    });
    socketSend({
      method : 'run',
      'command' : '-data-list-register-values --skip-unavailable x'
    }).then(function(record) {
      let registersElement = document.querySelector('#registers tbody');
      while (registersElement.firstChild) {
        registersElement.removeChild(registersElement.firstChild);
        }
      for (let i = 0; i < record['register-values'].length; i++) {
        let reg = record['register-values'][i];
        if (parseInt(reg.number) > registerNames.length) {
          continue;
          }
        let rowElement = document.createElement('tr');
        let cellElement = document.createElement('td');
        cellElement.appendChild(
            document.createTextNode(registerNames[parseInt(reg.number)]));
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(reg.value));
        rowElement.appendChild(cellElement);
        registersElement.appendChild(rowElement);
      }
    });
    socketSend({
      method : 'run',
      'command' : '-data-read-memory $rsp-128 x 8 100 1'
    }).then(function(record) {
      let stackElement = document.querySelector('#stack tbody');
      while (stackElement.firstChild) {
        stackElement.removeChild(stackElement.firstChild);
        }
      let offset = -128;
      for (let entry of record['memory']) {
        let rowElement = document.createElement('tr');
        let cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(entry.addr));
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.className = 'right';
        cellElement.appendChild(document.createTextNode(offset.toString(16)));
        offset += 8;
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(entry.data[0]));
        rowElement.appendChild(cellElement);
        stackElement.appendChild(rowElement);
      }
    });
    if (sourceCache.hasOwnProperty(currentFrame.fullname)) {
      onSourceReady();
      return;
    }
    socketSend({method : 'get-source', filename : currentFrame.fullname})
        .then(function(record) {
          sourceCache[currentFrame.fullname] = record || '';
          onSourceReady();
        });
  }
  socket.onmessage = function(event) {
    let data = JSON.parse(event.data);
    if (data.type == 'console-stream') {
      appendConsoleNode(data.payload, 'console');
    } else if (data.type == 'log-stream') {
      appendConsoleNode(data.payload, 'log');
    } else if (data.type == 'error-stream') {
      appendConsoleNode(data.payload, 'error');
    } else if (data.type == 'notify-async' &&
               data['class'] == 'thread-selected') {
      onThreadSelected(data.output.frame);
    } else if (data.type == 'result') {
      if (typeof(data.token) === 'undefined' ||
          !promiseMapping.hasOwnProperty(data.token))
        return;
      promiseMapping[data.token].resolve(data.record);
      delete promiseMapping[data.token];
    } else {
      console.log(data);
    }
  };
  socket.onerror = function(event) { console.error(event); };
  let registerNames = [];
  socket.onopen = function(event) {
    socketSend({method : 'run', 'command' : '-data-list-register-names'})
        .then(function(record) {
          Array.prototype.push.apply(registerNames, record['register-names']);
          socketSend({method : 'run', 'command' : '-thread-info'})
              .then(function(record) {
                for (let i = 0; i < record.threads.length; ++i) {
                  if (record.threads[i].id != record['current-thread-id'])
                    continue;
                  onThreadSelected(record.threads[i].frame);
                }
              });
        });
  };

  let cmdHistory = [];
  let cmdHistoryIdx = 0;
  document.querySelector('#gdb-console')
      .addEventListener('submit', function(ev) {
        ev.preventDefault();
        let cmd = document.querySelector('#gdb-console input').value;
        if (cmd) {
          cmdHistory.push(cmd);
          cmdHistoryIdx = cmdHistory.length;
        } else if (cmdHistory.length) {
          cmd = cmdHistory[cmdHistory.length - 1];
        } else {
          return;
        }
        appendConsoleNode('(gdb) ' + cmd + '\n', 'prompt');
        document.querySelector('#gdb-console input').value = '';
        socketSend({method : 'run', 'command' : cmd});
      });

  document.querySelector('#gdb-console input')
      .addEventListener('keydown', function(ev) {
        if (ev.key == 'ArrowUp') {
          ev.preventDefault();
          if (cmdHistoryIdx > 0) {
            document.querySelector('#gdb-console input').value =
                cmdHistory[--cmdHistoryIdx];
          }
        } else if (ev.key == 'ArrowDown') {
          ev.preventDefault();
          if (cmdHistoryIdx < cmdHistory.length) {
            document.querySelector('#gdb-console input').value =
                cmdHistory[++cmdHistoryIdx] || '';
          } else {
            document.querySelector('#gdb-console input').value = '';
          }
        }
      });

  document.querySelector('#gdb-console select[name="view"]')
      .addEventListener('change', function(ev) {
        if (ev.target.value == 'graph') {
          graph.show();
          document.getElementById('source-editor').style.display = 'none';
        } else {
          graph.hide();
          document.getElementById('source-editor').style.display = 'block';
        }
      });
}

document.addEventListener('DOMContentLoaded', main, false);
// vim: set expandtab:ts=2:sw=2
