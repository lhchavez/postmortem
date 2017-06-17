function Deferred() {
  this.resolve = null;
  this.reject = null;
  this.promise = new Promise(function(resolve, reject) {
    this.resolve = resolve;
    this.reject = reject;
  }.bind(this));
  Object.freeze(this);
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

function main() {
  var svg = document.getElementById('svg');
  var maxWidth = svg.clientWidth;
  var maxHeight = svg.clientHeight;
  let viewport = {
    x : 0,
    y : 0,
    width : svg.clientWidth,
    height : svg.clientHeight,
  };
  var mousedown = false;
  var mouseanchor = null;
  svg.addEventListener('wheel', function(ev) {
    viewport.width = Math.max(svg.clientWidth, viewport.width - ev.wheelDelta);
    viewport.height =
        Math.max(svg.clientHeight, viewport.height - ev.wheelDelta);
    svg.setAttribute('viewBox',
                     viewport.x + ' ' + viewport.y + ' ' + viewport.width +
                         ' ' + viewport.height);
  });
  svg.addEventListener('mousemove', function(ev) {
    if (!mousedown)
      return;
    var scale = 1.0;
    if (svg.clientWidth) {
      scale = viewport.width / svg.clientWidth;
    }
    viewport.x =
        Math.min(Math.max(0, viewport.x - scale * (ev.offsetX - mouseanchor.x)),
                 maxWidth - svg.clientWidth / scale);
    viewport.y =
        Math.min(Math.max(0, viewport.y - scale * (ev.offsetY - mouseanchor.y)),
                 maxHeight - svg.clientWidth / scale);
    svg.setAttribute('viewBox',
                     viewport.x + ' ' + viewport.y + ' ' + viewport.width +
                         ' ' + viewport.height);
    mouseanchor = {
      x : ev.offsetX,
      y : ev.offsetY,
    };
  });
  svg.addEventListener('mousedown', function(ev) {
    ev.preventDefault();
    mousedown = true;
    mouseanchor = {
      x : ev.offsetX,
      y : ev.offsetY,
    };
  });
  svg.addEventListener('mouseup', function(ev) {
    ev.preventDefault();
    mousedown = false;
    mouseanchor = null;
  });
  var svgNS = 'http://www.w3.org/2000/svg';
  var xlinkNS = 'http://www.w3.org/1999/xlink';

  function createSVGNode(type, attributes) {
    let node = document.createElementNS(svgNS, type);
    if (attributes) {
      for (const key in attributes) {
        node.setAttributeNS(null, key, attributes[key]);
      }
      }
    return node;
    }

  function renderGraph(data) {
    var offsetY = 20;
    var blocks = {};
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
      var first = true;
      var addressWidth = 0;
      var mnemonicWidth = 0;
      var opWidth = 0;
      for (var i = 0; i < block.instructions.length; i++) {
        var ins = block.instructions[i];

        addressWidth = Math.max(addressWidth, ins.address.length);
        mnemonicWidth = Math.max(mnemonicWidth, ins.mnemonic.length);
        opWidth = Math.max(opWidth, ins.op.length);
        }
      for (var i = 0; i < block.instructions.length; i++) {
        var ins = block.instructions[i];

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
      for (var i = 0; i < block.edges.length; i++) {
        g.setEdge(addr, block.edges[i].target, {type : block.edges[i].type});
      }
    }

    dagre.layout(g);
    g.nodes().forEach(function(v) {
      var block = g.node(v);
      block.element.setAttributeNS(null, 'transform',
                                   'translate(' +
                                       (5 + block.x - block.width / 2) + ', ' +
                                       (18 + block.y - block.height / 2) + ')');
    });
    g.edges().forEach(function(e) {
      var edge = g.edge(e);
      var points = '';
      for (var i = 0; i < edge.points.length; i++) {
        if (i == 0) {
          points += 'M';
        } else {
          points += 'L';
        }
        points += edge.points[i].x + ',' + edge.points[i].y;
        }
      var lineElm = createSVGNode('path', {
        d : points,
      });
      lineElm.setAttribute('class', 'edge ' + edge.type);
      graphNode.appendChild(lineElm);
    });
    maxWidth = svg.getBBox().width;
    maxHeight = svg.getBBox().height;
    }

  function appendConsoleNode(contents, className) {
    var consoleDiv = document.querySelector('.gdb-console');
    var node = document.createElement('span');
    node.className = className;
    node.appendChild(document.createTextNode(contents));
    consoleDiv.appendChild(node);
    node.scrollIntoView();
    }

  let sourceEditor = document.querySelector('#source-editor>pre>code');
  let assemblyEditor = document.querySelector('#assembly-editor>pre>code');

  var socket = new WebSocket('ws://localhost:8001');
  var currentFrame = {
    fullname : null,
    line : null,
    address : null,
  };
  var payloadCount = 0;
  var promiseMapping = {};

  function socketSend(payload) {
    payload.token = ++payloadCount;
    socket.send(JSON.stringify(payload));
    promiseMapping[payload.token] = new Deferred();
    return promiseMapping[payload.token].promise;
    }
  var sourceCache = {};
  function onSourceReady() {
    sourceEditor.innerText = sourceCache[currentFrame.fullname];
    document.querySelector('#source-editor>pre')
        .setAttribute('data-line', currentFrame.line);
    Prism.highlightElement(sourceEditor);
    document.querySelector('#source-editor .line-highlight').scrollIntoView();
    }
  function onAssemblyReady(currentAddress, insns) {
    var contents = '';
    var activeLine = 0;
    for (var i = 0; i < insns.length; i++) {
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
    var startAddress = parseInt(insns[0].address.substr(2), 16);
    var endAddress = parseInt(insns[insns.length - 1].address.substr(2), 16);
    socketSend({
      method : 'disassemble-graph',
      startAddress : startAddress,
      endAddress : endAddress
    }).then(function(record) { renderGraph(record); });
    }
  function onThreadSelected(frame) {
    currentFrame = frame;
    var cmd = '-data-disassemble -f ' + currentFrame.fullname + ' -l ' +
              currentFrame.line + ' -n -1 -- 0';
    socketSend({method : 'run', 'command' : cmd}).then(function(record) {
      onAssemblyReady(currentFrame.addr, record.asm_insns);
    });
    socketSend({
      method : 'run',
      'command' : '-data-list-register-values --skip-unavailable x'
    }).then(function(record) {
      var registersElement = document.querySelector('#registers tbody');
      while (registersElement.firstChild) {
        registersElement.removeChild(registersElement.firstChild);
        }
      for (var i = 0; i < record['register-values'].length; i++) {
        var reg = record['register-values'][i];
        if (parseInt(reg.number) > registerNames.length) {
          continue;
          }
        var rowElement = document.createElement('tr');
        var cellElement = document.createElement('td');
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
      var stackElement = document.querySelector('#stack tbody');
      while (stackElement.firstChild) {
        stackElement.removeChild(stackElement.firstChild);
        }
      let offset = -128;
      for (let entry of record['memory']) {
        var rowElement = document.createElement('tr');
        var cellElement = document.createElement('td');
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
    var data = JSON.parse(event.data);
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
  var registerNames = [];
  socket.onopen = function(event) {
    socketSend({method : 'run', 'command' : '-data-list-register-names'})
        .then(function(record) {
          Array.prototype.push.apply(registerNames, record['register-names']);
          socketSend({method : 'run', 'command' : '-thread-info'})
              .then(function(record) {
                for (var i = 0; i < record.threads.length; ++i) {
                  if (record.threads[i].id != record['current-thread-id'])
                    continue;
                  onThreadSelected(record.threads[i].frame);
                }
              });
        });
  };

  var cmdHistory = [];
  var cmdHistoryIdx = 0;
  document.querySelector('#gdb-console')
      .addEventListener('submit', function(ev) {
        ev.preventDefault();
        var cmd = document.querySelector('#gdb-console input').value;
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
          document.getElementById('svg').style.display = 'block';
          document.getElementById('source-editor').style.display = 'none';
        } else {
          document.getElementById('svg').style.display = 'none';
          document.getElementById('source-editor').style.display = 'block';
        }
      });
}

document.addEventListener('DOMContentLoaded', main, false);
// vim: set expandtab:ts=2:sw=2
