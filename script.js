function Deferred() {
  this.resolve = null;
  this.reject = null;
  this.promise = new Promise(
    function(resolve, reject) {
      this.resolve = resolve;
      this.reject = reject;
    }.bind(this)
  );
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
  comment: /#.*/,
  immediate: {
    pattern: /\$0x[0-9a-fA-F]+/,
    alias: 'number',
  },
  register: {
    pattern: /%[a-z0-9]+/,
    alias: 'function',
  },
  'source-address': {
    pattern: /^[0-9a-fA-F]+/m,
    alias: 'string',
  },
  address: {
    pattern: /-?0x[0-9a-fA-F]+/,
    alias: 'string',
  },
  symbol: /<.*>/,
  opcode: {
    pattern: /[a-z][a-z0-9.]+/,
    alias: 'keyword',
  },
  number: /[0-9]+/,
  operator: /[(),]/,
};

Prism.hooks.add('after-highlight', function(env) {
  if (env.language != 'assembly') {
    return;
  }
  let sourceAddressRegexp = /\bsource-address\b/;
  env.element.addEventListener('click', function(ev) {
    if (!sourceAddressRegexp.test(ev.target.className)) {
      return;
    }
    ev.target.dispatchEvent(
      new CustomEvent('source-address', {
        bubbles: true,
        detail: {
          address: parseInt(ev.target.innerText.trim(), 16),
        },
      })
    );
  });
});

class GraphView {
  constructor(svg) {
    this.svg = svg;
    this.visible = false;
    this.maxWidth = this.svg.clientWidth;
    this.maxHeight = this.svg.clientHeight;
    this.miniViewScale = 1.0;
    this.highlightedAddress = null;
    this.viewport = {
      x: 0,
      y: 0,
      scale: 1.0,
    };
    this.mousedown = false;
    this.mousemoved = false;
    this.mouseanchor = null;
    this.svg.addEventListener('wheel', ev => this.__onWheel(ev));
    this.svg.addEventListener('mousemove', ev => this.__onMouseMove(ev));
    this.svg.addEventListener('mousedown', ev => this.__onMouseDown(ev));
    this.svg.addEventListener('mouseup', ev => this.__onMouseUp(ev));

    this.viewportMousedown = false;
    let miniViewViewport = this.svg.querySelector('#MiniView rect.viewport');
    miniViewViewport.addEventListener('mousedown', ev =>
      this.__viewportOnMouseDown(ev)
    );

    this.instructionSpans = {};
    this.instructionNodes = {};
    this.debug = false;
    this.graph = new Graph();
  }

  show() {
    this.svg.style.display = 'block';
    window.requestAnimationFrame(() => {
      this.visible = true;
      this.maxWidth = this.svg.clientWidth;
      this.maxHeight = this.svg.clientHeight;
      this.viewport = {
        x: 0,
        y: 0,
        scale: 1.0,
      };
      this.__render(this.data);
      if (this.highlightedAddress) {
        this.__highlight(this.highlightedAddress, true);
        this.__scrollIntoView(this.highlightedAddress);
      }
    });
  }

  hide() {
    this.svg.style.display = 'none';
    this.visible = false;
  }

  render(data) {
    this.data = data;
    this.dirty = true;
    this.highlightedAddress = null;
    if (!this.visible) {
      return;
    }
    this.__render(this.data);
  }

  highlight(address) {
    this.highlightedAddress = address;
    if (this.dirty) {
      return;
    }
    this.__highlight(this.highlightedAddress, true);
  }

  scrollIntoView(address) {
    if (!this.visible) {
      return;
    }
    this.__highlight(address, false);
    this.__scrollIntoView(address);
  }

  __render(data) {
    if (!this.dirty) {
      return;
    }
    this.dirty = false;
    let offsetY = 20;
    let blocks = {};
    let graphNode = document.querySelector('#ProgramControlFlowGraph');
    while (graphNode.lastChild) {
      graphNode.removeChild(graphNode.lastChild);
    }
    let nodes = [];
    this.instructionSpans = {};
    this.graph.clear();
    for (const addr in data) {
      const block = data[addr];
      let blockElm = createSVGNode('g');
      nodes.push(blockElm);
      blockElm.classList.add('block');
      let addressWidth = 0;
      let mnemonicWidth = 0;
      let opWidth = 0;
      for (const ins of block.instructions) {
        addressWidth = Math.max(addressWidth, ins.address.length);
        mnemonicWidth = Math.max(mnemonicWidth, ins.mnemonic.length);
        opWidth = Math.max(opWidth, ins.op.length);
      }

      for (let i = 0; i < block.instructions.length; i++) {
        let ins = block.instructions[i];

        let blockTextElm = createSVGNode('text', {
          x: 0,
          y: i + 'em',
        });
        let address = parseInt(ins.address, 16);
        this.instructionSpans[address] = blockTextElm;
        this.instructionNodes[address] = addr;

        let addressSpan = createSVGNode('tspan');
        addressSpan.setAttribute('class', 'address');
        addressSpan.appendChild(document.createTextNode(ins.address));
        blockTextElm.appendChild(addressSpan);

        let mnemonicSpan = createSVGNode('tspan', {
          x: addressWidth + 2 + 'ex',
        });
        mnemonicSpan.setAttribute('class', 'mnemonic');
        mnemonicSpan.appendChild(document.createTextNode(ins.mnemonic));
        blockTextElm.appendChild(mnemonicSpan);

        let registerSpan = createSVGNode('tspan', {
          x: addressWidth + mnemonicWidth + 5 + 'ex',
        });
        registerSpan.setAttribute('class', 'register');
        registerSpan.appendChild(document.createTextNode(ins.op));
        blockTextElm.appendChild(registerSpan);

        blockElm.appendChild(blockTextElm);
      }

      // Add the block to the svg graph node just to be able to get its
      // bounding box.
      graphNode.appendChild(blockElm);
      const blockTextBBox = blockElm.getBBox();
      graphNode.removeChild(blockElm);

      let rectElm = createSVGNode('rect', {
        x: blockTextBBox.x - 5,
        y: blockTextBBox.y - 5,
        width: blockTextBBox.width + 10,
        height: blockTextBBox.height + 10,
      });
      rectElm.setAttribute('class', 'block');
      blockElm.insertBefore(rectElm, blockElm.firstChild);
      blocks[addr] = {
        label: addr,
        width: blockTextBBox.width + 10,
        height: blockTextBBox.height + 10,
        element: blockElm,
      };
      this.graph.setNode(addr, blocks[addr]);
      for (let i = 0; i < block.edges.length; i++) {
        this.graph.setEdge(addr, block.edges[i].target, {
          type: block.edges[i].type,
        });
      }
    }

    if (!this.graph.nodes.length) {
      return;
    }

    this.graph.layout();
    let minX = 1e99;
    for (let block of this.graph.nodes) {
      minX = Math.min(minX, block.x);
    }
    for (let edge of this.graph.edges) {
      for (let point of edge.points) {
        minX = Math.min(minX, point.x);
      }
    }

    for (let block of this.graph.nodes) {
      block.element.setAttributeNS(
        null,
        'transform',
        'translate(' + (5 + block.x - minX) + ', ' + (18 + block.y) + ')'
      );
      if (this.debug) {
        let rectElm = createSVGNode('rect', {
          x: block.subtreeBBox.x - minX,
          y: block.subtreeBBox.y,
          width: block.subtreeBBox.width,
          height: block.subtreeBBox.height,
        });
        rectElm.setAttribute('class', 'bounding-box');
        nodes.push(rectElm);
      }
    }
    for (let edge of this.graph.edges) {
      let points = '';
      for (let i = 0; i < edge.points.length; i++) {
        if (i == 0) {
          points += 'M';
        } else {
          points += 'L';
        }
        points += edge.points[i].x - minX;
        points += ',' + edge.points[i].y;
      }
      let lineElm = createSVGNode('path', {
        d: points,
      });
      lineElm.setAttribute(
        'class',
        'edge ' + edge.type + (edge.back ? ' back-edge' : '')
      );
      nodes.push(lineElm);
      edge.element = lineElm;
    }

    // With everything laid out, we can now add everything back.
    for (const node of nodes) {
      graphNode.appendChild(node);
    }
    this.maxWidth = graphNode.getBBox().width;
    this.maxHeight = graphNode.getBBox().height;

    // Update miniview.
    const maxMiniViewSize = 200;
    this.miniViewScale = this.maxWidth > this.maxHeight
      ? maxMiniViewSize / this.maxWidth
      : maxMiniViewSize / this.maxHeight;
    let miniViewWidth = this.maxWidth * this.miniViewScale;
    let miniViewHeight = this.maxHeight * this.miniViewScale;
    let miniViewRect = this.svg.querySelector('#MiniView rect.background');
    miniViewRect.setAttribute('x', this.svg.clientWidth - miniViewWidth - 22);
    miniViewRect.setAttribute('y', this.svg.clientHeight - miniViewHeight - 22);
    miniViewRect.setAttribute('width', miniViewWidth + 22);
    miniViewRect.setAttribute('height', miniViewHeight + 22);
    this.svg
      .querySelector('#MiniView use')
      .setAttribute(
        'transform',
        'translate(' +
          (this.svg.clientWidth - miniViewWidth - 12) +
          ' ' +
          (this.svg.clientHeight - miniViewHeight - 12) +
          '),scale(' +
          this.miniViewScale +
          ' ' +
          this.miniViewScale +
          ')'
      );
    this.viewport.x = 0;
    this.viewport.y = 0;
    this.viewport.scale = Math.max(
      this.svg.clientWidth / this.maxWidth,
      this.svg.clientHeight / this.maxHeight,
      1.0
    );
    this.__updateViewBox();
  }

  __highlight(address, moveArrow) {
    let highlightElement = this.svg.querySelector(
      '#instruction-highlight rect'
    );
    for (let previous of this.svg.querySelectorAll('g.current')) {
      previous.classList.remove('current');
    }
    for (let previous of this.svg.querySelectorAll('g.reachable')) {
      previous.classList.remove('reachable');
    }
    for (let activePath of this.svg.querySelectorAll('path.active')) {
      activePath.classList.remove('active');
    }
    if (address === null || !this.instructionSpans.hasOwnProperty(address)) {
      this.svg.classList.add('unselected');
      highlightElement.setAttribute('opacity', 0);
      return;
    }
    this.svg.classList.remove('unselected');
    highlightElement.setAttribute('opacity', 1.0);

    let element = this.instructionSpans[address];
    let elementBBox = element.getBoundingClientRect();

    let node = this.graph.getNode(this.instructionNodes[address]);
    node.element.classList.add('current');
    for (let edge of node.inEdges) {
      edge.element.classList.add('active');
      this.graph.getNode(edge.from).element.classList.add('reachable');
    }
    for (let edge of node.outEdges) {
      edge.element.classList.add('active');
      this.graph.getNode(edge.to).element.classList.add('reachable');
    }

    highlightElement.setAttribute('x', elementBBox.left);
    highlightElement.setAttribute('y', elementBBox.top + 1);
    highlightElement.setAttribute(
      'width',
      element.parentElement.getBoundingClientRect().width - 10
    );
    highlightElement.setAttribute('height', elementBBox.height - 2);

    if (moveArrow) {
      element.setAttribute('class', 'highlight');
      let highlightArrow = this.svg.querySelector(
        '#instruction-highlight path'
      );
      let highlightArrowBBox = highlightArrow.getBBox();
      highlightArrow.setAttribute(
        'transform',
        'translate(' +
          (elementBBox.left - highlightArrowBBox.width - 8) +
          ', ' +
          (elementBBox.top +
            (elementBBox.height - highlightArrowBBox.height) / 2.0) +
          ')'
      );
    }
  }

  __scrollIntoView(address) {
    let element = this.instructionSpans[address];
    if (!element) {
      return;
    }
    let elementBBox = element.getBoundingClientRect();
    let elementBBoxWidth =
      element.parentElement.getBoundingClientRect().width - 10;
    this.__moveViewport(
      elementBBox.left + elementBBoxWidth / 2.0 - this.svg.clientWidth / 2.0,
      elementBBox.top + elementBBox.height / 2.0 - this.svg.clientHeight / 2.0
    );
    this.__updateViewBox();
  }

  __moveViewport(x, y) {
    this.viewport.x = Math.max(
      0,
      Math.min(x, this.maxWidth - this.svg.clientWidth / this.viewport.scale)
    );
    this.viewport.y = Math.max(
      0,
      Math.min(y, this.maxHeight - this.svg.clientHeight / this.viewport.scale)
    );
  }

  __onWheel(ev) {
    let oldScale = this.viewport.scale;
    this.viewport.scale = Math.max(
      Math.min(
        this.svg.clientWidth / this.maxWidth,
        this.svg.clientHeight / this.maxHeight
      ),
      Math.min(this.viewport.scale + ev.wheelDelta / 1200.0, 1.0)
    );
    if (oldScale == this.viewport.scale) {
      return;
    }
    this.__moveViewport(
      this.viewport.x +
        ev.offsetX / oldScale -
        ev.offsetX / this.viewport.scale,
      this.viewport.y + ev.offsetY / oldScale - ev.offsetY / this.viewport.scale
    );
    this.__updateViewBox();
  }

  __onMouseMove(ev) {
    if (!this.mousedown) return;
    ev.preventDefault();
    this.mousemoved = true;
    if (this.viewportMousedown) {
      this.__moveViewport(
        this.viewport.x +
          (ev.offsetX - this.mouseanchor.x) / this.miniViewScale,
        this.viewport.y + (ev.offsetY - this.mouseanchor.y) / this.miniViewScale
      );
    } else {
      this.__moveViewport(
        this.viewport.x -
          (ev.offsetX - this.mouseanchor.x) / this.viewport.scale,
        this.viewport.y -
          (ev.offsetY - this.mouseanchor.y) / this.viewport.scale
      );
    }
    this.__updateViewBox();
    this.mouseanchor = {
      x: ev.offsetX,
      y: ev.offsetY,
    };
  }

  __onMouseDown(ev) {
    ev.preventDefault();
    this.mousedown = true;
    this.mousemoved = false;
    this.mouseanchor = {
      x: ev.offsetX,
      y: ev.offsetY,
    };
  }

  __findAddressAtCoordinates(x, y) {
    for (let address of Object.keys(this.instructionSpans)) {
      let element = this.instructionSpans[address];
      let elementBBox = element.getBoundingClientRect();
      let elementBBoxWidth =
        element.parentElement.getBoundingClientRect().width - 10;

      if (
        elementBBox.left <= x &&
        x <= elementBBox.left + elementBBoxWidth &&
        (elementBBox.top <= y && y <= elementBBox.bottom)
      ) {
        return address;
      }
    }
    return null;
  }

  __onMouseUp(ev) {
    ev.preventDefault();
    if (!this.mousemoved) {
      let clickedAddress = this.__findAddressAtCoordinates(
        this.mouseanchor.x / this.viewport.scale + this.viewport.x,
        this.mouseanchor.y / this.viewport.scale + this.viewport.y
      );
      this.__highlight(clickedAddress);
    }
    this.mousedown = false;
    this.mouseanchor = null;
    this.viewportMousedown = false;
  }

  __viewportOnMouseDown(ev) {
    ev.preventDefault();
    this.viewportMousedown = true;
  }

  __updateViewBox() {
    let mainTransform =
      'translate(' +
      -this.viewport.x * this.viewport.scale +
      ', ' +
      -this.viewport.y * this.viewport.scale +
      '),scale(' +
      this.viewport.scale +
      ' ' +
      this.viewport.scale +
      ')';
    this.svg
      .querySelector('#MainView')
      .setAttribute('transform', mainTransform);

    this.svg
      .querySelector('#instruction-highlight')
      .setAttribute('transform', mainTransform);
    let miniViewRect = this.svg.querySelector('#MiniView rect.viewport');
    let miniViewOffsetX =
      this.svg.clientWidth - this.maxWidth * this.miniViewScale - 12;
    let miniViewOffsetY =
      this.svg.clientHeight - this.maxHeight * this.miniViewScale - 12;
    let miniViewViewportWidth =
      Math.min(this.svg.clientWidth / this.viewport.scale, this.maxWidth) *
      this.miniViewScale;
    let miniViewViewportHeight =
      Math.min(this.svg.clientHeight / this.viewport.scale, this.maxHeight) *
      this.miniViewScale;
    miniViewRect.setAttribute(
      'x',
      miniViewOffsetX + this.viewport.x * this.miniViewScale
    );
    miniViewRect.setAttribute(
      'y',
      miniViewOffsetY + this.viewport.y * this.miniViewScale
    );
    miniViewRect.setAttribute('width', miniViewViewportWidth);
    miniViewRect.setAttribute('height', miniViewViewportHeight);
  }
}

class Machine {
  constructor() {
    this.isa = undefined;
    this.bits = undefined;
    this.registers = [];
  }

  set registerNames(registers) {
    Array.prototype.push.apply(this.registers, registers);
    if (registers.indexOf('rip') !== -1) {
      this.isa = 'x86_64';
      this.bits = 64;
    } else if (registers.indexOf('eip') !== -1) {
      this.isa = 'x86';
      this.bits = 32;
    } else if (registers.indexOf('x0') !== -1) {
      this.isa = 'aarch64';
      this.bits = 64;
    } else if (registers.indexOf('r0') !== -1) {
      this.isa = 'arm';
      this.bits = 32;
    } else {
      console.error('unknown architecture');
    }
  }

  get registerNames() {
    return this.registers;
  }

  get stackRedZone() {
    if (typeof this.isa === 'undefined') {
      throw new Error('Machine not initialized');
    }
    if (this.isa == 'x86_64') {
      return 128;
    }
    return 0;
  }

  get stackRegister() {
    if (typeof this.isa === 'undefined') {
      throw new Error('Machine not initialized');
    }
    switch (this.isa) {
      case 'x86_64':
        return 'rsp';
      case 'x86':
        return 'esp';
      case 'aarch64':
      case 'arm':
        return 'sp';
    }
  }

  get registerWidth() {
    if (typeof this.isa === 'undefined') {
      throw new Error('Machine not initialized');
    }
    if (this.bits == 64) {
      return 8;
    }
    return 4;
  }

  get gdbStackCommand() {
    return (
      '-data-read-memory $' +
      this.stackRegister +
      '-' +
      this.stackRedZone +
      ' x ' +
      this.registerWidth +
      ' 100 1'
    );
  }
}

function main() {
  let payload = JSON.parse(atob(window.location.hash.substring(1)));
  let graph = new GraphView(document.getElementById('svg'));

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
  let machine = new Machine();

  let socket = new WebSocket('ws://localhost:' + payload.websocketPort);
  let currentFrame = {
    fullname: null,
    line: null,
    address: null,
  };
  let currentThread = null;
  let payloadCount = 0;
  let promiseMapping = {};

  function socketSend(payload) {
    payload.token = ++payloadCount;
    socket.send(JSON.stringify(payload));
    promiseMapping[payload.token] = new Deferred();
    return promiseMapping[payload.token].promise;
  }
  let sourceCache = {};
  let threads = {};
  function onSourceReady() {
    const sourcePath = currentFrame.fullname || '<unknown>';
    sourceEditor.innerText = sourceCache[sourcePath] || '';
    if (sourceEditor.innerText) {
      document
        .querySelector('#source-editor>pre')
        .setAttribute('data-line', currentFrame.line);
    } else {
      document
        .querySelector('#source-editor>pre')
        .setAttribute('data-line', '');
    }
    if (sourcePath.endsWith('java')) {
      document.querySelector('#source-editor>pre>code').className =
        'language-java';
    } else if (sourcePath.endsWith('cpp') || sourcePath.endsWith('cc')) {
      document.querySelector('#source-editor>pre>code').className =
        'language-cpp';
    } else if (sourcePath.endsWith('c')) {
      document.querySelector('#source-editor>pre>code').className =
        'language-c';
    } else {
      console.log('Unknown language for ' + sourcePath + '. defaulting to C++');
      document.querySelector('#source-editor>pre>code').className = '';
    }
    Prism.highlightElement(sourceEditor);
    if (sourceEditor.innerText) {
      document.querySelector('#source-editor .line-highlight').scrollIntoView();
    }
  }
  function onStackReady(frames, currentFrameIndex) {
    let framesElement = document.querySelector('select[name="frame"]');
    while (framesElement.firstChild) {
      framesElement.removeChild(framesElement.firstChild);
    }
    for (const frame of frames) {
      let frameElement = document.createElement('option');
      frameElement.value = frame.level;
      frameElement.appendChild(
        document.createTextNode(frame.fullname + ':' + frame.line)
      );
      if (parseInt(frame.level) == currentFrameIndex) {
        frameElement.selected = 'selected';
      }
      framesElement.appendChild(frameElement);
    }
  }
  function onAssemblyReady(currentAddress, insns) {
    let contents = '';
    let activeLine = 0;
    for (let i = 0; i < insns.length; i++) {
      contents += insns[i].address.substring(2) + ' ' + insns[i].inst + '\n';
      if (insns[i].address == currentAddress) {
        activeLine = i;
      }
    }
    assemblyEditor.innerText = contents;
    document
      .querySelector('#assembly-editor>pre')
      .setAttribute('data-line', activeLine + 1);
    Prism.highlightElement(assemblyEditor);
    document.querySelector('#assembly-editor .line-highlight').scrollIntoView();
    if (insns.length == 0) {
      graph.render({});
      return;
    }

    let startAddress = parseInt(insns[0].address.substr(2), 16);
    let endAddress = parseInt(insns[insns.length - 1].address.substr(2), 16);
    socketSend({
      method: 'disassemble-graph',
      isa: machine.isa,
      startAddress: startAddress,
      endAddress: endAddress,
    }).then(record => {
      graph.render(record);
      let address = parseInt(currentAddress.substring(2), 16);
      graph.highlight(address);
      graph.scrollIntoView(address);
    });
  }
  function onThreadSelected(selectedThread, selectedFrame) {
    currentThread = selectedThread;
    currentFrame = selectedFrame;
    if (currentFrame.fullname) {
      let cmd =
        '-data-disassemble -f ' +
        currentFrame.fullname +
        ' -l ' +
        currentFrame.line +
        ' -n -1 -- 0';
      socketSend({ method: 'run', command: cmd }).then(function(record) {
        onAssemblyReady(currentFrame.addr, record.asm_insns);
      });
    } else {
      onAssemblyReady(currentFrame.addr, []);
    }
    socketSend({
      method: 'run',
      command: '-data-list-register-values --skip-unavailable x',
    }).then(function(record) {
      let registersElement = document.querySelector('#registers tbody');
      while (registersElement.firstChild) {
        registersElement.removeChild(registersElement.firstChild);
      }
      for (let i = 0; i < record['register-values'].length; i++) {
        let reg = record['register-values'][i];
        if (parseInt(reg.number) > machine.registerNames.length) {
          continue;
        }
        let rowElement = document.createElement('tr');
        let cellElement = document.createElement('td');
        cellElement.appendChild(
          document.createTextNode(machine.registerNames[parseInt(reg.number)])
        );
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(reg.value));
        rowElement.appendChild(cellElement);
        registersElement.appendChild(rowElement);
      }
    });
    socketSend({
      method: 'run',
      command: machine.gdbStackCommand,
    }).then(function(record) {
      let stackElement = document.querySelector('#stack tbody');
      while (stackElement.firstChild) {
        stackElement.removeChild(stackElement.firstChild);
      }
      let offset = -machine.stackRedZone;
      for (let entry of record['memory']) {
        let rowElement = document.createElement('tr');
        let cellElement = document.createElement('td');

        cellElement.appendChild(document.createTextNode(entry.addr));
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');

        cellElement.className = 'right';
        cellElement.appendChild(document.createTextNode(offset.toString(16)));
        offset += machine.registerWidth;
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(entry.data[0]));
        rowElement.appendChild(cellElement);
        stackElement.appendChild(rowElement);
      }
    });
    if (threads[selectedThread.id].stack !== null) {
      onStackReady(
        threads[selectedThread.id].stack,
        parseInt(currentFrame.level)
      );
    } else {
      socketSend({
        method: 'run',
        command: '-stack-list-frames',
      }).then(function(record) {
        threads[selectedThread.id].stack = record.stack;
        onStackReady(
          threads[selectedThread.id].stack,
          parseInt(currentFrame.level)
        );
      });
    }
    if (!currentFrame.fullname) {
      sourceCache[currentFrame.fullname] = '';
    }
    if (sourceCache.hasOwnProperty(currentFrame.fullname)) {
      onSourceReady();
    } else {
      socketSend({
        method: 'get-source',
        filename: currentFrame.fullname,
      }).then(function(record) {
        sourceCache[currentFrame.fullname] = record || '';
        onSourceReady();
      });
    }
  }
  socket.onmessage = function(event) {
    let data = JSON.parse(event.data);
    if (data.type == 'console-stream') {
      appendConsoleNode(data.payload, 'console');
    } else if (data.type == 'log-stream') {
      appendConsoleNode(data.payload, 'log');
    } else if (data.type == 'error-stream') {
      appendConsoleNode(data.payload, 'error');
    } else if (
      data.type == 'notify-async' &&
      data['class'] == 'thread-selected'
    ) {
      onThreadSelected(data.output, data.output.frame);
    } else if (data.type == 'result') {
      if (
        typeof data.token === 'undefined' ||
        !promiseMapping.hasOwnProperty(data.token)
      )
        return;
      promiseMapping[data.token].resolve(data.record);
      delete promiseMapping[data.token];
    } else {
      console.log(data);
    }
  };
  socket.onerror = function(event) {
    console.error(event);
  };
  socket.onopen = function(event) {
    socketSend({ method: 'run', command: '-data-list-register-names' })
      .then(function(record) {
        machine.registerNames = record['register-names'];
        return socketSend({ method: 'run', command: '-thread-info' });
      })
      .then(function(record) {
        let activeThread = null;
        let threadSelect = document.querySelector('select[name="thread"]');
        for (const thread of record.threads) {
          let threadElement = document.createElement('option');
          threadElement.value = thread.id;
          threads[thread.id] = {
            id: thread.id,
            name: thread['target-id'],
            defaultFrame: thread.frame,
            stack: null,
          };
          let threadName = thread['target-id'];
          if (thread.id == record['current-thread-id']) {
            activeThread = thread;
            threadElement.selected = 'selected';
            threadName = '* ' + threadName;
          } else {
            threadName = '\u00A0 ' + threadName;
          }
          threadElement.appendChild(document.createTextNode(threadName));
          threadSelect.appendChild(threadElement);
        }
        onThreadSelected(activeThread, activeThread.frame);
      });
  };
  assemblyEditor.addEventListener('source-address', function(ev) {
    graph.scrollIntoView(ev.detail.address);
  });

  let cmdHistory = [];
  let cmdHistoryIdx = 0;
  document
    .querySelector('#gdb-console')
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
      socketSend({ method: 'run', command: cmd });
    });

  document
    .querySelector('#gdb-console input')
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

  function setView(value) {
    let viewElement = document.querySelector(
      '#gdb-console select[name="view"]'
    );
    if (viewElement.value != value) {
      viewElement.value = value;
    }
    if (value == 'graph') {
      graph.show();
      document.getElementById('source-editor').style.display = 'none';
    } else {
      graph.hide();
      document.getElementById('source-editor').style.display = 'block';
      window.requestAnimationFrame(onSourceReady);
    }
    if (value == preferences.view) {
      return;
    }
    preferences.view = value;
    window.localStorage.setItem('preferences', JSON.stringify(preferences));
  }

  function setThread(value) {
    let threadIndex = parseInt(value);
    socketSend({
      method: 'run',
      command: '-thread-select ' + threadIndex,
    }).then(function(record) {
      onThreadSelected(threads[threadIndex], threads[threadIndex].defaultFrame);
    });
  }

  function setFrame(value) {
    let frameIndex = parseInt(value);
    socketSend({
      method: 'run',
      command: '-stack-select-frame ' + frameIndex,
    }).then(function(record) {
      onThreadSelected(
        currentThread,
        threads[currentThread.id].stack[frameIndex]
      );
    });
  }

  document
    .querySelector('#gdb-console select[name="view"]')
    .addEventListener('change', ev => setView(ev.target.value));
  document
    .querySelector('#gdb-console select[name="thread"]')
    .addEventListener('change', ev => setThread(ev.target.value));
  document
    .querySelector('#gdb-console select[name="frame"]')
    .addEventListener('change', ev => setFrame(ev.target.value));

  // Restore preferences.
  let preferences = JSON.parse(
    window.localStorage.getItem('preferences') || '{"view":"source"}'
  );
  setView(preferences.view);

  document.querySelector('#gdb-console input').focus();
}

document.addEventListener('DOMContentLoaded', main, false);
// vim: set expandtab:ts=2:sw=2
