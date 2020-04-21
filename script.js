'use strict';

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
  identifier: {
    pattern: /\{[a-z_][a-z0-9_]*\}/,
    alias: 'tag',
  },
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
      if (
        this.maxWidth != this.svg.clientWidth ||
        this.maxHeight != this.svg.clientHeight
      ) {
        this.dirty = true;
      }
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

  __getBoundingRect(element) {
    let elementBBox = element.getBoundingClientRect();
    let svgBBox = this.svg.getBoundingClientRect();
    elementBBox.x -= svgBBox.x;
    elementBBox.y -= svgBBox.y;
    return elementBBox;
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
    if (!this.svg.clientWidth || !this.svg.clientHeight) return;
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
    let elementBBox = this.__getBoundingRect(element);

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

    highlightElement.setAttribute('x', elementBBox.x);
    highlightElement.setAttribute('y', elementBBox.y + 1);
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
          (elementBBox.x - highlightArrowBBox.width - 8) +
          ', ' +
          (elementBBox.y +
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
    let elementBBox = this.__getBoundingRect(element);
    let elementBBoxWidth =
      element.parentElement.getBoundingClientRect().width - 10;
    this.__moveViewport(
      elementBBox.x + elementBBoxWidth / 2.0 - this.svg.clientWidth / 2.0,
      elementBBox.y + elementBBox.height / 2.0 - this.svg.clientHeight / 2.0
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
      let elementBBox = this.__getBoundingRect(element);
      let elementBBoxWidth =
        element.parentElement.getBoundingClientRect().width - 10;

      if (
        elementBBox.x <= x &&
        x <= elementBBox.x + elementBBoxWidth &&
        (elementBBox.y <= y && y <= elementBBox.y + elementBBox.height)
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
      this.svg.dispatchEvent(
        new CustomEvent('address-selected', {
          bubbles: true,
          detail: {
            address: clickedAddress ? parseInt(clickedAddress) : null,
          },
        })
      );
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
  let machine = new Machine();
  let threads = {};
  let currentFrame = {
    fullname: null,
    func: null,
    line: null,
    address: null,
  };
  let symbolTable =
      JSON.parse(window.localStorage.getItem('symbolTable') || '{}');
  let currentThread = null;
  let functionBounds = null;

  let socket = new WebSocket(`ws://localhost:${payload.websocketPort}`);
  let payloadCount = 0;
  let promiseMapping = {};
  function socketSend(payload) {
    payload.token = ++payloadCount;
    socket.send(JSON.stringify(payload));
    promiseMapping[payload.token] = new Deferred();
    return promiseMapping[payload.token].promise;
  }
  socket.onmessage = function(event) {
    let data = JSON.parse(event.data);
    if (data.type == 'console-stream') {
      layout.eventHub.emit('consoleAdded', data.payload, 'console');
    } else if (data.type == 'log-stream') {
      layout.eventHub.emit('consoleAdded', data.payload, 'log');
    } else if (data.type == 'error-stream') {
      layout.eventHub.emit('consoleAdded', data.payload, 'error');
    } else if (
      data.type == 'notify-async' &&
      data['class'] == 'thread-selected'
    ) {
      layout.eventHub.emit('threadSelected', data.output, data.output.frame);
    } else if (data.type == 'result') {
      if (
        typeof data.token === 'undefined' ||
        !promiseMapping.hasOwnProperty(data.token)
      )
        return;
      promiseMapping[data.token].resolve(data.record);
      delete promiseMapping[data.token];
    } else {
      console.log(`unknown data type: ${data.type}`, data);
    }
  };
  socket.onerror = function(event) {
    console.error(event);
  };
  socket.onopen = function(event) {
    socketSend({ method: 'run', command: '-data-list-register-names' })
      .then(record => {
        machine.registerNames = record['register-names'];
        return socketSend({ method: 'run', command: '-thread-info' });
      })
      .then(record => {
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
        layout.eventHub.emit(
          'threadSelected',
          activeThread,
          activeThread.frame
        );
      });
  };

  function getFunctionBounds(func) {
    function _boundsFor(func) {
      if (!functionBounds.hasOwnProperty(func)) {
        console.error(`could not find bounds for ${func}. Guesstimating 1024 bytes`);
        return {
          start: `"${func}"`,
          end: `"${func} + 1024"`,
        };
      }
      return functionBounds[func];
    }

    if (functionBounds !== null) {
      return Promise.resolve(_boundsFor(func));
    }
    return socketSend({
             method : 'info-functions',
           })
        .then(record => {
          functionBounds = {};

          let lastAddress = BigInt('0xffffffffffffffff');
          for (const functionRecord of record.reverse()) {
            let currentAddress = BigInt(functionRecord.address);
            const length =
                Math.min(131072, Number(lastAddress - currentAddress));
            lastAddress = currentAddress;
            functionBounds[functionRecord.name] = {
              start : functionRecord.address,
              end : `0x${(currentAddress + BigInt(length)).toString(16)}`,
            };
          }

          return _boundsFor(func);
        });
  }

  const goldenLayoutSettings = {
    content: [
      {
        type: 'column',
        content: [
          {
            type: 'row',
            content: [
              {
                type: 'component',
                componentName: 'control-flow-graph',
                componentState: {},
                id: 'control-flow-graph',
                title: 'Control Flow Graph',
                isCloseable: false,
              },
              {
                type: 'column',
                content: [
                  {
                    type: 'component',
                    componentName: 'source-editor',
                    componentState: {},
                    id: 'source-editor',
                    title: 'Source',
                    isCloseable: false,
                  },
                  {
                    type: 'component',
                    componentName: 'disassembly',
                    componentState: {},
                    id: 'disassembly',
                    title: 'Disassembly',
                    isCloseable: false,
                  },
                ],
              },
              {
                type: 'column',
                content: [
                  {
                    type: 'component',
                    componentName: 'registers',
                    componentState: {},
                    id: 'registers',
                    title: 'Registers',
                    isCloseable: false,
                  },
                  {
                    type: 'component',
                    componentName: 'stack',
                    componentState: {},
                    id: 'stack',
                    title: 'Stack',
                    isCloseable: false,
                  },
                ],
              },
            ],
          },
          {
            type: 'component',
            componentName: 'console',
            componentState: {},
            id: 'console',
            title: 'Console',
            isCloseable: false,
            height: 20,
          },
        ],
      },
    ],
  };

  const layout = new GoldenLayout(
    goldenLayoutSettings,
    document.getElementById('layout-root')
  );

  layout.registerComponent('control-flow-graph', function(container, state) {
    let svgNode = $(
      `<svg class="h-100 w-100" xmlns="http://www.w3.org/2000/svg"
           xmlns:xlink="http://www.w3.org/1999/xlink">
        <defs>
          <marker id="TriangleUnconditional" viewBox="0 0 10 10" refX="10" refY="5"
                   markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#77c5d1" />
          </marker>
          <marker id="TriangleFallthrough" viewBox="0 0 10 10" refX="10" refY="5"
                   markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#98c99b" />
          </marker>
          <marker id="TriangleJump" viewBox="0 0 10 10" refX="10" refY="5"
                   markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#895f63" />
          </marker>
          <g id="ProgramControlFlowGraph"></g>
        </defs>
        <use id="MainView" href="#ProgramControlFlowGraph" x="0" y="0" viewBox="0 0 500 500"/>
        <g id="MiniView" opacity="0.5">
          <rect class="background" fill-opacity="0.2"/>
          <use href="#ProgramControlFlowGraph"/>
          <rect class="viewport" fill-opacity="0.2"/>
        </g>
        <g id="instruction-highlight">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#fff" />
          <rect fill-opacity="0.2" fill="#fff" />
        </g>
      </svg>`
    );
    let graph = null;
    container.getElement().append(svgNode);
    container.on('open', () => {
      graph = new GraphView(svgNode[0]);
      graph.show();
      layout.eventHub.on('graphReady', (data, address) => {
        graph.render(data);
        if (!address) return;
        graph.highlight(address);
        graph.scrollIntoView(address);
      });
      svgNode[0].addEventListener('address-selected', ev =>
        layout.eventHub.emit('addressSelected', ev.detail.address)
      );
    });
    container.on('resize', () => {
      if (!graph) return;
      graph.show();
    });
    layout.eventHub.on('addressSelected', address => {
      if (!graph) return;
      graph.scrollIntoView(address);
    });
  });
  layout.registerComponent('source-editor', function(container, state) {
    let editorNode = $(
      `<div class="source-editor h-100 w-100">
        <pre class="line-numbers"><code class="language-cpp"></code></pre>
      </div>`
    );
    let sourcePreNode = editorNode[0].querySelector('pre');
    let sourceEditorNode = editorNode[0].querySelector('code');
    let currentSource = '';
    container.getElement().append(editorNode);

    function redraw() {
      sourceEditorNode.textContent = currentSource;
      if (currentSource) {
        sourcePreNode.setAttribute('data-line', currentFrame.line);
      } else {
        sourcePreNode.setAttribute('data-line', '');
      }
      Prism.highlightElement(sourceEditorNode);
      let highlight = sourcePreNode.querySelector('.line-highlight');
      if (highlight) highlight.scrollIntoView();
    }
    container.on('show', () => window.requestAnimationFrame(() => redraw()));

    let sourceCache = {};
    layout.eventHub.on('fileChanged', sourcePath => {
      if (!sourcePath) {
        sourcePath = '<unknown>';
        sourceCache[sourcePath] = '';
      }
      container.setTitle(sourcePath);
      if (sourceCache.hasOwnProperty(sourcePath)) {
        layout.eventHub.emit(
          'sourceReady',
          sourcePath,
          sourceCache[sourcePath]
        );
      } else {
        socketSend({
          method: 'get-source',
          filename: sourcePath,
        }).then(record => {
          sourceCache[sourcePath] = record || '';
          layout.eventHub.emit(
            'sourceReady',
            sourcePath,
            sourceCache[sourcePath]
          );
        });
      }
    });
    layout.eventHub.on('sourceReady', (sourcePath, contents) => {
      currentSource = contents;
      if (sourcePath.endsWith('java')) {
        sourceEditorNode.className = 'language-java';
      } else if (sourcePath.endsWith('cpp') || sourcePath.endsWith('cc')) {
        sourceEditorNode.className = 'language-cpp';
      } else if (sourcePath.endsWith('c')) {
        sourceEditorNode.className = 'language-c';
      } else {
        console.log(
          `Unknown language for ${sourcePath}. defaulting to C++`
        );
        sourceEditorNode.className = '';
      }
      redraw();
    });
  });
  layout.registerComponent('disassembly', function(container, state) {
    let assemblyNode = $(
      `<div class="assembly-editor w-100 h-100">
        <pre><code class="language-assembly"></code></pre>
      </div>`
    );
    let assemblyPreNode = assemblyNode[0].querySelector('pre');
    container.getElement().append(assemblyNode);
    let assemblyEditorNode = assemblyNode[0].querySelector('code');
    layout.eventHub.on('assemblyReady', (currentAddress, insns) => {
      container.setTitle(currentFrame.func || 'Disassembly');
      let replacements = symbolTable[currentFrame.func] || {};
      let contents = [];
      let activeLine = 0;
      for (let i = 0; i < insns.length; i++) {
        let instruction = insns[i].inst;
        for (const [search, replace] of Object.entries(replacements)) {
          instruction = instruction.replace(search, `${search} {${replace}}`);
        }
        contents.push(`${insns[i].address.substring(2)} ${instruction}`);
        if (insns[i].address == currentAddress) {
          activeLine = i;
        }
      }
      assemblyEditorNode.textContent = contents.join('\n');
      assemblyPreNode.setAttribute('data-line', activeLine + 1);
      Prism.highlightElement(assemblyEditorNode);
      let highlight = assemblyPreNode.querySelector('.line-highlight');
      if (highlight) highlight.scrollIntoView();
      if (insns.length == 0) {
        layout.eventHub.emit('graphReady', {}, 0);
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
        let address = parseInt(currentAddress.substring(2), 16);
        layout.eventHub.emit('graphReady', record, address);
      });
    });
    assemblyEditorNode.addEventListener('source-address', ev =>
      layout.eventHub.emit('addressSelected', ev.detail.address)
    );
    layout.eventHub.on('addressSelected', address => {
      if (address == null) return;
      const hexAddress = Number(address).toString(16);
      const addressElements = assemblyEditorNode.querySelectorAll(
        '.source-address'
      );
      for (let element of addressElements) {
        if (!element.textContent.endsWith(hexAddress)) continue;
        element.scrollIntoView();
        break;
      }
    });
  });
  layout.registerComponent('registers', function(container, state) {
    let registersNode = $(
      `<div class="registers w-100 h-100">
        <table class="w-100">
          <thead>
            <th>Register</th>
            <th>Value</th>
          </thead>
          <tbody>
          </tbody>
        </table>
      </div>`
    );
    container.getElement().append(registersNode);
    layout.eventHub.on('registersReady', record => {
      let registersElement = registersNode[0].querySelector('tbody');
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
  });
  layout.registerComponent('stack', function(container, state) {
    let stackNode = $(
      `<div class="stack w-100 h-100">
        <table class="w-100">
          <thead>
            <th>Address</th>
            <th>Offset</th>
            <th>Value</th>
          </thead>
          <tbody>
          </tbody>
        </table>
      </div>`
    );
    container.getElement().append(stackNode);
    layout.eventHub.on('stackDumpReady', record => {
      let stackElement = stackNode[0].querySelector('tbody');
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
        cellElement.appendChild(
          document.createTextNode(
            (offset >= 0 ? '0x' : '-0x') + Math.abs(offset).toString(16)
          )
        );
        offset += machine.registerWidth;
        rowElement.appendChild(cellElement);
        cellElement = document.createElement('td');
        cellElement.appendChild(document.createTextNode(entry.data[0]));
        rowElement.appendChild(cellElement);
        stackElement.appendChild(rowElement);
      }
    });
  });
  layout.registerComponent('console', function(container, state) {
    let cmdHistory = [];
    let cmdHistoryIdx = 0;

    const consoleNode = $(
      `<div class="d-flex flex-column h-100 w-100">
        <div class="gdb-console-container">
          <div class="h-100 w-100 gdb-console"></div>
        </div>
        <form class="form-inline flex-row gdb-console-input">
          <label class="p-1">(gdb) </label>
          <input type="text" name="command" autocomplete="off" class="form-control form-control-sm">
        </form>
      </div>`
    );
    const consoleElement = consoleNode[0].querySelector('.gdb-console');
    const inputElement = consoleNode[0].querySelector('input');
    const commandElement = consoleNode[0].querySelector('form');
    container.getElement().append(consoleNode);

    function appendConsoleNode(contents, className) {
      let node = document.createElement('span');
      node.className = className;
      node.appendChild(document.createTextNode(contents));
      consoleElement.appendChild(node);
      node.scrollIntoView();
    }

    commandElement.addEventListener('submit', ev => {
      ev.preventDefault();
      let inputElement = ev.target.querySelector('input');
      let cmd = inputElement.value;
      if (cmd) {
        cmdHistory.push(cmd);
        cmdHistoryIdx = cmdHistory.length;
      } else if (cmdHistory.length) {
        cmd = cmdHistory[cmdHistory.length - 1];
      } else {
        return;
      }
      layout.eventHub.emit('consoleAdded', '(gdb) ' + cmd + '\n', 'prompt');
      inputElement.value = '';
      socketSend({ method: 'run', command: cmd });
    });

    inputElement.addEventListener('keydown', ev => {
      if (ev.key == 'ArrowUp') {
        ev.preventDefault();
        if (cmdHistoryIdx > 0) {
          inputElement.value = cmdHistory[--cmdHistoryIdx];
        }
      } else if (ev.key == 'ArrowDown') {
        ev.preventDefault();
        if (cmdHistoryIdx < cmdHistory.length) {
          inputElement.value = cmdHistory[++cmdHistoryIdx] || '';
        } else {
          inputElement.value = '';
        }
      }
    });
    layout.eventHub.on('consoleAdded', appendConsoleNode);
    container.on('open', () => inputElement.focus());
  });

  layout.init();

  layout.eventHub.on('threadSelected', (selectedThread, selectedFrame) => {
    currentThread = selectedThread;
    currentFrame = selectedFrame;
    if (currentFrame.fullname) {
      let cmd = `-data-disassemble -f ${currentFrame.fullname}  -l ${
          currentFrame.line} -n -1 -- 0`;
      socketSend({ method: 'run', command: cmd }).then(record => {
        layout.eventHub.emit(
          'assemblyReady',
          currentFrame.addr,
          record.asm_insns
        );
      });
    } else if (currentFrame.func) {
      getFunctionBounds(currentFrame.func).then(bounds => {
        let cmd = `-data-disassemble -s ${bounds.start}  -e ${bounds.end} -- 0`;
        socketSend({ method: 'run', command: cmd }).then(record => {
          layout.eventHub.emit(
            'assemblyReady',
            currentFrame.addr,
            record.asm_insns
          );
        });
      });
    } else {
      layout.eventHub.emit('assemblyReady', currentFrame.addr, []);
    }
    socketSend({
      method: 'run',
      command: '-data-list-register-values --skip-unavailable x',
    }).then(record => layout.eventHub.emit('registersReady', record));
    socketSend({
      method: 'run',
      command: machine.gdbStackCommand,
    }).then(record => layout.eventHub.emit('stackDumpReady', record));
    if (threads[selectedThread.id].stack !== null) {
      layout.eventHub.emit(
        'stackReady',
        threads[selectedThread.id].stack,
        parseInt(currentFrame.level)
      );
    } else {
      socketSend({
        method: 'run',
        command: '-stack-list-frames',
      }).then(record => {
        threads[selectedThread.id].stack = record.stack;
        layout.eventHub.emit(
          'stackReady',
          threads[selectedThread.id].stack,
          parseInt(currentFrame.level)
        );
      });
    }
    layout.eventHub.emit('fileChanged', currentFrame.fullname);
  });
  layout.eventHub.on('stackReady', (frames, currentFrameIndex) => {
    let framesElement = document.querySelector('select[name="frame"]');
    while (framesElement.firstChild) {
      framesElement.removeChild(framesElement.firstChild);
    }
    for (const frame of frames) {
      let frameElement = document.createElement('option');
      frameElement.value = frame.level;
      if (typeof frame.fullname !== 'undefined' && typeof frame.line !== 'undefined') {
        frameElement.appendChild(
          document.createTextNode(`${frame.level}. ${frame.fullname}:${frame.line}`)
        );
      } else {
        frameElement.appendChild(
          document.createTextNode(`${frame.level}. ${frame.func} (${frame.addr})`)
        );
      }
      if (parseInt(frame.level) == currentFrameIndex) {
        frameElement.selected = 'selected';
      }
      framesElement.appendChild(frameElement);
    }
  });

  document
    .querySelector('select[name="thread"]')
    .addEventListener('change', ev => {
      let threadIndex = parseInt(ev.target.value);
      socketSend({
        method: 'run',
        command: '-thread-select ' + threadIndex,
      }).then(record => {
        layout.eventHub.emit(
          'threadSelected',
          threads[threadIndex],
          threads[threadIndex].defaultFrame
        );
      });
    });
  document
    .querySelector('select[name="frame"]')
    .addEventListener('change', ev => {
      let frameIndex = parseInt(ev.target.value);
      socketSend({
        method: 'run',
        command: '-stack-select-frame ' + frameIndex,
      }).then(record => {
        layout.eventHub.emit(
          'threadSelected',
          currentThread,
          threads[currentThread.id].stack[frameIndex]
        );
      });
    });
  window.addEventListener('resize', ev => layout.updateSize());
}

document.addEventListener('DOMContentLoaded', main, false);
// vim: set expandtab:ts=2:sw=2
