import CodeMirror from 'codemirror';
import 'codemirror/addon/mode/simple';
import 'codemirror/mode/clike/clike';
import 'codemirror/addon/selection/active-line';
import { GoldenLayout } from 'golden-layout';
import type { LayoutConfig, ComponentContainer } from 'golden-layout';
import type {
  GDBMIFrame,
  GDBMIRecord,
  AssemblyInstructionRecord,
  DataDisassembleRecord,
  DisassembleGraphRecord,
  ListRegisterValuesRecord,
  FunctionRecord,
  RegisterNamesRecord,
  StackDumpRecord,
  StackListFramesRecord,
  ThreadInfoRecord,
} from './gdbmi';

import Graph, { Node } from './graph';

class Deferred<T> {
  public resolve: (arg: T) => void;

  public reject: () => void;

  public readonly promise: Promise<T>;

  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

function createSVGNode(
  type: string,
  attributes: { [key: string]: string } = {},
): SVGGraphicsElement {
  const svgNS = 'http://www.w3.org/2000/svg';

  const node = document.createElementNS(svgNS, type) as SVGGraphicsElement;
  if (!attributes) {
    return node;
  }
  for (const key in attributes) {
    node.setAttributeNS(null, key, attributes[key]);
  }
  return node;
}

CodeMirror.defineSimpleMode('assembly', {
  start: [
    { regex: /#.*/, token: 'comment' },
    // identifier
    { regex: /\{[a-z_][a-z0-9_]*\}/, token: 'tag' },
    // address
    { regex: /\$0x[0-9a-fA-F]+\b/, token: 'number' },
    // address
    { regex: /[+-]?0x[0-9a-fA-F]+\b/, token: 'string' },
    // register
    { regex: /(\b|%)[a-z][a-z0-9]+\b/, token: 'attribute' },
    // source-address
    {
      regex: /[0-9a-fA-F]+\b/,
      sol: true,
      token: 'type.link',
      next: 'opcode',
    },
    { regex: /<.*>/, token: 'atom' },
    { regex: /\b[0-9]+\b/, token: 'number' },
    { regex: /BYTE|WORD|DWORD|QWORD|PTR/, token: 'def' },
    { regex: /[\[\]():,]/, token: 'def' },
  ],
  opcode: [{ regex: /\b[a-z][a-z0-9.]+\b/, token: 'keyword', next: 'start' }],
  meta: {
    dontIndentStates: ['comment'],
    lineComment: '#',
  },
});

class GraphView {
  private readonly svg: SVGElement;

  private visible = false;

  private dirty = false;

  private maxWidth: number;

  private maxHeight: number;

  private miniViewScale = 1.0;

  private highlightedAddress: number | null = null;

  private viewport: {
    x: number;
    y: number;
    scale: number;
  } = {
    x: 0,
    y: 0,
    scale: 1.0,
  };

  private mousedown = false;

  private mousemoved = false;

  private mouseanchor: { x: number; y: number } | null = null;

  private viewportMousedown = false;

  private debug = false;

  private instructionSpans: { [address: number]: SVGElement } = {};

  private instructionNodes: { [address: number]: string } = {};

  private readonly graph: Graph;

  private data: DisassembleGraphRecord = {};

  constructor(svg: SVGElement) {
    this.svg = svg;
    this.maxWidth = this.svg.clientWidth;
    this.maxHeight = this.svg.clientHeight;
    this.svg.addEventListener('wheel', (ev) => this.__onWheel(ev));
    this.svg.addEventListener('mousemove', (ev) => this.__onMouseMove(ev));
    this.svg.addEventListener('mousedown', (ev) => this.__onMouseDown(ev));
    this.svg.addEventListener('mouseup', (ev) => this.__onMouseUp(ev));

    const miniViewViewport = this.svg.querySelector('#MiniView rect.viewport');
    miniViewViewport.addEventListener('mousedown', (ev: MouseEvent) =>
      this.__viewportOnMouseDown(ev),
    );

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

  hide(): void {
    this.svg.style.display = 'none';
    this.visible = false;
  }

  render(data: DisassembleGraphRecord): void {
    this.data = data;
    this.dirty = true;
    this.highlightedAddress = null;
    if (!this.visible) {
      return;
    }
    this.__render(this.data);
  }

  highlight(address: number): void {
    this.highlightedAddress = address;
    if (this.dirty) {
      return;
    }
    this.__highlight(this.highlightedAddress, true);
  }

  scrollIntoView(address: number): void {
    if (!this.visible) {
      return;
    }
    this.__highlight(address, false);
    this.__scrollIntoView(address);
  }

  private __getBoundingRect(element: SVGElement): SVGRect {
    const elementBBox = element.getBoundingClientRect();
    const svgBBox = this.svg.getBoundingClientRect();
    elementBBox.x -= svgBBox.x;
    elementBBox.y -= svgBBox.y;
    return elementBBox;
  }

  private __render(graph: DisassembleGraphRecord): void {
    if (!this.dirty) {
      return;
    }
    this.dirty = false;
    const blocks: { [addr: string]: Node } = {};
    const graphNode = document.querySelector(
      '#ProgramControlFlowGraph',
    ) as SVGGraphicsElement;
    while (graphNode.lastChild) {
      graphNode.removeChild(graphNode.lastChild);
    }
    const nodes: SVGGraphicsElement[] = [];
    this.instructionSpans = {};
    this.graph.clear();
    for (const addr in graph) {
      const block = graph[addr];
      const blockElm = createSVGNode('g');
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
        const ins = block.instructions[i];

        const blockTextElm = createSVGNode('text', {
          x: '0',
          y: `${i}em`,
        });
        const address = parseInt(ins.address, 16);
        this.instructionSpans[address] = blockTextElm;
        this.instructionNodes[address] = addr;

        const addressSpan = createSVGNode('tspan');
        addressSpan.setAttribute('class', 'address');
        addressSpan.appendChild(document.createTextNode(ins.address));
        blockTextElm.appendChild(addressSpan);

        const mnemonicSpan = createSVGNode('tspan', {
          x: `${addressWidth + 2}ex`,
        });
        mnemonicSpan.setAttribute('class', 'mnemonic');
        mnemonicSpan.appendChild(document.createTextNode(ins.mnemonic));
        blockTextElm.appendChild(mnemonicSpan);

        const registerSpan = createSVGNode('tspan', {
          x: `${addressWidth + mnemonicWidth + 5}ex`,
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

      const rectElm = createSVGNode('rect', {
        x: String(blockTextBBox.x - 5),
        y: String(blockTextBBox.y - 5),
        width: String(blockTextBBox.width + 10),
        height: String(blockTextBBox.height + 10),
      });
      rectElm.setAttribute('class', 'block');
      blockElm.insertBefore(rectElm, blockElm.firstChild);
      blocks[addr] = {
        label: addr,
        id: addr,
        inEdges: [],
        outEdges: [],
        x: 0,
        y: 0,
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
    for (const block of this.graph.nodes) {
      minX = Math.min(minX, block.x);
    }
    for (const edge of this.graph.edges) {
      for (const point of edge.points) {
        minX = Math.min(minX, point.x);
      }
    }

    for (const block of this.graph.nodes) {
      block.element.setAttributeNS(
        null,
        'transform',
        `translate(${5 + block.x - minX}, ${18 + block.y})`,
      );
      if (this.debug) {
        const rectElm = createSVGNode('rect', {
          x: String(block.subtreeBBox.x - minX),
          y: String(block.subtreeBBox.y),
          width: String(block.subtreeBBox.width),
          height: String(block.subtreeBBox.height),
        });
        rectElm.setAttribute('class', 'bounding-box');
        nodes.push(rectElm);
      }
    }
    for (const edge of this.graph.edges) {
      let points = '';
      for (let i = 0; i < edge.points.length; i++) {
        if (i == 0) {
          points += 'M';
        } else {
          points += 'L';
        }
        points += `${edge.points[i].x - minX},${edge.points[i].y}`;
      }
      const lineElm = createSVGNode('path', {
        d: points,
      });
      lineElm.setAttribute(
        'class',
        `edge ${edge.type}${edge.back ? ' back-edge' : ''}`,
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
    this.miniViewScale =
      this.maxWidth > this.maxHeight
        ? maxMiniViewSize / this.maxWidth
        : maxMiniViewSize / this.maxHeight;
    const miniViewWidth = this.maxWidth * this.miniViewScale;
    const miniViewHeight = this.maxHeight * this.miniViewScale;
    const miniViewRect = this.svg.querySelector('#MiniView rect.background');
    miniViewRect.setAttribute(
      'x',
      String(this.svg.clientWidth - miniViewWidth - 22),
    );
    miniViewRect.setAttribute(
      'y',
      String(this.svg.clientHeight - miniViewHeight - 22),
    );
    miniViewRect.setAttribute('width', String(miniViewWidth + 22));
    miniViewRect.setAttribute('height', String(miniViewHeight + 22));
    this.svg
      .querySelector('#MiniView use')
      .setAttribute(
        'transform',
        `translate(${this.svg.clientWidth - miniViewWidth - 12} ${
          this.svg.clientHeight - miniViewHeight - 12
        }),scale(${this.miniViewScale} ${this.miniViewScale})`,
      );
    this.viewport.x = 0;
    this.viewport.y = 0;
    this.viewport.scale = Math.max(
      this.svg.clientWidth / this.maxWidth,
      this.svg.clientHeight / this.maxHeight,
      1.0,
    );
    this.__updateViewBox();
  }

  private __highlight(address: number, moveArrow = false): void {
    const highlightElement = this.svg.querySelector(
      '#instruction-highlight rect',
    );
    for (const previous of Array.from(this.svg.querySelectorAll('g.current'))) {
      previous.classList.remove('current');
    }
    for (const previous of Array.from(
      this.svg.querySelectorAll('g.reachable'),
    )) {
      previous.classList.remove('reachable');
    }
    for (const activePath of Array.from(
      this.svg.querySelectorAll('path.active'),
    )) {
      activePath.classList.remove('active');
    }
    if (address === null || !this.instructionSpans.hasOwnProperty(address)) {
      this.svg.classList.add('unselected');
      highlightElement.setAttribute('opacity', '0');
      return;
    }
    this.svg.classList.remove('unselected');
    highlightElement.setAttribute('opacity', '1');

    const element = this.instructionSpans[address];
    const elementBBox = this.__getBoundingRect(element);

    const node = this.graph.getNode(this.instructionNodes[address]);
    node.element.classList.add('current');
    for (const edge of node.inEdges) {
      edge.element.classList.add('active');
      this.graph.getNode(edge.from).element.classList.add('reachable');
    }
    for (const edge of node.outEdges) {
      edge.element.classList.add('active');
      this.graph.getNode(edge.to).element.classList.add('reachable');
    }

    highlightElement.setAttribute('x', String(elementBBox.x));
    highlightElement.setAttribute('y', String(elementBBox.y + 1));
    highlightElement.setAttribute(
      'width',
      String(element.parentElement.getBoundingClientRect().width - 10),
    );
    highlightElement.setAttribute('height', String(elementBBox.height - 2));

    if (moveArrow) {
      element.setAttribute('class', 'highlight');
      const highlightArrow = this.svg.querySelector(
        '#instruction-highlight path',
      ) as SVGGraphicsElement;
      const highlightArrowBBox = highlightArrow.getBBox();
      highlightArrow.setAttribute(
        'transform',
        `translate(${elementBBox.x - highlightArrowBBox.width - 8}, ${
          elementBBox.y + (elementBBox.height - highlightArrowBBox.height) / 2.0
        })`,
      );
    }
  }

  private __scrollIntoView(address: number): void {
    const element = this.instructionSpans[address];
    if (!element) {
      return;
    }
    const elementBBox = this.__getBoundingRect(element);
    const elementBBoxWidth =
      element.parentElement.getBoundingClientRect().width - 10;
    this.__moveViewport(
      elementBBox.x + elementBBoxWidth / 2.0 - this.svg.clientWidth / 2.0,
      elementBBox.y + elementBBox.height / 2.0 - this.svg.clientHeight / 2.0,
    );
    this.__updateViewBox();
  }

  private __moveViewport(x: number, y: number): void {
    this.viewport.x = Math.max(
      0,
      Math.min(x, this.maxWidth - this.svg.clientWidth / this.viewport.scale),
    );
    this.viewport.y = Math.max(
      0,
      Math.min(y, this.maxHeight - this.svg.clientHeight / this.viewport.scale),
    );
  }

  private __onWheel(ev: MouseWheelEvent): null {
    const oldScale = this.viewport.scale;
    this.viewport.scale = Math.max(
      Math.min(
        this.svg.clientWidth / this.maxWidth,
        this.svg.clientHeight / this.maxHeight,
      ),
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore: wheelDelta _should_ be part of MouseWheelEvent
      Math.min(this.viewport.scale + ev.wheelDelta / 1200.0, 1.0),
    );
    if (oldScale == this.viewport.scale) {
      return;
    }
    this.__moveViewport(
      this.viewport.x +
        ev.offsetX / oldScale -
        ev.offsetX / this.viewport.scale,
      this.viewport.y +
        ev.offsetY / oldScale -
        ev.offsetY / this.viewport.scale,
    );
    this.__updateViewBox();
  }

  private __onMouseMove(ev: MouseEvent): void {
    if (!this.mousedown) return;
    ev.preventDefault();
    this.mousemoved = true;
    if (this.viewportMousedown) {
      this.__moveViewport(
        this.viewport.x +
          (ev.offsetX - this.mouseanchor.x) / this.miniViewScale,
        this.viewport.y +
          (ev.offsetY - this.mouseanchor.y) / this.miniViewScale,
      );
    } else {
      this.__moveViewport(
        this.viewport.x -
          (ev.offsetX - this.mouseanchor.x) / this.viewport.scale,
        this.viewport.y -
          (ev.offsetY - this.mouseanchor.y) / this.viewport.scale,
      );
    }
    this.__updateViewBox();
    this.mouseanchor = {
      x: ev.offsetX,
      y: ev.offsetY,
    };
  }

  private __onMouseDown(ev: MouseEvent): void {
    ev.preventDefault();
    this.mousedown = true;
    this.mousemoved = false;
    this.mouseanchor = {
      x: ev.offsetX,
      y: ev.offsetY,
    };
  }

  private __findAddressAtCoordinates(x: number, y: number): number | null {
    for (const [address, element] of Object.entries(this.instructionSpans)) {
      const elementBBox = this.__getBoundingRect(element);
      const elementBBoxWidth =
        element.parentElement.getBoundingClientRect().width - 10;

      if (
        elementBBox.x <= x &&
        x <= elementBBox.x + elementBBoxWidth &&
        elementBBox.y <= y &&
        y <= elementBBox.y + elementBBox.height
      ) {
        return address as unknown as number;
      }
    }
    return null;
  }

  private __onMouseUp(ev: MouseEvent): void {
    ev.preventDefault();
    if (!this.mousemoved) {
      const clickedAddress = this.__findAddressAtCoordinates(
        this.mouseanchor.x / this.viewport.scale + this.viewport.x,
        this.mouseanchor.y / this.viewport.scale + this.viewport.y,
      );
      this.__highlight(clickedAddress);
      this.svg.dispatchEvent(
        new CustomEvent('address-selected', {
          bubbles: true,
          detail: {
            address: clickedAddress,
          },
        }),
      );
    }
    this.mousedown = false;
    this.mouseanchor = null;
    this.viewportMousedown = false;
  }

  private __viewportOnMouseDown(ev: MouseEvent): void {
    ev.preventDefault();
    this.viewportMousedown = true;
  }

  private __updateViewBox(): void {
    const mainTransform = `translate(${
      -this.viewport.x * this.viewport.scale
    }, ${-this.viewport.y * this.viewport.scale}),scale(${
      this.viewport.scale
    } ${this.viewport.scale})`;
    this.svg
      .querySelector('#MainView')
      .setAttribute('transform', mainTransform);

    this.svg
      .querySelector('#instruction-highlight')
      .setAttribute('transform', mainTransform);
    const miniViewRect = this.svg.querySelector('#MiniView rect.viewport');
    const miniViewOffsetX =
      this.svg.clientWidth - this.maxWidth * this.miniViewScale - 12;
    const miniViewOffsetY =
      this.svg.clientHeight - this.maxHeight * this.miniViewScale - 12;
    const miniViewViewportWidth =
      Math.min(this.svg.clientWidth / this.viewport.scale, this.maxWidth) *
      this.miniViewScale;
    const miniViewViewportHeight =
      Math.min(this.svg.clientHeight / this.viewport.scale, this.maxHeight) *
      this.miniViewScale;
    miniViewRect.setAttribute(
      'x',
      String(miniViewOffsetX + this.viewport.x * this.miniViewScale),
    );
    miniViewRect.setAttribute(
      'y',
      String(miniViewOffsetY + this.viewport.y * this.miniViewScale),
    );
    miniViewRect.setAttribute('width', String(miniViewViewportWidth));
    miniViewRect.setAttribute('height', String(miniViewViewportHeight));
  }
}

class Machine {
  public isa: undefined | string;

  public bits: undefined | number;

  public registers: Array<string>;

  constructor() {
    this.isa = undefined;
    this.bits = undefined;
    this.registers = [];
  }

  set registerNames(registers: Array<string>) {
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

  get registerNames(): Array<string> {
    return this.registers;
  }

  get stackRedZone(): number {
    if (typeof this.isa === 'undefined') {
      throw new Error('Machine not initialized');
    }
    if (this.isa == 'x86_64') {
      return 128;
    }
    return 0;
  }

  get stackRegister(): string {
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

  get registerWidth(): number {
    if (typeof this.isa === 'undefined') {
      throw new Error('Machine not initialized');
    }
    if (this.bits == 64) {
      return 8;
    }
    return 4;
  }

  get gdbStackCommand(): string {
    return `-data-read-memory $${this.stackRegister}-${this.stackRedZone} x ${this.registerWidth} 100 1`;
  }
}

type Thread = {
  id: string;
  name: string;
  defaultFrame: GDBMIFrame;
  stack: null | GDBMIFrame[];
};

function main() {
  const payload = JSON.parse(atob(window.location.hash.substring(1)));
  const machine = new Machine();
  const threads: {
    [name: string]: Thread;
  } = {};
  let currentFrame: GDBMIFrame = {
    func: '',
    file: '',
    line: '1',
    addr: '0x0',
    level: '0',
  };
  const symbolTable = JSON.parse(
    window.localStorage.getItem('symbolTable') || '{}',
  );
  let currentThread: Thread | null = null;
  let functionBounds: {
    [functionName: string]: { start: string; end: string };
  } | null = null;
  let dirtyThreads = true;

  const socket = new WebSocket(`ws://localhost:${payload.websocketPort}`);
  let payloadCount = 0;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const promiseMapping: { [token: number]: Deferred<any> } = {};
  function socketSend<T>(
    payload: {
      method: string;
      token?: number;
      command?: string;
    } & { [key: string]: any }, // eslint-disable-line @typescript-eslint/no-explicit-any
  ): Promise<T> {
    payload.token = ++payloadCount;
    socket.send(JSON.stringify(payload));
    promiseMapping[payload.token] = new Deferred<T>();
    return promiseMapping[payload.token].promise;
  }
  socket.onmessage = function (event) {
    const data = JSON.parse(event.data) as GDBMIRecord;
    if (data.type == 'console-stream') {
      layout.eventHub.emitUserBroadcast(
        'consoleAdded',
        data.payload,
        'console',
      );
    } else if (data.type == 'log-stream') {
      layout.eventHub.emitUserBroadcast('consoleAdded', data.payload, 'log');
    } else if (data.type == 'error-stream') {
      layout.eventHub.emitUserBroadcast('consoleAdded', data.payload, 'error');
    } else if (data.type == 'notify-async' && data.class == 'thread-selected') {
      layout.eventHub.emitUserBroadcast(
        'threadSelected',
        data.output,
        data.output.frame,
      );
    } else if (
      data.type == 'notify-async' &&
      (data.class == 'thread-created' ||
        data.class == 'thread-exited' ||
        data.class == 'thread-group-added' ||
        data.class == 'thread-group-removed' ||
        data.class == 'thread-group-started' ||
        data.class == 'thread-group-exited')
    ) {
      dirtyThreads = true;
    } else if (data.type == 'exec-async' && data.class == 'running') {
      const buttonElement: HTMLButtonElement = document.querySelector(
        '.gdb-console-input button',
      );
      buttonElement.textContent = '⏸';
      buttonElement.dataset.state = 'pause';
      (
        document.querySelector('.gdb-console-input input') as HTMLInputElement
      ).disabled = true;
    } else if (data.type == 'exec-async' && data.class == 'stopped') {
      const buttonElement: HTMLButtonElement = document.querySelector(
        '.gdb-console-input button',
      );
      buttonElement.textContent = '▶️';
      buttonElement.dataset.state = 'play';
      (
        document.querySelector('.gdb-console-input input') as HTMLInputElement
      ).disabled = false;
      if (dirtyThreads) {
        dirtyThreads = false;
        socketSend<ThreadInfoRecord>({
          method: 'run',
          command: '-thread-info',
        }).then((record) => {
          let activeThread = null;
          const threadSelect = document.querySelector(
            'select[name="thread"]',
          ) as HTMLSelectElement;
          while (threadSelect.firstChild) {
            threadSelect.removeChild(threadSelect.firstChild);
          }
          for (const thread of record.threads) {
            const threadElement = document.createElement(
              'option',
            ) as HTMLOptionElement;
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
              threadElement.selected = true;
              threadName = `* ${threadName}`;
            } else {
              threadName = `\u00A0 ${threadName}`;
            }
            threadElement.appendChild(document.createTextNode(threadName));
            threadSelect.appendChild(threadElement);
          }
          if (activeThread) {
            layout.eventHub.emitUserBroadcast(
              'threadSelected',
              activeThread,
              activeThread.frame,
            );
          }
        });
      }
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
  socket.onerror = (event) => {
    console.error(event);
  };
  socket.onopen = () => {
    socketSend<RegisterNamesRecord>({
      method: 'run',
      command: '-data-list-register-names',
    }).then((record) => {
      machine.registerNames = record['register-names'];
    });
  };

  function getFunctionBounds(
    func: string,
  ): Promise<{ start: string; end: string }> {
    function _boundsFor(func: string): { start: string; end: string } {
      if (!functionBounds.hasOwnProperty(func)) {
        console.error(
          `could not find bounds for ${func}. Guesstimating 1024 bytes`,
        );
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
    return socketSend<FunctionRecord[]>({
      method: 'info-functions',
    }).then((record) => {
      functionBounds = {};

      let lastAddress = BigInt('0xffffffffffffffff');
      for (const functionRecord of record.reverse()) {
        const currentAddress = BigInt(functionRecord.address);
        const length = Math.min(131072, Number(lastAddress - currentAddress));
        lastAddress = currentAddress;
        functionBounds[functionRecord.name] = {
          start: functionRecord.address,
          end: `0x${(currentAddress + BigInt(length)).toString(16)}`,
        };
      }

      return _boundsFor(func);
    });
  }

  const goldenLayoutSettings: LayoutConfig = {
    root: {
      type: 'column',
      content: [
        {
          type: 'row',
          content: [
            {
              type: 'component',
              componentType: 'control-flow-graph',
              componentState: {},
              id: 'control-flow-graph',
              title: 'Control Flow Graph',
              isClosable: false,
            },
            {
              type: 'column',
              content: [
                {
                  type: 'component',
                  componentType: 'source-editor',
                  componentState: {},
                  id: 'source-editor',
                  title: 'Source',
                  isClosable: false,
                },
                {
                  type: 'component',
                  componentType: 'disassembly',
                  componentState: {},
                  id: 'disassembly',
                  title: 'Disassembly',
                  isClosable: false,
                },
              ],
            },
            {
              type: 'column',
              content: [
                {
                  type: 'component',
                  componentType: 'registers',
                  componentState: {},
                  id: 'registers',
                  title: 'Registers',
                  isClosable: false,
                },
                {
                  type: 'component',
                  componentType: 'stack',
                  componentState: {},
                  id: 'stack',
                  title: 'Stack',
                  isClosable: false,
                },
              ],
            },
          ],
        },
        {
          type: 'component',
          componentType: 'console',
          componentState: {},
          id: 'console',
          title: 'Console',
          isClosable: false,
          height: 20,
        },
      ],
    },
  };

  const layout = new GoldenLayout(
    goldenLayoutSettings,
    document.getElementById('layout-root'),
  );

  layout.registerComponentFactoryFunction(
    'control-flow-graph',
    (container: ComponentContainer) => {
      const svgNode =
        $(`<svg class="h-100 w-100" xmlns="http://www.w3.org/2000/svg"
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
      </svg>`);
      let graph: GraphView | null = null;
      container.getElement().append(svgNode[0]);
      container.on('open', () => {
        graph = new GraphView(svgNode[0] as unknown as SVGGraphicsElement);
        graph.show();
        layout.eventHub.on(
          'userBroadcast',
          (
            eventName: string,
            data: DisassembleGraphRecord,
            address: number,
          ) => {
            if (eventName !== 'graphReady') return;
            graph.render(data);
            if (!address) return;
            graph.highlight(address);
            graph.scrollIntoView(address);
          },
        );
        svgNode[0].addEventListener('address-selected', (ev: CustomEvent) =>
          layout.eventHub.emitUserBroadcast(
            'addressSelected',
            ev.detail.address,
          ),
        );
      });
      container.on('resize', () => {
        if (!graph) return;
        graph.show();
      });
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, address: number) => {
          if (eventName !== 'addressSelected') return;
          if (!graph) return;
          graph.scrollIntoView(address);
        },
      );
    },
  );
  layout.registerComponentFactoryFunction(
    'source-editor',
    (container: ComponentContainer) => {
      const editorNode = $(`<div class="source-editor h-100 w-100">
        <textarea></textarea>
      </div>`);
      const sourceCodeMirror = CodeMirror.fromTextArea(
        editorNode[0].querySelector('textarea'),
        {
          theme: 'monokai',
          mode: 'clike',
          readOnly: true,
          lineNumbers: true,
        },
      );
      let sourceCurrentLineHandle: CodeMirror.LineHandle | null = null;
      let currentSource = '';
      container.getElement().append(editorNode[0]);

      function redraw() {
        sourceCodeMirror.getDoc().setValue(currentSource);
        if (sourceCurrentLineHandle) {
          sourceCodeMirror.removeLineClass(
            sourceCurrentLineHandle,
            'background',
          );
        }
        if (currentFrame && currentFrame.line) {
          const currentLine = parseInt(currentFrame.line, 10) - 1;
          sourceCodeMirror.scrollIntoView({ line: currentLine, ch: 0 }, 100);
          sourceCurrentLineHandle = sourceCodeMirror.addLineClass(
            currentLine,
            'background',
            'current-line',
          );
        }
      }
      container.on('show', () => window.requestAnimationFrame(() => redraw()));
      container.on('resize', () => sourceCodeMirror.refresh());

      const sourceCache: { [filename: string]: string } = {};
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, sourcePath: string) => {
          if (eventName !== 'fileChanged') return;
          if (!sourcePath) {
            sourcePath = '<unknown>';
            sourceCache[sourcePath] = '';
          }
          container.setTitle(sourcePath);
          if (sourceCache.hasOwnProperty(sourcePath)) {
            layout.eventHub.emitUserBroadcast(
              'sourceReady',
              sourcePath,
              sourceCache[sourcePath],
            );
          } else {
            socketSend<string | null>({
              method: 'get-source',
              filename: sourcePath,
            }).then((record) => {
              sourceCache[sourcePath] = record || '';
              layout.eventHub.emitUserBroadcast(
                'sourceReady',
                sourcePath,
                sourceCache[sourcePath],
              );
            });
          }
        },
      );
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, sourcePath: string, contents: string) => {
          if (eventName !== 'sourceReady') return;
          currentSource = contents;
          if (sourcePath.endsWith('java')) {
            sourceCodeMirror.setOption('mode', 'text/x-java');
          } else if (sourcePath.endsWith('cpp') || sourcePath.endsWith('cc')) {
            sourceCodeMirror.setOption('mode', 'text/x-c++src');
          } else if (sourcePath.endsWith('h')) {
            sourceCodeMirror.setOption('mode', 'text/x-c++hdr');
          } else if (sourcePath.endsWith('c')) {
            sourceCodeMirror.setOption('mode', 'text/x-c');
          } else {
            console.log(
              `Unknown language for ${sourcePath}. defaulting to C++`,
            );
            sourceCodeMirror.setOption('mode', 'text/x-c++src');
          }
          redraw();
        },
      );
    },
  );
  layout.registerComponentFactoryFunction(
    'disassembly',
    (container: ComponentContainer) => {
      const assemblyNode = $(`<div class="assembly-editor w-100 h-100">
        <textarea></textarea>
      </div>`);
      container.getElement().append(assemblyNode[0]);
      const assemblyCodeMirror = CodeMirror.fromTextArea(
        assemblyNode[0].querySelector('textarea'),
        {
          theme: 'monokai',
          mode: 'assembly',
          styleActiveLine: true,
        },
      );
      let assemblyCurrentLineHandle: CodeMirror.LineHandle | null = null;
      assemblyCodeMirror.on('mousedown', (cm, e) => {
        const target = e.target as HTMLElement;
        if (target.className.indexOf('cm-link') === -1) {
          return;
        }
        layout.eventHub.emitUserBroadcast(
          'addressSelected',
          parseInt(target.textContent, 16),
        );
      });
      container.on('resize', () => assemblyCodeMirror.refresh());
      layout.eventHub.on(
        'userBroadcast',
        (
          eventName: string,
          currentAddress: string,
          insns: AssemblyInstructionRecord[],
        ) => {
          if (eventName !== 'assemblyReady') return;
          container.setTitle(currentFrame.func || 'Disassembly');
          const replacements = symbolTable[currentFrame.func] || {};
          const contents = [];
          let activeLine = 0;
          for (let i = 0; i < insns.length; i++) {
            let instruction = insns[i].inst;
            for (const [search, replace] of Object.entries(replacements)) {
              instruction = instruction.replace(
                search,
                `${search} {${replace}}`,
              );
            }
            contents.push(`${insns[i].address.substring(2)} ${instruction}`);
            if (insns[i].address == currentAddress) {
              activeLine = i;
            }
          }
          assemblyCodeMirror.getDoc().setValue(contents.join('\n'));
          assemblyCodeMirror.scrollIntoView({ line: activeLine, ch: 0 }, 100);
          if (assemblyCurrentLineHandle) {
            assemblyCodeMirror.removeLineClass(
              assemblyCurrentLineHandle,
              'text',
            );
          }
          assemblyCurrentLineHandle = assemblyCodeMirror.addLineClass(
            activeLine,
            'text',
            'current-instruction',
          );
          assemblyCodeMirror.setCursor(activeLine);
          if (insns.length == 0) {
            layout.eventHub.emitUserBroadcast('graphReady', {}, 0);
            return;
          }

          const startAddress = parseInt(insns[0].address.substr(2), 16);
          const endAddress = parseInt(
            insns[insns.length - 1].address.substr(2),
            16,
          );
          socketSend<DisassembleGraphRecord>({
            method: 'disassemble-graph',
            isa: machine.isa,
            startAddress,
            endAddress,
          }).then((record) => {
            const address = parseInt(currentAddress.substring(2), 16);
            layout.eventHub.emitUserBroadcast('graphReady', record, address);
          });
        },
      );
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, address: string | null) => {
          if (eventName !== 'addressSelected') return;
          if (address === null) return;
          const hexAddress = Number(address).toString(16);
          for (let i = 0; i < assemblyCodeMirror.lineCount(); ++i) {
            for (const token of assemblyCodeMirror.getLineTokens(i)) {
              if (
                !token.type ||
                token.type.indexOf('link') === -1 ||
                !token.string.endsWith(hexAddress)
              ) {
                continue;
              }
              assemblyCodeMirror.scrollIntoView({ line: i, ch: 0 }, 100);
              assemblyCodeMirror.setCursor(i);
              return;
            }
          }
        },
      );
    },
  );
  layout.registerComponentFactoryFunction(
    'registers',
    (container: ComponentContainer) => {
      const registersNode = $(`<div class="registers w-100 h-100">
        <table class="w-100">
          <thead>
            <th>Register</th>
            <th>Value</th>
          </thead>
          <tbody>
          </tbody>
        </table>
      </div>`);
      container.getElement().append(registersNode[0]);
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, record: ListRegisterValuesRecord) => {
          if (eventName !== 'registersReady') return;
          const registersElement = registersNode[0].querySelector('tbody');
          while (registersElement.firstChild) {
            registersElement.removeChild(registersElement.firstChild);
          }
          for (let i = 0; i < record['register-values'].length; i++) {
            const reg = record['register-values'][i];
            if (parseInt(reg.number, 10) > machine.registerNames.length) {
              continue;
            }
            const rowElement = document.createElement('tr');
            let cellElement = document.createElement('td');
            cellElement.appendChild(
              document.createTextNode(
                machine.registerNames[parseInt(reg.number, 10)],
              ),
            );
            rowElement.appendChild(cellElement);
            cellElement = document.createElement('td');
            cellElement.appendChild(document.createTextNode(reg.value));
            rowElement.appendChild(cellElement);
            registersElement.appendChild(rowElement);
          }
        },
      );
    },
  );
  layout.registerComponentFactoryFunction(
    'stack',
    (container: ComponentContainer) => {
      const stackNode = $(`<div class="stack w-100 h-100">
        <table class="w-100">
          <thead>
            <th>Address</th>
            <th>Offset</th>
            <th>Value</th>
          </thead>
          <tbody>
          </tbody>
        </table>
      </div>`);
      container.getElement().append(stackNode[0]);
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, record: StackDumpRecord) => {
          if (eventName !== 'stackDumpReady') return;
          const stackElement = stackNode[0].querySelector('tbody');
          while (stackElement.firstChild) {
            stackElement.removeChild(stackElement.firstChild);
          }
          let offset = -machine.stackRedZone;
          for (const entry of record.memory) {
            const rowElement = document.createElement('tr');
            let cellElement = document.createElement('td');

            cellElement.appendChild(document.createTextNode(entry.addr));
            rowElement.appendChild(cellElement);
            cellElement = document.createElement('td');

            cellElement.className = 'right';
            cellElement.appendChild(
              document.createTextNode(
                `${offset >= 0 ? '0x' : '-0x'}${Math.abs(offset).toString(16)}`,
              ),
            );
            offset += machine.registerWidth;
            rowElement.appendChild(cellElement);
            cellElement = document.createElement('td');
            cellElement.appendChild(document.createTextNode(entry.data[0]));
            rowElement.appendChild(cellElement);
            stackElement.appendChild(rowElement);
          }
        },
      );
    },
  );
  layout.registerComponentFactoryFunction(
    'console',
    (container: ComponentContainer) => {
      const cmdHistory: string[] = [];
      let cmdHistoryIdx = 0;

      const consoleNode = $(`<div class="d-flex flex-column h-100 w-100">
        <div class="gdb-console-container">
          <div class="h-100 w-100 gdb-console"></div>
        </div>
        <form class="form-inline flex-row gdb-console-input">
          <label class="p-1">(gdb) </label>
          <input type="text" name="command" autocomplete="off" class="form-control form-control-sm">
          <button data-state="pause">⏸</button>
        </form>
      </div>`);
      const consoleElement = consoleNode[0].querySelector('.gdb-console');
      const inputElement = consoleNode[0].querySelector('input');
      const commandElement = consoleNode[0].querySelector('form');
      const buttonElement = consoleNode[0].querySelector('button');
      container.getElement().append(consoleNode[0]);

      function appendConsoleNode(contents: string, className: string): void {
        const node = document.createElement('span');
        node.className = className;
        node.appendChild(document.createTextNode(contents));
        consoleElement.appendChild(node);
        node.scrollIntoView();
      }

      commandElement.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const inputElement = (ev.target as HTMLFormElement).querySelector(
          'input',
        );
        let cmd = inputElement.value;
        if (cmd) {
          cmdHistory.push(cmd);
          cmdHistoryIdx = cmdHistory.length;
        } else if (cmdHistory.length) {
          cmd = cmdHistory[cmdHistory.length - 1];
        } else {
          return;
        }
        layout.eventHub.emitUserBroadcast(
          'consoleAdded',
          `(gdb) ${cmd}\n`,
          'prompt',
        );
        inputElement.value = '';
        socketSend<void>({ method: 'run', command: cmd });
      });

      inputElement.addEventListener('keydown', (ev) => {
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

      buttonElement.addEventListener('click', (ev) => {
        if ((ev.target as HTMLButtonElement).dataset.state == 'play') {
          socketSend<void>({
            method: 'run',
            command: '-exec-continue',
          });
        } else {
          socketSend<void>({
            method: 'run',
            command: '-exec-interrupt --all',
          });
        }
      });
      layout.eventHub.on(
        'userBroadcast',
        (eventName: string, contents: string, className: string) => {
          if (eventName !== 'consoleAdded') return;
          appendConsoleNode(contents, className);
        },
      );
      container.on('open', () => inputElement.focus());
    },
  );

  layout.init();

  layout.eventHub.on(
    'userBroadcast',
    (eventName: string, selectedThread: Thread, selectedFrame: GDBMIFrame) => {
      if (eventName !== 'threadSelected') return;
      currentThread = selectedThread;
      currentFrame = selectedFrame;
      if (currentFrame.fullname) {
        const cmd = `-data-disassemble -f ${currentFrame.fullname}  -l ${currentFrame.line} -n -1 -- 0`;
        socketSend<DataDisassembleRecord>({ method: 'run', command: cmd }).then(
          (record) => {
            layout.eventHub.emitUserBroadcast(
              'assemblyReady',
              currentFrame.addr,
              record.asm_insns,
            );
          },
        );
      } else if (currentFrame.func) {
        getFunctionBounds(currentFrame.func).then((bounds) => {
          const cmd = `-data-disassemble -s ${bounds.start}  -e ${bounds.end} -- 0`;
          socketSend<DataDisassembleRecord>({
            method: 'run',
            command: cmd,
          }).then((record) => {
            layout.eventHub.emitUserBroadcast(
              'assemblyReady',
              currentFrame.addr,
              record.asm_insns,
            );
          });
        });
      } else {
        layout.eventHub.emitUserBroadcast(
          'assemblyReady',
          currentFrame.addr,
          [],
        );
      }
      socketSend<ListRegisterValuesRecord>({
        method: 'run',
        command: '-data-list-register-values --skip-unavailable x',
      }).then((record) =>
        layout.eventHub.emitUserBroadcast('registersReady', record),
      );
      socketSend<StackDumpRecord>({
        method: 'run',
        command: machine.gdbStackCommand,
      }).then((record) =>
        layout.eventHub.emitUserBroadcast('stackDumpReady', record),
      );
      if (threads[selectedThread.id].stack !== null) {
        layout.eventHub.emitUserBroadcast(
          'stackReady',
          threads[selectedThread.id].stack,
          parseInt(currentFrame.level, 10),
        );
      } else {
        socketSend<StackListFramesRecord>({
          method: 'run',
          command: '-stack-list-frames',
        }).then((record) => {
          threads[selectedThread.id].stack = record.stack;
          layout.eventHub.emitUserBroadcast(
            'stackReady',
            threads[selectedThread.id].stack,
            parseInt(currentFrame.level, 10),
          );
        });
      }
      layout.eventHub.emitUserBroadcast('fileChanged', currentFrame.fullname);
    },
  );
  layout.eventHub.on(
    'userBroadcast',
    (eventName: string, frames: GDBMIFrame[], currentFrameIndex: number) => {
      if (eventName !== 'stackReady') return;
      const framesElement = document.querySelector('select[name="frame"]');
      while (framesElement.firstChild) {
        framesElement.removeChild(framesElement.firstChild);
      }
      for (const frame of frames) {
        const frameElement: HTMLOptionElement =
          document.createElement('option');
        frameElement.value = frame.level;
        if (
          typeof frame.fullname !== 'undefined' &&
          typeof frame.line !== 'undefined'
        ) {
          frameElement.appendChild(
            document.createTextNode(
              `${frame.level}. ${frame.fullname}:${frame.line}`,
            ),
          );
        } else {
          frameElement.appendChild(
            document.createTextNode(
              `${frame.level}. ${frame.func} (${frame.addr})`,
            ),
          );
        }
        if (parseInt(frame.level, 10) === currentFrameIndex) {
          frameElement.selected = true;
        }
        framesElement.appendChild(frameElement);
      }
    },
  );

  document
    .querySelector('select[name="thread"]')
    .addEventListener('change', (ev) => {
      const threadIndex = parseInt((ev.target as HTMLSelectElement).value, 10);
      socketSend<void>({
        method: 'run',
        command: `-thread-select ${threadIndex}`,
      }).then(() => {
        layout.eventHub.emitUserBroadcast(
          'threadSelected',
          threads[threadIndex],
          threads[threadIndex].defaultFrame,
        );
      });
    });
  document
    .querySelector('select[name="frame"]')
    .addEventListener('change', (ev) => {
      const frameIndex = parseInt((ev.target as HTMLSelectElement).value, 10);
      socketSend<void>({
        method: 'run',
        command: `-stack-select-frame ${frameIndex}`,
      }).then(() => {
        const { stack } = threads[currentThread.id];
        if (!stack) {
          return;
        }
        layout.eventHub.emitUserBroadcast(
          'threadSelected',
          currentThread,
          stack[frameIndex],
        );
      });
    });
  window.addEventListener('resize', () =>
    layout.setSize(window.innerWidth, window.innerHeight),
  );
}

document.addEventListener('DOMContentLoaded', main, false);
// vim: set expandtab:ts=2:sw=2
