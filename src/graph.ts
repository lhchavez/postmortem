function extend<T1, T2>(a: T1, b: T2): T1 & T2 {
  for (const key in b) {
    if (!b.hasOwnProperty(key)) {
      continue;
    }
    // @ts-ignore
    a[key] = b[key];
  }
  // @ts-ignore
  return a;
}

declare global {
  interface Set<T> {
    equals(setB: Set<T>): boolean;
    union(setB: Set<T>): Set<T>;
    intersection(setB: Set<T>): Set<T>;
    difference(setB: Set<T>): Set<T>;
  }
}

Set.prototype.equals = function <T>(setB: Set<T>): boolean {
  if (this.size != setB.size) {
    return false;
  }
  for (let elem of setB) {
    if (!this.has(elem)) {
      return false;
    }
  }
  return true;
};

Set.prototype.union = function <T>(setB: Set<T>): Set<T> {
  const union = new Set<T>(this);
  for (const elem of setB) {
    union.add(elem);
  }
  return union;
};

Set.prototype.intersection = function <T>(setB: Set<T>): Set<T> {
  const intersection = new Set<T>();
  for (const elem of setB) {
    if (this.has(elem)) {
      intersection.add(elem);
    }
  }
  return intersection;
};

Set.prototype.difference = function <T>(setB: Set<T>): Set<T> {
  const difference = new Set<T>(this);
  for (const elem of setB) {
    difference.delete(elem);
  }
  return difference;
};

class BBox {
  public x: number;
  public y: number;
  public readonly width: number;
  public readonly height: number;

  constructor(x: number, y: number, w: number, h: number) {
    this.x = x || 0;
    this.y = y || 0;
    this.width = w || -1;
    this.height = h || -1;
  }

  get empty(): boolean {
    return this.width < 0 || this.height < 0;
  }

  union(box: BBox): BBox {
    if (this.empty) {
      return box;
    }
    if (box.empty) {
      return this;
    }
    const left = Math.min(this.x, box.x),
      top = Math.min(this.y, box.y),
      right = Math.max(this.x + this.width, box.x + box.width),
      bottom = Math.max(this.y + this.height, box.y + box.height);
    return new BBox(left, top, right - left, bottom - top);
  }

  grow(left: number, top: number, right: number, bottom: number): BBox {
    return new BBox(
      this.x - left,
      this.y - top,
      this.width + (left + right),
      this.height + (top + bottom),
    );
  }
}

export type Node = {
  id: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  element: SVGGraphicsElement;
  subtreeBBox?: BBox;

  outEdges: Edge[];
  inEdges: Edge[];
};

type Edge = {
  type: string;
  from: string;
  to: string;
  back: boolean;
  points: { x: number; y: number }[];

  element: SVGGraphicsElement | null;
};

export default class Graph {
  private _nodes: { [id: string]: Node } = {};
  private _edges: Array<Edge> = [];
  private _dirty: boolean = false;

  constructor() {
    this.clear();
  }

  clear(): void {
    this._nodes = {};
    this._edges = [];
    this._dirty = false;
  }

  getNode(id: string): Node {
    return this._nodes[id];
  }

  setNode(id: string, node: Node): void {
    this._dirty = true;
    this._nodes[id] = extend(
      {
        id: id,
        x: 0,
        y: 0,
        inEdges: [],
        outEdges: [],
      },
      node,
    );
  }

  setEdge(from: string, to: string, edge: { type: string }) {
    this._dirty = true;
    this._edges.push(
      extend({ from, to, back: false, points: [], element: null }, edge),
    );
  }

  layout(): void {
    for (let edge of this._edges) {
      this._nodes[edge.from].outEdges.push(edge);
      this._nodes[edge.to].inEdges.push(edge);
    }
    let entry = null;
    for (let node of this.nodes) {
      if (node.inEdges.length == 0) {
        entry = node;
        break;
      }
    }

    const dominators: { [id: string]: Set<string> } = {};
    dominators[entry.id] = new Set<string>([entry.id]);
    const allNodes = new Set<string>();
    for (const node of this.nodes) {
      allNodes.add(node.id);
    }
    for (const node of this.nodes) {
      if (node == entry) {
        continue;
      }
      dominators[node.id] = allNodes;
    }
    let dirty = true;
    while (dirty) {
      dirty = false;
      for (const key of allNodes) {
        if (key == entry.id) {
          continue;
        }
        let node = this._nodes[key];
        let predDominators = allNodes;
        for (let edge of node.inEdges) {
          predDominators = predDominators.intersection(dominators[edge.from]);
        }
        let newDominatorSet = new Set([node.id]).union(predDominators);
        if (!dominators[node.id].equals(newDominatorSet)) {
          dominators[node.id] = newDominatorSet;
          dirty = true;
        }
      }
    }

    let strictlyDominates: { [id: string]: Set<string> } = {};
    for (let node of this.nodes) {
      for (let dominator of dominators[node.id]) {
        if (!strictlyDominates.hasOwnProperty(dominator)) {
          strictlyDominates[dominator] = new Set<string>();
        }
        if (dominator != node.id) {
          strictlyDominates[dominator].add(node.id);
        }
      }
    }

    let immediatelyDominates: { [id: string]: Set<string> } = {};
    let idom: { [id: string]: string } = {};
    for (let node in strictlyDominates) {
      let result = strictlyDominates[node];
      for (let child of strictlyDominates[node]) {
        result = result.difference(strictlyDominates[child]);
      }
      immediatelyDominates[node] = result;
      for (const child of immediatelyDominates[node]) {
        if (idom.hasOwnProperty(child)) {
          throw new Error(
            'Node ' + child + "'s immediate dominator is non-unique",
          );
        }
        idom[child] = node;
      }
    }
    if (Object.keys(idom).length != this.nodes.length - 1) {
      throw new Error('Incomplete immediate dominator list');
    }

    let dfs: (node: string) => void;
    let visited = new Set();
    const dominatorTree = (node: string) => {
      let keys = Array.from(immediatelyDominates[node].values());
      keys.sort();
      return keys;
    };
    const basicBlockTree = (id: string) => {
      let node = this._nodes[id];
      if (node.outEdges.length == 0) {
        return [];
      } else if (node.outEdges.length == 1) {
        return [node.outEdges[0].to];
      } else if (node.outEdges[0].type == 'fallthrough') {
        return [node.outEdges[0].to, node.outEdges[1].to];
      } else {
        return [node.outEdges[1].to, node.outEdges[0].to];
      }
    };
    let children = dominatorTree; //basicBlockTree;

    // Determine back edges.
    for (const edge of this._edges) {
      edge.back =
        edge.to == edge.from || strictlyDominates[edge.to].has(edge.from);
    }

    let exits = [];
    for (const node of this.nodes) {
      let forwardOutEdges = 0;
      for (const edge of node.outEdges) {
        if (!edge.back) {
          forwardOutEdges++;
        }
      }
      if (forwardOutEdges == 0) {
        exits.push(node);
      }
    }

    // Is graph acyclic?
    var colors: { [node: string]: string } = {};
    for (let node of Object.keys(this._nodes)) {
      colors[node] = 'white';
    }
    dfs = (node: string) => {
      if (colors[node] == 'black') {
        return;
      } else if (colors[node] == 'gray') {
        console.error('Graph not acyclic', node);
        return;
      }
      colors[node] = 'gray';
      for (let edge of this._nodes[node].outEdges) {
        if (edge.back) continue;
        dfs(edge.to);
      }
      colors[node] = 'black';
    };
    dfs(entry.id);

    const reversePostOrder: string[] = [];
    colors = {};
    dfs = (node: string) => {
      if (colors.hasOwnProperty(node)) {
        return;
      }
      colors[node] = 'gray';
      for (const edge of this._nodes[node].inEdges) {
        if (edge.back) {
          continue;
        }
        dfs(edge.from);
      }

      reversePostOrder.push(node);
      colors[node] = 'black';
    };
    for (const node of exits) {
      dfs(node.id);
    }

    // Preliminary layout.
    visited.clear();
    const layoutChunk = (root: string) => {
      let bbox = new BBox(0, 0, 0, 0);
      const layers: { [y: number]: string[] } = {
        0: [root],
      };
      this._nodes[root].subtreeBBox = new BBox(
        0,
        0,
        this._nodes[root].width,
        this._nodes[root].height,
      );
      for (const node of reversePostOrder) {
        if (!immediatelyDominates[root].has(node)) {
          continue;
        }
        let minY = 0;
        for (let edge of this._nodes[node].inEdges) {
          if (
            edge.back ||
            (root != edge.from && !strictlyDominates[root].has(edge.from))
          ) {
            continue;
          }
          let parentNode = this._nodes[edge.from];
          let betterParent = parentNode.id;
          while (
            idom.hasOwnProperty(betterParent) &&
            root != betterParent &&
            !immediatelyDominates[root].has(betterParent)
          ) {
            betterParent = idom[betterParent];
          }
          let offsetY;
          if (this._nodes[betterParent].subtreeBBox) {
            offsetY =
              this._nodes[betterParent].subtreeBBox.y +
              this._nodes[betterParent].subtreeBBox.height +
              30;
          } else {
            offsetY = this._nodes[betterParent].height + 30;
          }
          minY = Math.max(minY, offsetY);
        }
        this._nodes[node].subtreeBBox.y = minY;
        if (layers.hasOwnProperty(minY)) {
          let sibling = this._nodes[layers[minY].slice(-1)[0]];
          this._nodes[node].subtreeBBox.x =
            sibling.subtreeBBox.x + sibling.subtreeBBox.width + 30;
          layers[minY].push(node);
        } else {
          this._nodes[node].subtreeBBox.x = 30;
          layers[minY] = [node];
        }
        bbox = bbox.union(this._nodes[node].subtreeBBox.grow(0, 0, 30, 30));
      }
      this._nodes[root].subtreeBBox = bbox.union(this._nodes[root].subtreeBBox);
      this._nodes[root].x =
        (this._nodes[root].subtreeBBox.width - this._nodes[root].width) / 2.0;
      for (let layer of Object.values(layers)) {
        let leftmost = this._nodes[layer[0]];
        let rightmost = this._nodes[layer[layer.length - 1]];
        let layerWidth =
          rightmost.subtreeBBox.x +
          rightmost.subtreeBBox.width -
          leftmost.subtreeBBox.x;
        let layerOffset =
          (this._nodes[root].subtreeBBox.width - layerWidth) / 2.0 -
          leftmost.subtreeBBox.x;
        for (let node of layer) {
          if (node == root) {
            continue;
          }
          this._nodes[node].subtreeBBox.x += layerOffset;
        }
      }
    };
    dfs = function (node: string) {
      if (visited.has(node)) {
        return;
      }
      visited.add(node);
      let x = 0;
      for (let child of children(node)) {
        if (visited.has(child)) {
          continue;
        }
        dfs(child);
      }
      layoutChunk(node);
    };
    dfs(entry.id);

    visited.clear();
    const otherDfs = (node: string, offsetX: number, offsetY: number) => {
      if (visited.has(node)) {
        return;
      }
      visited.add(node);
      this._nodes[node].subtreeBBox.x += offsetX;
      this._nodes[node].subtreeBBox.y += offsetY;
      this._nodes[node].x += this._nodes[node].subtreeBBox.x;
      this._nodes[node].y += this._nodes[node].subtreeBBox.y;
      for (let child of children(node)) {
        if (visited.has(child)) {
          continue;
        }
        otherDfs(
          child,
          this._nodes[node].subtreeBBox.x,
          this._nodes[node].subtreeBBox.y,
        );
      }
    };
    otherDfs(entry.id, 0, 0);

    for (let edge of this._edges) {
      let from = this._nodes[edge.from];
      let to = this._nodes[edge.to];
      var offsetX = 0;
      if (edge.type == 'fallthrough') {
        offsetX = -5;
      } else if (edge.type == 'jump') {
        offsetX = 5;
      }
      edge.points = [
        { x: from.x + from.width / 2.0 + offsetX, y: from.y + from.height },
        { x: to.x + (to.width - 15 * to.inEdges.length) / 2.0, y: to.y },
      ];
      for (let i = 0; i < to.inEdges.length; i++) {
        if (to.inEdges[i] == edge) {
          edge.points[1].x += 15 * i;
          break;
        }
      }
      if (edge.points[1].y > edge.points[0].y) {
        edge.points.splice(
          1,
          0,
          { x: edge.points[0].x, y: edge.points[1].y - 15 },
          { x: edge.points[1].x, y: edge.points[1].y - 15 },
        );
      }
    }
    this._dirty = false;
  }

  get dirty() {
    return this._dirty;
  }

  get nodes() {
    return Object.values(this._nodes);
  }

  get edges() {
    return this._edges;
  }
}
