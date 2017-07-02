function extend(a, b) {
  for (const key in b) {
    if (!b.hasOwnProperty(key)) {
      continue;
    }
    a[key] = b[key];
  }
  return a;
}

Set.prototype.equals = function(setB) {
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

Set.prototype.union = function(setB) {
  let union = new Set(this);
  for (let elem of setB) {
    union.add(elem);
  }
  return union;
};

Set.prototype.intersection = function(setB) {
  let intersection = new Set();
  for (let elem of setB) {
    if (this.has(elem)) {
      intersection.add(elem);
    }
  }
  return intersection;
};

Set.prototype.difference = function(setB) {
  let difference = new Set(this);
  for (let elem of setB) {
    difference.delete(elem);
  }
  return difference;
};

class BBox {
  constructor(x, y, w, h) {
    this.x = x || 0;
    this.y = y || 0;
    this.width = w || -1;
    this.height = h || -1;
  }

  get empty() {
    return this.width < 0 || this.height < 0;
  }

  union(box) {
    if (this.empty) {
      return box;
    }
    if (box.empty) {
      return this;
    }
    let left = Math.min(this.x, box.x),
      top = Math.min(this.y, box.y),
      right = Math.max(this.x + this.width, box.x + box.width),
      bottom = Math.max(this.y + this.height, box.y + box.height);
    return new BBox(left, top, right - left, bottom - top);
  }

  grow(left, top, right, bottom) {
    return new BBox(
      this.x - left,
      this.y - top,
      this.width + (left + right),
      this.height + (top + bottom)
    );
  }
}

class Graph {
  constructor() {
    this.clear();
  }

  clear() {
    this._nodes = {};
    this._edges = [];
    this._dirty = false;
  }

  getNode(id) {
    return this._nodes[id];
  }

  setNode(id, node) {
    this._dirty = true;
    this._nodes[id] = extend(
      {
        id: id,
        x: 0,
        y: 0,
        inEdges: [],
        outEdges: [],
      },
      node
    );
  }

  setEdge(from, to, data) {
    this._dirty = true;
    this._edges.push(
      extend({ from: from, to: to, back: false, points: [] }, data)
    );
  }

  layout() {
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

    let dominators = {};
    dominators[entry.id] = new Set([entry.id]);
    let allNodes = new Set();
    for (let node of this.nodes) {
      allNodes.add(node.id);
    }
    for (let node of this.nodes) {
      if (node == entry) {
        continue;
      }
      dominators[node.id] = allNodes;
    }
    let dirty = true;
    while (dirty) {
      dirty = false;
      for (let key of allNodes) {
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

    let strictlyDominates = {};
    for (let node of this.nodes) {
      for (let dominator of dominators[node.id]) {
        if (!strictlyDominates.hasOwnProperty(dominator)) {
          strictlyDominates[dominator] = new Set();
        }
        if (dominator != node.id) {
          strictlyDominates[dominator].add(node.id);
        }
      }
    }

    let immediatelyDominates = {};
    let idom = {};
    for (let node in strictlyDominates) {
      let result = strictlyDominates[node];
      for (let child of strictlyDominates[node]) {
        result = result.difference(strictlyDominates[child]);
      }
      immediatelyDominates[node] = result;
      for (let child of immediatelyDominates[node]) {
        if (idom.hasOwnProperty(child)) {
          throw new Error(
            'Node ' + child + "'s immediate dominator is non-unique"
          );
        }
        idom[child] = node;
      }
    }
    if (Object.keys(idom).length != this.nodes.length - 1) {
      throw new Error('Incomplete immediate dominator list');
    }

    let dfs;
    let visited = new Set();
    let dominatorTree = function(node) {
      let keys = Array.from(immediatelyDominates[node].values());
      keys.sort();
      return keys;
    };
    let basicBlockTree = function(id) {
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
    }.bind(this);
    let children = dominatorTree; //basicBlockTree;

    // Determine back edges.
    for (let edge of this._edges) {
      edge.back =
        edge.to == edge.from || strictlyDominates[edge.to].has(edge.from);
    }

    let exits = [];
    for (let node of this.nodes) {
      let forwardOutEdges = 0;
      for (let edge of node.outEdges) {
        if (!edge.back) {
          forwardOutEdges++;
        }
      }
      if (forwardOutEdges == 0) {
        exits.push(node);
      }
    }

    // Is graph acyclic?
    var colors = {};
    for (let node of Object.keys(this._nodes)) {
      colors[node] = 'white';
    }
    dfs = function(node) {
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
    }.bind(this);
    dfs(entry.id);

    let reversePostOrder = [];
    colors = {};
    dfs = function(node) {
      if (colors.hasOwnProperty(node)) {
        return;
      }
      colors[node] = 'gray';
      for (let edge of this._nodes[node].inEdges) {
        if (edge.back) {
          continue;
        }
        dfs(edge.from);
      }

      reversePostOrder.push(node);
      colors[node] = 'black';
    }.bind(this);
    for (let node of exits) {
      dfs(node.id);
    }

    // Preliminary layout.
    visited.clear();
    let layoutChunk = function(root) {
      let bbox = new BBox();
      let layers = {
        0: [root],
      };
      this._nodes[root].subtreeBBox = new BBox(
        0,
        0,
        this._nodes[root].width,
        this._nodes[root].height
      );
      for (let node of reversePostOrder) {
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
    }.bind(this);
    dfs = function(node) {
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
    }.bind(this);
    dfs(entry.id);

    visited.clear();
    dfs = function(node, offsetX, offsetY) {
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
        dfs(
          child,
          this._nodes[node].subtreeBBox.x,
          this._nodes[node].subtreeBBox.y
        );
      }
    }.bind(this);
    dfs(entry.id, 0, 0);

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
          { x: edge.points[1].x, y: edge.points[1].y - 15 }
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
