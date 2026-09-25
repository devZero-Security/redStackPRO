// What jsdom does not implement and React Flow needs.
//
// React Flow measures the pane to place nodes, and jsdom has no layout engine,
// so every measurement is zero unless something stands in. None of this is
// pretending the canvas renders correctly. It is the minimum that lets the
// component mount so the save and load behaviour around it can be exercised.

import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

class DOMMatrixReadOnlyStub {
  constructor(transform) {
    const [a, b, c, d, e, f] = (transform || "")
      .match(/matrix\(([^)]+)\)/)?.[1]
      .split(",")
      .map(Number) || [1, 0, 0, 1, 0, 0];
    Object.assign(this, { m22: d ?? 1, a, b, c, d, e, f });
  }
}

global.ResizeObserver = ResizeObserverStub;
global.DOMMatrixReadOnly = DOMMatrixReadOnlyStub;
global.DOMMatrix = DOMMatrixReadOnlyStub;

if (!global.crypto) global.crypto = {};
if (!global.crypto.randomUUID) {
  let counter = 0;
  global.crypto.randomUUID = () => `test-key-${(counter += 1)}`;
}

Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
  configurable: true,
  get() {
    return parseFloat(this.style.height) || 400;
  },
});
Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
  configurable: true,
  get() {
    return parseFloat(this.style.width) || 800;
  },
});
Object.defineProperty(SVGElement.prototype, "getBBox", {
  configurable: true,
  value: () => ({ x: 0, y: 0, width: 0, height: 0 }),
});

afterEach(cleanup);
