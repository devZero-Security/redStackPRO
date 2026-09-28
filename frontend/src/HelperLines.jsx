import React from "react";
import { useStore } from "@xyflow/react";

// The guide lines the alignment engine asks for, drawn across the whole pane so
// they read as "this edge lines up with that one" rather than a short tick. They
// live inside the React Flow container and track the viewport, so a line pinned
// to a flow coordinate stays on its shape while the canvas pans and zooms.
//
// `vertical` is a flow x coordinate, `horizontal` a flow y. Either may be
// undefined when only one axis is aligned.
export function HelperLines({ vertical, horizontal }) {
  const [tx, ty, zoom] = useStore((state) => state.transform);
  if (vertical === undefined && horizontal === undefined) return null;
  return (
    <>
      {vertical !== undefined ? (
        <div className="rg-guide rg-guide-v" style={{ left: tx + vertical * zoom }} />
      ) : null}
      {horizontal !== undefined ? (
        <div className="rg-guide rg-guide-h" style={{ top: ty + horizontal * zoom }} />
      ) : null}
    </>
  );
}
