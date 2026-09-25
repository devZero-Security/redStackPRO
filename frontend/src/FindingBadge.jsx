import React from "react";
import { familyFor, familyTooltip } from "./findingFamilies.js";

// The leading token on a finding, in all three places findings are shown: the
// canvas footer, the inspector, and the export panel. It reads as words and
// carries the code in its tooltip. See findingFamilies.js for why round that
// way, and 0014 for why the canvas is free to choose.
export function FindingBadge({ code }) {
  const family = familyFor(code);
  return (
    <span
      className={`rg-finding-family${family.known ? "" : " is-unknown"}`}
      title={familyTooltip(code)}
      // The code is still in the DOM for anyone reading it out of the page, and
      // for a screen reader, which cannot hover to get the tooltip.
      data-code={code}
      aria-label={familyTooltip(code)}
    >
      {family.label}
    </span>
  );
}
