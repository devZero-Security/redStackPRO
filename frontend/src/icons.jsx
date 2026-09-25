// Tabler Icons, MIT licensed, vendored from github.com/tabler/tabler-icons.
// Vendored rather than fetched at runtime, because the audience includes
// restricted environments with no outbound access. The registry names these
// icons; this file supplies the paths.

import React from "react";

const PATHS = {
  "network": "<path d=\"M6 9a6 6 0 1 0 12 0a6 6 0 0 0 -12 0\" /> <path d=\"M12 3c1.333 .333 2 2.333 2 6s-.667 5.667 -2 6\" /> <path d=\"M12 3c-1.333 .333 -2 2.333 -2 6s.667 5.667 2 6\" /> <path d=\"M6 9h12\" /> <path d=\"M3 20h7\" /> <path d=\"M14 20h7\" /> <path d=\"M10 20a2 2 0 1 0 4 0a2 2 0 0 0 -4 0\" /> <path d=\"M12 15v3\" />",
  "box": "<path d=\"M12 3l8 4.5l0 9l-8 4.5l-8 -4.5l0 -9l8 -4.5\" /> <path d=\"M12 12l8 -4.5\" /> <path d=\"M12 12l0 9\" /> <path d=\"M12 12l-8 -4.5\" />",
  "route": "<path d=\"M3 19a2 2 0 1 0 4 0a2 2 0 0 0 -4 0\" /> <path d=\"M19 7a2 2 0 1 0 0 -4a2 2 0 0 0 0 4\" /> <path d=\"M11 19h5.5a3.5 3.5 0 0 0 0 -7h-8a3.5 3.5 0 0 1 0 -7h4.5\" />",
  "server2": "<path d=\"M3 7a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-2\" /> <path d=\"M3 15a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3l0 -2\" /> <path d=\"M7 8l0 .01\" /> <path d=\"M7 16l0 .01\" /> <path d=\"M11 8h6\" /> <path d=\"M11 16h6\" />",
  "database": "<path d=\"M4 6a8 3 0 1 0 16 0a8 3 0 1 0 -16 0\" /> <path d=\"M4 6v6a8 3 0 0 0 16 0v-6\" /> <path d=\"M4 12v6a8 3 0 0 0 16 0v-6\" />",
  "shieldLock": "<path d=\"M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3\" /> <path d=\"M11 11a1 1 0 1 0 2 0a1 1 0 1 0 -2 0\" /> <path d=\"M12 12l0 2.5\" />",
  "deviceDesktop": "<path d=\"M3 5a1 1 0 0 1 1 -1h16a1 1 0 0 1 1 1v10a1 1 0 0 1 -1 1h-16a1 1 0 0 1 -1 -1v-10\" /> <path d=\"M7 20h10\" /> <path d=\"M9 16v4\" /> <path d=\"M15 16v4\" />",
  "sitemap": "<path d=\"M3 15m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z\" /> <path d=\"M15 15m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z\" /> <path d=\"M9 6m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z\" /> <path d=\"M6 15v-4a1 1 0 0 1 1 -1h10a1 1 0 0 1 1 1v4\" /> <path d=\"M12 9l0 6\" />",
  "shieldCheck": "<path d=\"M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06\" /> <path d=\"M15 19l2 2l4 -4\" />",
  "wall": "<path d=\"M4 4m0 1a1 1 0 0 1 1 -1h14a1 1 0 0 1 1 1v14a1 1 0 0 1 -1 1h-14a1 1 0 0 1 -1 -1z\" /> <path d=\"M4 9h16\" /> <path d=\"M4 14h16\" /> <path d=\"M8 4v5\" /> <path d=\"M16 9v5\" /> <path d=\"M9 14v5\" /> <path d=\"M14 14v5\" />",
  "deviceAnalytics": "<path d=\"M3 4m0 1a1 1 0 0 1 1 -1h16a1 1 0 0 1 1 1v10a1 1 0 0 1 -1 1h-16a1 1 0 0 1 -1 -1z\" /> <path d=\"M7 20h10\" /> <path d=\"M9 16v4\" /> <path d=\"M15 16v4\" /> <path d=\"M9 12v-2\" /> <path d=\"M12 12v-4\" /> <path d=\"M15 12v-1\" />",
  "world": "<path d=\"M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0\" /> <path d=\"M3.6 9h16.8\" /> <path d=\"M3.6 15h16.8\" /> <path d=\"M11.5 3a17 17 0 0 0 0 18\" /> <path d=\"M12.5 3a17 17 0 0 1 0 18\" />",
  "folder": "<path d=\"M5 4h4l3 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2\" />",
  "certificate": "<path d=\"M15 15m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0\" /> <path d=\"M13 17.5v4.5l2 -1.5l2 1.5v-4.5\" /> <path d=\"M10 19h-5a2 2 0 0 1 -2 -2v-10c0 -1.1 .9 -2 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-1\" /> <path d=\"M6 9l12 0\" /> <path d=\"M6 12l3 0\" /> <path d=\"M6 15l2 0\" />",
  "trash": "<path d=\"M4 7l16 0\" /> <path d=\"M10 11l0 6\" /> <path d=\"M14 11l0 6\" /> <path d=\"M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12\" /> <path d=\"M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3\" />",
  "terminal2": "<path d=\"M8 9l3 3l-3 3\" /> <path d=\"M13 15l3 0\" /> <path d=\"M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z\" />",
};

// The registry declares "tabler/outline/route"; only the last segment matters.
function keyFor(icon) {
  const last = (icon || "").split("/").pop() || "";
  return last.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
}

export function Icon({ icon, color = "currentColor", size = 18 }) {
  const body = PATHS[keyFor(icon)];
  if (!body) return null;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      dangerouslySetInnerHTML={{ __html: body }}
    />
  );
}

