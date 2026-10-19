const NS = "http://www.w3.org/2000/svg";

/** A small SVG drawn from shapes, hidden from screen readers, which read the label beside it. */
export function svg(width, height, shapes) {
  const root = document.createElementNS(NS, "svg");
  root.setAttribute("viewBox", `0 0 ${width} ${height}`);
  root.setAttribute("width", width);
  root.setAttribute("height", height);
  root.setAttribute("aria-hidden", "true");
  root.setAttribute("focusable", "false");
  for (const [tag, attrs] of shapes) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    root.append(el);
  }
  return root;
}
