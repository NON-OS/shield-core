import { h } from "../h.js";
import { matrix } from "./matrix.js";

/** `text` as a QR code image, drawn here with a quiet zone, with `label` for a screen reader. */
export function qr(text, label) {
  const modules = matrix(text);
  if (!modules) return null;
  const quiet = 4;
  const scale = 4;
  const size = (modules.length + quiet * 2) * scale;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const g = canvas.getContext("2d");
  g.fillStyle = "#ffffff";
  g.fillRect(0, 0, size, size);
  g.fillStyle = "#0a0b0d";
  modules.forEach((row, y) =>
    row.forEach(
      (dark, x) => dark && g.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale),
    ),
  );
  return h("img", {
    class: "qr",
    src: canvas.toDataURL("image/png"),
    alt: label,
    width: size,
    height: size,
  });
}
