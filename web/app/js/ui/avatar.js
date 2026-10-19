import { h } from "./h.js";

// A circle coloured from an address, as both apps draw it: two hues from its hex digits, so each
// account is known at a glance. It carries nothing beyond the address it is drawn from.
const hue = (address, at) => {
  const digits = address
    .toLowerCase()
    .replace(/^0x/, "")
    .slice(at, at + 6);
  return (parseInt(digits, 16) || 0) % 360;
};

export function avatar(address) {
  const el = h("span", { class: "avatar", "aria-hidden": "true" });
  // HSV saturation 0.55 and value 0.85, as the apps use, in the HSL the browser takes.
  const colour = (h) => `hsl(${h} 49% 62%)`;
  el.style.background = `linear-gradient(135deg, ${colour(hue(address, 0))}, ${colour(hue(address, 8))})`;
  return el;
}
