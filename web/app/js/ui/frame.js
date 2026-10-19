import { h } from "./h.js";
import { back as chevron } from "./back.js";
import { app } from "../state/app.js";

// Set through the style object, which the page's CSP allows, where a style attribute it would not.
function band(name) {
  const el = h("div", { class: "backdrop", "aria-hidden": "true" });
  el.style.backgroundImage = `url("${new URL(`../../images/etna/${name}.webp`, import.meta.url).href}")`;
  return el;
}

/**
 * A screen as the apps lay it out: the bar with its number and title and Back where there is one,
 * the Etna band, any failure the last action met, the content, the actions pinned at the foot, and
 * the status line that says how this page reaches the network.
 */
export function frame({ number, title, back, backdrop, footer }, ...content) {
  const failure =
    app.failure &&
    h(
      "div",
      { class: "failure", role: "alert" },
      h("p", {}, app.failure),
      h("button", { type: "button", class: "dismiss", onclick: () => app.clear() }, "Dismiss"),
    );
  const update =
    app.updateReady &&
    h(
      "div",
      { class: "update", role: "status" },
      h("p", {}, "Update ready. The new release opens after a reload."),
      h("button", { type: "button", class: "take", onclick: () => app.updateReady() }, "Reload"),
    );
  const status = [
    app.offline ? "offline" : "browser, direct",
    app.network === "mainnet" ? "mainnet, real money" : "sepolia, test",
    app.version,
  ].filter(Boolean);
  return h(
    "div",
    { class: "screen" },
    h(
      "header",
      { class: "bar" },
      back && chevron(back),
      h("h1", { tabindex: "-1", class: back ? null : "lone" }, `${number}  ${title}`),
    ),
    h("hr", { class: "rule" }),
    backdrop && band(backdrop),
    h("div", { class: "content" }, update, failure, ...content),
    footer?.length && h("div", { class: "footer" }, ...footer),
    h("footer", { class: "status" }, status.join("  ·  ")),
  );
}
