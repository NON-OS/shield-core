import { h } from "./h.js";
import { app } from "../state/app.js";

/**
 * A screen as the apps lay it out: a numbered heading, any failure the last action met, the
 * content, and the status line that says how this page reaches the network.
 */
export function frame(number, title, ...content) {
  const failure = app.failure
    ? h(
        "div",
        { class: "failure", role: "alert" },
        h("p", {}, app.failure),
        h(
          "button",
          {
            type: "button",
            class: "icon-button",
            onclick: () => app.clear(),
            "aria-label": "Dismiss",
          },
          "Close",
        ),
      )
    : null;
  return [
    h(
      "header",
      { class: "heading" },
      h("span", { class: "number", "aria-hidden": "true" }, number),
      h("h1", { tabindex: "-1" }, title),
    ),
    failure,
    ...content,
    h(
      "footer",
      { class: "status" },
      h("span", {}, "browser, direct"),
      h("span", {}, app.network === "mainnet" ? "mainnet, real money" : "sepolia, test"),
      h("span", {}, app.version),
    ),
  ];
}
