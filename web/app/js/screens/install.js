import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { app } from "../state/app.js";

/** Where a browser without an install prompt keeps "Add to Home Screen". */
export function install() {
  return frame(
    {
      number: "04",
      title: "Add to the home screen",
      backdrop: "settings",
      back: () => app.show("settings"),
    },
    h("p", { class: "statement" }, "On iPhone and iPad, in Safari."),
    h(
      "p",
      { class: "lead" },
      "Tap Share, then Add to Home Screen, then Add. The wallet then opens on its own, without the browser's bar, and works without a network for everything but reading the chain.",
    ),
    h("p", { class: "statement" }, "On Android and computers."),
    h(
      "p",
      { class: "lead" },
      "Chrome and Edge offer Install in their menu, or in the address bar. Once the page has been open a moment, Settings shows Add to the home screen as a button.",
    ),
  );
}
