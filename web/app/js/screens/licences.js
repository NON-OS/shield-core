import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { app } from "../state/app.js";

const text = async (name) =>
  (await fetch(new URL(`../../licences/${name}`, import.meta.url))).text();

/** What the build linked, listed from the build itself, then each licence's full text. */
export function licences() {
  const { list, texts } = app.params;
  if (!list) {
    Promise.all([text("licences.txt"), text("licence-texts.txt")]).then(
      ([l, t]) => app.show("licences", { list: l, texts: t, entered: true }),
      (e) => app.fail(e),
    );
  }
  const line = (s) => h("p", { class: "lead mono-line" }, s);
  return frame(
    { number: "06", title: "Licences", backdrop: "settings", back: () => app.show("settings") },
    h(
      "p",
      { class: "lead" },
      "Generated from what the build linked, so it is what the page holds.",
    ),
    list && h("div", { class: "licences" }, list.trim().split("\n").map(line)),
    texts && [
      h("p", { class: "label" }, "Notices"),
      h(
        "div",
        { class: "licences" },
        texts.split("\n\f\n").map((block) => h("pre", { class: "notice" }, block.trim())),
      ),
    ],
  );
}
