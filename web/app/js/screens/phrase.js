import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

export function phrase() {
  const words = app.params.words ?? [];
  return frame(
    "01",
    "Recovery phrase",
    h("p", { class: "statement" }, "Write these 24 words down."),
    h(
      "p",
      { class: "lead" },
      "On paper, not in a photo and not in a manager that syncs. These words are the wallet: nothing else can restore it.",
    ),
    h(
      "ol",
      { class: "words", "aria-label": "Recovery words, in order" },
      words.map((w, i) => h("li", {}, `${i + 1}. ${w}`)),
    ),
    h(
      "div",
      { class: "actions" },
      button("I have written them down", () => {
        app.params.words?.fill("");
        app.show("overview");
      }),
    ),
  );
}
