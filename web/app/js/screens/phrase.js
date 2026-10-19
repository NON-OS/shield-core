import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

export function phrase() {
  const words = app.params.words ?? [];
  return frame(
    {
      number: "01",
      title: "Recovery phrase",
      backdrop: "backup",
      footer: [
        button("I have written them down", () => {
          app.params.words?.fill("");
          app.show("overview");
        }),
      ],
    },
    h("p", { class: "statement" }, "Write these 24 words down."),
    h(
      "p",
      { class: "lead" },
      "On paper, not in a photo and not in a manager that syncs. They restore the keys, the accounts and every note sent to this wallet. A deposit's note stays on this device until it is sent privately; Home says when one is waiting.",
    ),
    h(
      "ol",
      { class: "words", "aria-label": "Recovery words, in order" },
      words.map((w, i) => h("li", {}, `${i + 1}. ${w}`)),
    ),
  );
}
