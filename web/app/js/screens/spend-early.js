import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { app } from "../state/app.js";

/** The apps' prompt for notes too new to blend in, with their exact words. */
export function early(p) {
  const word = field("Type EARLY to send now anyway", { autocapitalize: "characters" });
  const go = button("Send now anyway", () =>
    app.show("spend", {
      ...p,
      tooSoon: false,
      proving: true,
      early: true,
      running: null,
      startedAt: null,
    }),
  );
  go.disabled = true;
  word.input.addEventListener("input", () => {
    go.disabled = word.input.value.trim() !== "EARLY";
  });
  return {
    body: [
      h("p", { class: "statement" }, "These notes are still new."),
      h(
        "p",
        { class: "lead" },
        "The pool must add 20 more notes and six hours must pass before they blend in. Sent now, anyone watching can link your deposit to this spend by its timing.",
      ),
      word,
    ],
    footer: [go, button("Wait instead", () => app.show("shield"), { kind: "outline" })],
  };
}
