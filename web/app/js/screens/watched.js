import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { quiet } from "../ui/quiet.js";
import { app } from "../state/app.js";

// An incoming key cannot tell a spent note from an unspent one, so its figure is what arrived.
const figure = (w) =>
  (w.kind === "full" ? "" : "received ") +
  w.balances.map((b) => `${b.spendableText} ${b.coin.toUpperCase()}`).join(" · ");

/** The accounts somebody shared a view key for: they show notes and never send. */
export function watched() {
  const list = app.watched ?? [];
  const key = field("A noxivk1 or noxfvk1 view key", { multiline: true });
  const add = () =>
    app.run(async () => {
      await app.call("importViewKey", key.input.value.trim());
      app.watched = await app.call("watchedAccounts");
      app.draw();
    });
  const forget = (index) =>
    app.run(async () => {
      await app.call("forgetViewKey", index);
      app.watched = await app.call("watchedAccounts");
      app.draw();
    });
  return h(
    "section",
    { class: "field", "aria-label": "View only" },
    h("p", { class: "label" }, "View only"),
    list.length > 0 &&
      h(
        "div",
        { class: "tile" },
        list.map((w) =>
          h(
            "div",
            { class: "tile-row" },
            h("span", { class: "name" }, `View only ${w.index + 1}`),
            h("span", { class: "value" }, figure(w)),
          ),
        ),
      ),
    list.length > 0 &&
      quiet(list.map((w) => [`Forget view only ${w.index + 1}`, () => forget(w.index)])),
    key,
    button("Add the view key", add, { busy: "Adding" }),
  );
}
