import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";
import { giveKey } from "../device/key.js";
import { copyThenClear } from "../ui/copy.js";

export function keys() {
  const p = app.params;
  const words = () =>
    app.run(async () => {
      await giveKey(app);
      app.show("keys", { words: await app.call("recoveryWords") });
    });
  const key = () =>
    app.run(async () => {
      await giveKey(app);
      const account = app.accounts?.find((a) => a.active)?.index ?? 0;
      app.show("keys", { key: await app.call("exportPublicKey", account) });
    });
  return frame(
    "06",
    "Keys",
    p.words &&
      h(
        "ol",
        { class: "words", "aria-label": "Recovery words, in order" },
        p.words.map((w, i) => h("li", {}, `${i + 1}. ${w}`)),
      ),
    p.key && [
      h(
        "p",
        { class: "warning" },
        "This key moves everything the public account holds, on every network. Anyone who sees it owns the account.",
      ),
      h("p", { class: "address" }, p.key),
      button("Copy, cleared in a minute", () => copyThenClear(p.key), {
        kind: "outline",
        busy: "Copied",
      }),
    ],
    !p.words &&
      !p.key &&
      h(
        "div",
        { class: "actions" },
        button("Show the recovery words", words, { kind: "outline", busy: "Asking the passkey" }),
        button("Export the account private key", key, {
          kind: "outline",
          busy: "Asking the passkey",
        }),
      ),
    h(
      "button",
      { type: "button", class: "link", onclick: () => app.show("settings") },
      p.words || p.key ? "Hide and go back" : "Back",
    ),
  );
}
