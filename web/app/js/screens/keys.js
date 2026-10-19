import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { quiet } from "../ui/quiet.js";
import { valueBlock } from "../ui/value-block.js";
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
    {
      number: "06",
      title: "Keys",
      backdrop: "backup",
      back: () => app.show("settings"),
      footer: p.key
        ? [
            button("Copy, cleared in a minute", () => copyThenClear(p.key), {
              kind: "outline",
              busy: "Copied",
            }),
          ]
        : [],
    },
    p.words &&
      h(
        "ol",
        { class: "words", "aria-label": "Recovery words, in order" },
        p.words.map((w, i) => h("li", {}, `${i + 1}. ${w}`)),
      ),
    p.key && [
      h(
        "p",
        { class: "lead" },
        "This key moves everything the public account holds, on every network. Anyone who sees it owns the account.",
      ),
      valueBlock(p.key),
    ],
    !p.words &&
      !p.key &&
      quiet([
        ["Show the recovery words", words],
        ["Export the account private key", key],
      ]),
  );
}
