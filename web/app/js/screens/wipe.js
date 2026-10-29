import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

export function wipe() {
  const back = app.params.back ?? "settings";
  const destroy = () =>
    app.run(async () => {
      await app.call("wipe").catch(() => undefined);
      await app.store.wipe();
      await app.wallet.restart();
      app.chain = app.shielded = app.public = app.accounts = app.spend = null;
      app.show("welcome");
    });
  return frame(
    {
      number: "04",
      title: "Settings",
      backdrop: "settings",
      back: () => app.show(back),
      footer: [
        button("Keep this wallet", () => app.show(back)),
        button("Destroy it", destroy, { kind: "danger", busy: "Destroying" }),
      ],
    },
    h(
      "p",
      { class: "statement" },
      "This removes the seed, the notes and the key that seals them from this device. The 24 words are the only way back. Without them the balance is gone.",
    ),
  );
}
