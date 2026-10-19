import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { quiet } from "../ui/quiet.js";
import { app } from "../state/app.js";
import { giveKey } from "../device/key.js";

export function locked() {
  const unlock = () =>
    app.run(async () => {
      await giveKey(app);
      await app.call("unlock");
      app.show("overview");
    });
  return frame(
    {
      number: "02",
      title: "Locked",
      backdrop: "history",
      footer: [button("Unlock", unlock, { busy: "Unlocking" })],
    },
    h("p", { class: "statement" }, "This wallet is sealed."),
    h(
      "p",
      { class: "lead" },
      "The seed is under a key your passkey derives. Unlocking asks the passkey for it.",
    ),
    facts([
      ["key held in", "a passkey"],
      ["released", "after you are confirmed"],
    ]),
    quiet([["The passkey is gone", () => app.show("wipe", { back: "locked" })]]),
  );
}
