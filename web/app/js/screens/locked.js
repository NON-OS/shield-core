import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
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
    "02",
    "Locked",
    h("p", { class: "statement" }, "This wallet is sealed."),
    h(
      "p",
      { class: "lead" },
      "The seed is under a key your passkey derives. Unlocking asks the passkey for it.",
    ),
    facts([
      ["key held in", "a passkey"],
      ["released", "after you are verified"],
    ]),
    h(
      "div",
      { class: "actions" },
      button("Unlock", unlock, { busy: "Unlocking" }),
      h(
        "button",
        { type: "button", class: "link", onclick: () => app.show("wipe", { back: "locked" }) },
        "The passkey is gone",
      ),
    ),
  );
}
