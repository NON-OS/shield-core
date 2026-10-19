import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";
import { short } from "../text/short.js";
import { giveKey } from "../device/key.js";

export function accounts() {
  const list = app.accounts ?? [];
  const pick = (index) =>
    app.run(async () => {
      await app.call("selectAccount", index);
      app.accounts = await app.call("accounts");
      app.public = null;
      app.shielded = null;
      app.chain = null;
      app.show("overview");
    });
  return frame(
    "05",
    "Accounts",
    h(
      "ul",
      { class: "actions", "aria-label": "Accounts" },
      list.map((a) =>
        h(
          "li",
          {},
          button(
            `Account ${a.index + 1}  ${a.active ? "In use" : short(a.publicAddress)}`,
            () => pick(a.index),
            { kind: a.active ? "" : "outline" },
          ),
        ),
      ),
    ),
    h(
      "p",
      { class: "lead" },
      "Every account comes from the same recovery words. Moving value between two of them is a private transfer and pays the relay fee.",
    ),
    h(
      "div",
      { class: "actions" },
      button(
        "Add an account",
        () =>
          app.run(async () => {
            // A new account is derived from the seed, so the vault is opened again for it.
            await giveKey(app);
            await app.call("addAccount");
            app.accounts = await app.call("accounts");
            app.draw();
          }),
        { kind: "outline", busy: "Adding" },
      ),
      button("Back", () => app.show("overview"), { kind: "outline" }),
    ),
  );
}

accounts.enter = async () => {
  app.accounts = await app.call("accounts").catch(() => app.accounts);
};
