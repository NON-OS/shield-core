import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { quiet } from "../ui/quiet.js";
import { watched } from "./watched.js";
import { app } from "../state/app.js";
import { short } from "../text/short.js";
import { giveKey } from "../device/key.js";

export function accounts() {
  const list = app.accounts ?? [];
  const pick = (index) =>
    app.run(async () => {
      await app.call("selectAccount", index);
      app.accounts = await app.call("accounts");
      app.public = app.shielded = app.chain = null;
      app.show("overview");
    });
  return frame(
    { number: "05", title: "Accounts", backdrop: "settings", back: () => app.show("overview") },
    h(
      "nav",
      { class: "tile", "aria-label": "Accounts" },
      list.map((a) =>
        h(
          "button",
          { type: "button", class: "quiet", disabled: a.active, onclick: () => pick(a.index) },
          `Account ${a.index + 1}  `,
          h("span", { class: "lead" }, a.active ? "In use" : short(a.publicAddress)),
        ),
      ),
    ),
    quiet([
      [
        "Add an account",
        () =>
          app.run(async () => {
            // A new account is derived from the seed, so the vault is opened again for it.
            await giveKey(app);
            await app.call("addAccount");
            app.accounts = await app.call("accounts");
            app.draw();
          }),
      ],
    ]),
    h(
      "p",
      { class: "lead" },
      "Every account comes from the same recovery words. Moving value between two of them is a private transfer and pays the relay fee.",
    ),
    watched(),
  );
}

accounts.enter = async () => {
  app.accounts = await app.call("accounts").catch(() => app.accounts);
  app.watched = await app.call("watchedAccounts").catch(() => []);
};
