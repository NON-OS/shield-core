import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { app } from "../state/app.js";

/** After a restore: the accounts the words were used with, looked for once, then the wallet. */
async function look() {
  try {
    await app.call("findAccounts");
    app.show("overview");
  } catch {
    app.show("overview");
    app.fail("The other accounts could not be looked for. Add them in Accounts.");
  }
}

export function finding() {
  // Drawn again on any change, so the search starts only on the first draw.
  app.params.looking ??= look();
  return frame(
    "01",
    "Restore a wallet",
    h(
      "p",
      { class: "lead", role: "status" },
      "Looking for the other accounts these words were used with. Each one is a request from this browser to a public endpoint.",
    ),
    h("div", { class: "progress", "aria-hidden": "true" }, h("span")),
  );
}
