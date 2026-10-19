import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { app } from "../state/app.js";

const EVERY = 1000;

/** After a restore: the accounts the words were used with, looked for once, then the wallet. */
async function look() {
  try {
    await app.wallet.searchStart();
    for (;;) {
      const { looked, found } = await app.wallet.searchProgress();
      // The screen may have been drawn again since, so the count is found by its id.
      const count = document.getElementById("looked");
      if (count) count.textContent = `Looked at ${looked} so far.`;
      if (found !== null) break;
      await new Promise((r) => setTimeout(r, EVERY));
    }
    app.show("overview");
  } catch {
    app.show("overview");
    app.fail("The other accounts could not be looked for. Add them in Accounts.");
  }
}

export function finding() {
  const count = h("span", { id: "looked" }, "Looked at 0 so far.");
  // Drawn again on any change, so the search starts only on the first draw.
  app.params.looking ??= look();
  return frame(
    "01",
    "Restore a wallet",
    h(
      "p",
      { class: "lead", role: "status", "aria-live": "polite" },
      "Looking for the other accounts these words were used with. ",
      count,
    ),
    h("div", { class: "progress", "aria-hidden": "true" }, h("span")),
  );
}
