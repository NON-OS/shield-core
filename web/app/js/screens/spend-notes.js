import { h } from "../ui/h.js";
import { app } from "../state/app.js";

/**
 * The apps' notes under the address, checked on every edit as they are: whose account pays, a move
 * to another account of this wallet and its timing, and for a withdrawal whether the address is
 * fresh, used before, or simply public.
 */
export async function notes(p, to, into) {
  const lead = (text) => h("p", { class: "lead" }, text);
  const active = app.accounts?.find((a) => a.active)?.index ?? 0;
  const out = [lead(`From Account ${active + 1}.`)];
  if (p.withdraw) {
    let line = "A withdrawal is public: its amount and the address it pays can be seen by anyone.";
    if (to && to === p.fresh) {
      line =
        "A fresh address of this wallet, never used. The words restore it as the next account.";
    } else if (to.length === 42 && (await app.call("addressUsed", to).catch(() => false))) {
      line =
        "This address has been used before. A withdrawal to it can be linked to its past. A fresh one is safer.";
    }
    out.unshift(lead(line));
  } else if (to) {
    const own = await app.call("ownAccountOf", to).catch(() => null);
    if (own !== null) {
      out.push(
        lead(
          `This moves value to Account ${own + 1} of this wallet, as a private transfer that pays the relay fee.`,
        ),
      );
      if (await app.call("arrivedRecently").catch(() => false)) {
        out.push(
          lead(
            "Some of this value arrived only recently. Moving it on soon after can link the two accounts by timing. Waiting first makes that harder.",
          ),
        );
      }
    }
  }
  into.replaceChildren(...out);
}
