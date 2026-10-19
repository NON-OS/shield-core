import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";

const steps = [
  "Proved and sealed in this browser",
  "Settling on the pool, from your account",
  "Settled",
];

function list(now) {
  return h(
    "ol",
    { class: "steps", "aria-label": "Where this spend is" },
    steps.map((s, i) =>
      h(
        "li",
        { class: i === now ? "now" : null, "aria-current": i === now ? "step" : null },
        h("span", { class: "mark", "aria-hidden": "true" }, i < now ? "✓" : i === now ? "●" : "○"),
        h("span", {}, s),
      ),
    ),
  );
}

/**
 * A proved spend, settled by its owner. A browser cannot reach the landers, which are onion
 * services, so the settlement is sent from the public account, as the apps offer when no lander
 * lands a spend. What that reveals is said before it is confirmed.
 */
export function ticket(p) {
  const t = p.ticket;
  const gave = t.weakened?.length ? `gave up ${t.weakened.join(", ")}` : "all kept";
  if (p.settled) {
    const status = p.status ?? "pending";
    if (status === "pending" && !p.polling) {
      p.polling = true;
      untilMined(app, "sepolia", p.settled.hash, (s) => {
        if (app.screen === "spend" && app.params.settled === p.settled && s !== "pending") {
          app.show("spend", { ...p, status: s });
        }
      });
    }
    const line = {
      pending: "Settling on the pool.",
      confirmed: "Settled on the pool.",
      failed: "Your settlement failed on chain. Take back returns the notes.",
    }[status];
    return [
      list(status === "confirmed" ? 3 : 1),
      h("p", { class: "statement", role: "status" }, line),
      facts([
        ["lander", "you"],
        ["anonymity defaults", gave],
        ["settlement", p.settled.hash],
      ]),
      h(
        "div",
        { class: "actions" },
        status === "failed" &&
          button("Take back", () => app.run(async () => app.call("takeBackPending"))),
        button("Done with this spend", () => app.show("shield")),
      ),
    ];
  }
  const review = () =>
    app.run(async () => {
      app.show("spend", { ...p, review: await app.call("reviewSelfSettle") });
    });
  const settle = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", p.review.id);
      app.show("spend", { ...p, review: null, settled: sent });
    });
  const r = p.review;
  return [
    list(1),
    h("p", { class: "statement" }, "Proved and sealed in this browser."),
    h(
      "p",
      { class: "lead" },
      "A browser cannot reach the landers, which are onion services, so you settle this spend from your public account. That links the account to this spend in public. The amount and the recipient stay inside the proof, and the lander's part of the fee comes back to you.",
    ),
    r?.refusal && h("p", { class: "statement" }, r.refusal),
    r && !r.refusal && facts([["network fee, at most", `${r.maxNetworkFee} ETH`]]),
    facts([["anonymity defaults", gave]]),
    h(
      "div",
      { class: "actions" },
      r && !r.refusal
        ? button("Confirm and settle", settle, { busy: "Sending" })
        : button("Review the settlement", review, { busy: "Working it out" }),
    ),
  ];
}
