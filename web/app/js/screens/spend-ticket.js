import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { valueBlock } from "../ui/value-block.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";
import { inFlight } from "../state/in-flight.js";
import { zip } from "../files/zip.js";
import { save } from "../files/save.js";
import { steps } from "./landing-steps.js";
import { settleProgress } from "../ui/settle-progress.js";

async function share(files) {
  const read = await Promise.all(
    files.map(async (path) => [path.split("/").pop(), await app.wallet.readFile(path)]),
  );
  save(zip(read.filter(([, bytes]) => bytes)), "nonos-spend.zip");
}

const headline = (status) =>
  ({
    pending: "Settling on the pool.",
    confirmed: "Settled on the pool.",
    failed: "Your settlement failed on chain. Take back returns the notes.",
  })[status] ?? "Proved and sealed on this device.";

/**
 * A proved spend, settled by its owner. A browser cannot reach the landers, which are onion
 * services, so this is the apps' "settle it yourself": the settlement goes from the public
 * account, and what that reveals is said before it is confirmed.
 */
export function ticket(p) {
  const t = p.ticket;
  const gave = t.weakened?.length ? `gave up ${t.weakened.join(", ")}` : "all kept";
  const status = p.settled ? (p.status ?? "pending") : null;
  if (p.settled && status === "pending" && !p.polling) {
    p.polling = true;
    p.watch = { sentAt: p.settled.at ?? Date.now(), checks: 0, lastCheck: null };
    const counted = (seconds) => {
      p.watch.checks += 1;
      p.watch.lastCheck = seconds;
    };
    untilMined(
      app,
      "sepolia",
      p.settled.hash,
      async (s) => {
        if (s === "pending") return;
        if (s === "confirmed") {
          await inFlight.clear(app);
          app.spend = null;
        }
        if (app.screen === "spend" && app.params.settled?.hash === p.settled.hash)
          app.show("spend", { ...p, status: s });
      },
      counted,
    );
  }
  const review = () =>
    app.run(async () => {
      app.show("spend", { ...p, review: await app.call("reviewSelfSettle") });
    });
  const settle = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = { ...(await app.call("confirmPublicSend", p.review.id)), at: Date.now() };
      await inFlight.set(app, { withdraw: p.withdraw, ticket: t, settled: sent });
      app.show("spend", { ...p, review: null, settled: sent });
    });
  const r = p.review;
  const active = app.accounts?.find((a) => a.active);
  const now = status === "confirmed" ? 3 : 1;
  return {
    body: [
      h("p", { class: "statement", role: "status" }, headline(status)),
      steps(now),
      h(
        "section",
        { class: "tile", "aria-label": "This spend" },
        h(
          "div",
          { class: "tile-row" },
          h("span", { class: "name" }, "Lander"),
          h("span", { class: "value" }, "you"),
        ),
        h(
          "div",
          { class: "tile-row" },
          h("span", { class: "name" }, "Anonymity defaults"),
          h("span", { class: "value" }, gave),
        ),
      ),
      !p.settled &&
        h(
          "p",
          { class: "lead" },
          "A browser cannot reach the landers, which are onion services. Settling it yourself sends it from your public account, which links that account to this spend in public. The amount and the recipient stay inside the proof, and the lander's part of the fee comes back to you.",
        ),
      r?.refusal && h("p", { class: "statement" }, r.refusal),
      r &&
        !r.refusal &&
        facts([
          ["from", `Account ${(active?.index ?? 0) + 1}`],
          ["network fee, at most", `${r.maxNetworkFee} ETH`],
        ]),
      status === "pending" && p.watch && settleProgress(p.watch),
      p.settled && [
        h("p", { class: "label" }, "Settlement"),
        valueBlock(p.settled.hash),
        button("Copy the hash", () => copyThenClear(p.settled.hash), { kind: "outline" }),
      ],
    ],
    footer: [
      !p.settled &&
        (r && !r.refusal
          ? button("Confirm and settle", settle, { busy: "Sending" })
          : button("Settle it yourself", review, { busy: "Working it out" })),
      status === "failed" &&
        button("Take back", () =>
          app.run(async () => {
            await app.call("takeBackPending");
            await inFlight.clear(app);
            app.spend = null;
            app.show("shield");
          }),
        ),
      button("Share the files instead", () => app.run(() => share(t.files ?? [])), {
        kind: "outline",
      }),
      button("Done", () => app.show("shield"), { kind: "outline" }),
    ].filter(Boolean),
  };
}
