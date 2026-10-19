import { h } from "../ui/h.js";
import { quiet } from "../ui/quiet.js";
import { app } from "../state/app.js";
import { steps } from "./landing-steps.js";

/** A spend proved earlier and not settled yet, shown on the shield as the iOS app shows one. */
export function landing(spend) {
  return h(
    "section",
    { "aria-label": "The spend in flight" },
    h(
      "p",
      { class: "lead" },
      spend.settled ? "Settling on the pool." : "Proved and sealed on this device.",
    ),
    steps(1),
    quiet([
      [
        "Settle it yourself",
        () =>
          app.show("spend", {
            withdraw: spend.withdraw,
            ticket: spend.ticket,
            settled: spend.settled,
          }),
      ],
    ]),
  );
}
