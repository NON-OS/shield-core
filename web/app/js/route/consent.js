// The question the page asks when the mixnet failed a request after its retries. Nothing goes
// direct without an answer here, and no answer is stored: "Stay on Nym", the first and the one
// in focus, lets the request fail; "Connect directly" covers the one request; "Directly until I
// close the page" turns Nym off until then. One question is open at a time; a request that fails
// while it is open waits for the same answer.

import { h } from "../ui/h.js";

let open = null;

export function consent(host) {
  if (open) return open;
  open = new Promise((resolve) => {
    const before = document.activeElement;
    const answer = (choice) => () => {
      sheet.remove();
      open = null;
      before?.focus?.();
      resolve(choice);
    };
    const choose = (label, choice, kind = "") =>
      h(
        "button",
        { type: "button", class: `action ${kind}`.trim(), onclick: answer(choice) },
        label,
      );
    const sheet = h(
      "div",
      {
        class: "consent",
        role: "alertdialog",
        "aria-modal": "true",
        "aria-labelledby": "consent-q",
      },
      h(
        "div",
        { class: "consent-body" },
        h("p", { class: "statement", id: "consent-q" }, "Nym isn't reachable. Connect directly?"),
        h("p", { class: "lead" }, "Your IP address becomes visible to the network provider."),
        h("p", { class: "lead" }, `The request is for ${host}.`),
        choose("Stay on Nym", "stay"),
        choose("Connect directly", "once", "outline"),
        choose("Directly until I close the page", "session", "outline"),
      ),
    );
    document.body.append(sheet);
    sheet.querySelector("button").focus();
  });
  return open;
}
