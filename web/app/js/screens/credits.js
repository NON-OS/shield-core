import { h } from "../ui/h.js";

/** The apps' About, at the foot of Settings, with the credit the Etna photographs require. */
export function credits() {
  return h(
    "section",
    { class: "field", "aria-label": "About" },
    h("p", { class: "label" }, "About"),
    h(
      "p",
      { class: "lead" },
      "NØNOS Wallet: private payments on Ethereum. NOX is the token; NOX Shield is the private layer.",
    ),
    h("p", { class: "lead" }, "Designed after Etna, the volcano of Sicily, where NØNOS began."),
    h("p", { class: "label" }, "Acknowledgements"),
    h("p", { class: "lead" }, "Etna photographs: gnuckx, CC BY 2.0, recoloured by NØNOS"),
  );
}
