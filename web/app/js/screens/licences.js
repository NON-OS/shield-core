import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { app } from "../state/app.js";

export function licences() {
  return frame(
    "05",
    "Licences",
    h(
      "p",
      {},
      "The wallet core and this page are free software under the GNU AGPL, version 3 or later.",
    ),
    h(
      "p",
      {},
      "Geist and JetBrains Mono are under the SIL Open Font License 1.1: ",
      h("a", { href: new URL("../../fonts/Geist-OFL.txt", import.meta.url).href }, "Geist"),
      ", ",
      h(
        "a",
        { href: new URL("../../fonts/JetBrainsMono-OFL.txt", import.meta.url).href },
        "JetBrains Mono",
      ),
      ".",
    ),
    h("button", { type: "button", class: "link", onclick: () => app.show("settings") }, "Back"),
  );
}
