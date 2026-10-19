import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";
import { newKey } from "../device/new-key.js";
import { passkey } from "../device/passkey.js";
import { storage } from "../device/storage.js";
import { quiet } from "../ui/quiet.js";
import { watchInstall } from "../state/install.js";

async function create() {
  await app.run(async () => {
    await newKey(app);
    await storage.keep();
    const words = await app.call("create");
    app.show("phrase", { words });
  });
}

export function welcome() {
  return frame(
    {
      number: "01",
      title: "NØNOS",
      backdrop: "welcome",
      footer: [
        button("Create a wallet", create, { busy: "Making the passkey" }),
        button("Restore from a phrase", () => app.show("restore"), { kind: "outline" }),
      ],
    },
    h("img", {
      class: "wordmark large",
      src: new URL("../../images/wordmark.svg", import.meta.url).href,
      alt: "NØNOS",
    }),
    h("p", { class: "statement" }, "Shielded NOX. The keys never leave this device."),
    h(
      "p",
      { class: "lead" },
      "The balance is worked out here, from the pool itself. No server is told which notes are yours.",
    ),
    !watchInstall.installed() &&
      h(
        "p",
        { class: "lead" },
        "Add the page to the home screen first, and make the wallet there: an installed app's storage is kept, where a tab's can be cleared, and on iPhone it is apart from Safari's.",
      ),
    !watchInstall.installed() &&
      quiet([
        [
          "Add to the home screen",
          () => (app.install ? app.install() : app.show("install", { back: "welcome" })),
        ],
      ]),
  );
}

/** Whether this browser can guard a wallet at all, asked before the welcome is shown. */
welcome.possible = () => passkey.supported();
