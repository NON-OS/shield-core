import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { quiet } from "../ui/quiet.js";
import { app } from "../state/app.js";
import { newKey } from "../device/new-key.js";
import { storage } from "../device/storage.js";

export function restore() {
  const byKey = app.params.byKey === true;
  const input = byKey
    ? field("Private key", { type: "password" })
    : field("Recovery phrase", { multiline: true });
  const go = () =>
    app.run(async () => {
      const text = input.input.value.trim();
      await newKey(app);
      await storage.keep();
      if (byKey) {
        await app.call("restoreFromKey", text);
        app.show("overview");
        return;
      }
      await app.call("restore", ...text.split(/\s+/));
      app.show("finding");
    });
  return frame(
    {
      number: "01",
      title: "Restore a wallet",
      backdrop: "backup",
      back: () => app.show("welcome"),
      footer: [button("Restore", go, { busy: "Restoring" })],
    },
    h(
      "p",
      { class: "statement" },
      byKey ? "Paste the private key." : "Type the recovery words: 12, 15, 18, 21 or 24.",
    ),
    h(
      "p",
      { class: "lead" },
      byKey
        ? "64 hex digits, 0x optional. The wallet gets one account, and the key stays its backup."
        : "In order, separated by spaces. The core owns the word list and the checksum.",
    ),
    input,
    quiet([
      [
        byKey ? "Use recovery words instead" : "Use a private key instead",
        () => app.show("restore", { byKey: !byKey }),
      ],
    ]),
  );
}
