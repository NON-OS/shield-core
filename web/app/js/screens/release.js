import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";

/** What was served, and how anyone can check it against the source. */
export function release() {
  return frame(
    "05",
    "Check this release",
    facts([
      ["release", app.version],
      ["manifest hash", app.manifestHash ?? "not read"],
    ]),
    h(
      "p",
      { class: "lead" },
      "The page you are using is a set of static files. The release manifest lists each one with its SHA-256, and its own hash is above. Building the same commit gives the same files, and web/scripts/check-live.mjs in the source compares the live site with the manifest, file by file.",
    ),
    h("a", { href: "release-manifest.json" }, "The release manifest"),
    h("button", { type: "button", class: "link", onclick: () => app.show("settings") }, "Back"),
  );
}
