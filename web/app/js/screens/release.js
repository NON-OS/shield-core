import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { facts } from "../ui/facts.js";
import { valueBlock } from "../ui/value-block.js";
import { app } from "../state/app.js";

/** What was served, and how anyone can check it against the source. */
export function release() {
  return frame(
    {
      number: "04",
      title: "Check this release",
      backdrop: "settings",
      back: () => app.show("settings"),
    },
    facts([["release", app.version]]),
    h("p", { class: "label" }, "Manifest hash"),
    valueBlock(app.manifestHash ?? ""),
    h(
      "p",
      { class: "lead" },
      "This page is a set of static files. The release manifest lists each one with its SHA-256, and its own hash is above. Building the same commit gives the same files, and web/scripts/check-live.mjs in the source compares the live site with the manifest, file by file.",
    ),
    h("a", { href: "release-manifest.json" }, "The release manifest"),
  );
}
