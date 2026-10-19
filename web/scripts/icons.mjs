// Draw the home screen icons from the official mark: the cyan Ø on ink, as the apps' icon is.
// Run once when the mark changes; the PNGs are kept with the source.
//
//   node web/scripts/icons.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";

const images = new URL("../app/images/", import.meta.url);
const mark = readFileSync(new URL("mark.svg", images), "utf8");
// The maskable icon keeps the mark inside the middle 80%, the circle every launcher may cut to.
const sizes = [
  ["icon-180.png", 180, 0.5],
  ["icon-192.png", 192, 0.5],
  ["icon-512.png", 512, 0.5],
  ["icon-512-maskable.png", 512, 0.4],
];

const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const page = await browser.newPage();
for (const [name, size, share] of sizes) {
  const png = await page.evaluate(
    async ({ mark, size, share }) => {
      const img = new Image();
      img.src = `data:image/svg+xml;base64,${btoa(mark)}`;
      await img.decode();
      const canvas = Object.assign(document.createElement("canvas"), { width: size, height: size });
      const g = canvas.getContext("2d");
      g.fillStyle = "#0a0b0d";
      g.fillRect(0, 0, size, size);
      const h = size * share;
      const w = (h * img.width) / img.height;
      g.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);
      return canvas.toDataURL("image/png").split(",")[1];
    },
    { mark, size, share },
  );
  writeFileSync(new URL(name, images), Buffer.from(png, "base64"));
}
await browser.close();
