// The iOS launch images: the official mark on ink, for the current iPhone and iPad screens in
// portrait. Safari picks one by the media query beside it in index.html, which this also prints.
// Run once when the mark or the list changes; the PNGs are kept with the source.
//
//   node web/scripts/splash.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";

// CSS width, height and pixel ratio of each screen.
const screens = [
  [440, 956, 3],
  [402, 874, 3],
  [430, 932, 3],
  [393, 852, 3],
  [390, 844, 3],
  [375, 812, 3],
  [414, 896, 3],
  [414, 896, 2],
  [375, 667, 2],
  [744, 1133, 2],
  [820, 1180, 2],
  [834, 1194, 2],
  [1024, 1366, 2],
  [810, 1080, 2],
];

const images = new URL("../app/images/", import.meta.url);
const mark = readFileSync(new URL("mark.svg", images), "utf8");
const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const page = await browser.newPage();
const links = [];
for (const [w, h, r] of screens) {
  const name = `splash-${w * r}x${h * r}.png`;
  const png = await page.evaluate(
    async ({ mark, width, height }) => {
      const img = new Image();
      img.src = `data:image/svg+xml;base64,${btoa(mark)}`;
      await img.decode();
      const canvas = Object.assign(document.createElement("canvas"), { width, height });
      const g = canvas.getContext("2d");
      g.fillStyle = "#0a0b0d";
      g.fillRect(0, 0, width, height);
      const side = Math.min(width, height) * 0.22;
      const tall = (side * img.height) / img.width;
      g.drawImage(img, (width - side) / 2, (height - tall) / 2, side, tall);
      return canvas.toDataURL("image/png").split(",")[1];
    },
    { mark, width: w * r, height: h * r },
  );
  writeFileSync(new URL(name, images), Buffer.from(png, "base64"));
  links.push(
    `    <link rel="apple-touch-startup-image" href="images/${name}" media="(device-width: ${w}px) and (device-height: ${h}px) and (-webkit-device-pixel-ratio: ${r}) and (orientation: portrait)" />`,
  );
}
await browser.close();
console.log(links.join("\n"));
