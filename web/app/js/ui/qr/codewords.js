// The bytes of a QR symbol in byte mode: the data with its header and padding, split into blocks
// with their error correction, interleaved as the standard reads them.

import { L } from "./tables.js";
import { correction } from "./reed-solomon.js";

export function rawModules(v) {
  let n = (16 * v + 128) * v + 64;
  if (v >= 2) {
    const align = Math.floor(v / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (v >= 7) n -= 36;
  }
  return n;
}

const dataBytes = (v) => Math.floor(rawModules(v) / 8) - L.eccPerBlock[v] * L.blocks[v];
const countBits = (v) => (v < 10 ? 8 : 16);

/** The smallest version that holds `length` bytes, or none past version 40. */
export function versionFor(length) {
  for (let v = 1; v <= 40; v++) if (4 + countBits(v) + 8 * length <= 8 * dataBytes(v)) return v;
  return 0;
}

export function codewords(bytes, v) {
  const bits = [];
  const put = (value, n) => {
    for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4);
  put(bytes.length, countBits(v));
  for (const b of bytes) put(b, 8);
  const capacity = 8 * dataBytes(v);
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8)
    data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));

  const blocks = L.blocks[v];
  const ecc = L.eccPerBlock[v];
  const raw = Math.floor(rawModules(v) / 8);
  const short = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks);
  const all = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const take = shortLen - ecc + (i < short ? 0 : 1);
    const block = data.slice(k, k + take);
    k += take;
    const tail = correction(block, ecc);
    if (i < short) block.push(0);
    all.push(block.concat(tail));
  }
  const out = [];
  for (let i = 0; i < all[0].length; i++) {
    for (let j = 0; j < all.length; j++) {
      if (i !== shortLen - ecc || j >= short) out.push(all[j][i]);
    }
  }
  return out;
}
