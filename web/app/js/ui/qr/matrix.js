// The modules of a QR symbol: the fixed patterns, the codewords in the zigzag the standard reads,
// and the mask that scores best on the standard's penalty rules for runs, blocks and balance.

import { codewords, versionFor } from "./codewords.js";

function grid(size) {
  return Array.from({ length: size }, () => new Array(size).fill(false));
}

function alignment(v, size) {
  if (v === 1) return [];
  const n = Math.floor(v / 7) + 2;
  const step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2;
  const out = [6];
  for (let pos = size - 7; out.length < n; pos -= step) out.splice(1, 0, pos);
  return out;
}

const masks = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function penalty(m) {
  const size = m.length;
  let score = 0;
  for (let pass = 0; pass < 2; pass++) {
    for (let a = 0; a < size; a++) {
      let run = 1;
      for (let b = 1; b < size; b++) {
        const same = pass ? m[b][a] === m[b - 1][a] : m[a][b] === m[a][b - 1];
        if (same) run++;
        else {
          if (run >= 5) score += run - 2;
          run = 1;
        }
      }
      if (run >= 5) score += run - 2;
    }
  }
  for (let y = 0; y < size - 1; y++)
    for (let x = 0; x < size - 1; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3;
    }
  const dark = m.flat().filter(Boolean).length;
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

/** The modules of `text` as UTF-8, rows of booleans, true for dark, or null when it is too long. */
export function matrix(text) {
  const bytes = [...new TextEncoder().encode(text)];
  const v = versionFor(bytes.length);
  if (!v) return null;
  const size = v * 4 + 17;
  const m = grid(size);
  const fixed = grid(size);
  const set = (x, y, dark) => {
    m[y][x] = dark;
    fixed[y][x] = true;
  };
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [
    [3, 3],
    [size - 4, 3],
    [3, size - 4],
  ]) {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4);
      }
  }
  const pos = alignment(v, size);
  for (let i = 0; i < pos.length; i++)
    for (let j = 0; j < pos.length; j++) {
      const corner =
        (i === 0 && j === 0) ||
        (i === 0 && j === pos.length - 1) ||
        (i === pos.length - 1 && j === 0);
      if (corner) continue;
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++)
          set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  const format = (mask) => {
    const data = (1 << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = (i) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  format(0);
  if (v >= 7) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (v << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(a, b, dark);
      set(b, a, dark);
    }
  }
  const data = codewords(bytes, v);
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++)
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const up = ((right + 1) & 2) === 0;
        const y = up ? size - 1 - vert : vert;
        if (!fixed[y][x] && i < data.length * 8) {
          m[y][x] = ((data[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
  }
  const masked = (k) =>
    m.map((row, y) => row.map((dark, x) => (fixed[y][x] ? dark : dark !== masks[k](x, y))));
  let best = null;
  for (let k = 0; k < 8; k++) {
    format(k);
    const candidate = masked(k);
    const score = penalty(candidate);
    if (!best || score < best.score) best = { k, score, modules: candidate };
  }
  format(best.k);
  return masked(best.k);
}
