// Reed-Solomon error correction over GF(256) with the QR polynomial 0x11d.

function mul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function divisor(degree) {
  const out = new Array(degree).fill(0);
  out[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < out.length; j++) {
      out[j] = mul(out[j], root);
      if (j + 1 < out.length) out[j] ^= out[j + 1];
    }
    root = mul(root, 0x02);
  }
  return out;
}

/** The `degree` error correction bytes of `data`. */
export function correction(data, degree) {
  const div = divisor(degree);
  const out = new Array(degree).fill(0);
  for (const b of data) {
    const factor = b ^ out.shift();
    out.push(0);
    div.forEach((coef, i) => (out[i] ^= mul(coef, factor)));
  }
  return out;
}
