// The largest standard size, 1, 2 or 5 followed by zeros, that a note can send with room left for
// the fee, and no smaller than the pool's smallest size. Amounts are decimal text, read exactly.

const PLACES = 18;

const scaled = (text) => {
  const [whole, part = ""] = text.replace(/,/g, "").split(".");
  return (
    BigInt(whole || "0") * 10n ** BigInt(PLACES) +
    BigInt(part.padEnd(PLACES, "0").slice(0, PLACES) || "0")
  );
};

const decimal = (units) => {
  const digits = units.toString().padStart(PLACES + 1, "0");
  const whole = digits.slice(0, -PLACES);
  const part = digits.slice(-PLACES).replace(/0+$/, "");
  return part ? `${whole}.${part}` : whole;
};

export function standardWithin(value, room, least) {
  const most = scaled(value) - scaled(room);
  let best = null;
  for (let unit = 1n; unit <= most; unit *= 10n) {
    for (const lead of [1n, 2n, 5n]) if (lead * unit <= most) best = lead * unit;
  }
  return best === null || best < scaled(least) ? null : decimal(best);
}
