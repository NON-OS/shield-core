/** An address shortened for a pill: its first six and last four characters. */
export const short = (address) =>
  address && address.length > 14 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address;
