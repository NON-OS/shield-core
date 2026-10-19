// The core refuses a spend as more than the balance covers when the notes that would cover it are
// not yet under a root the association registry holds. The balance on screen says otherwise, so
// that case is told as it is.

const number = (text) => Number(String(text ?? "").replace(/,/g, ""));

export function unanchored(error, balances, coin, amount, fee) {
  if (error?.kind !== "Insufficient") return null;
  const held = balances?.find((b) => b.coin === coin);
  if (!held || number(held.spendableText) < number(amount) + number(fee)) return null;
  return "The newest notes are in the pool but not yet under a root the association registry has listed. Private sends from them open once it has. Try again later.";
}
