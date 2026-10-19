// A core failure as one line for a screen, from the case the core names and never from a secret.
// The sentences are the apps', with the network ones told for a browser, which has no Tor.

const wallet = {
  Insufficient: "That is more than the balance covers.",
  NoSpendPlan: "Two notes are needed to send. Receive again first.",
  Address: "That recipient address is not valid.",
  Amount: "That amount is out of range.",
  ReviewExpired: "That review has expired. Review the send again.",
  NoSuchAccount: "There is no such account.",
  Unavailable: "That is not in this build yet.",
  NotStandard:
    "Amounts come in standard sizes, 1, 2 or 5 followed by zeros, from 1,000 NOX or 0.01 ETH.",
  FeeTooHigh: "The pool would not take this fee. Try again in a minute, or reload the page.",
  TooSoon: "These notes are still new. Wait, or go early from the send screen.",
  FeeChanged: "The fee moved since it was shown. Review it again.",
};

const custody = {
  Locked: "The wallet is locked.",
  Guard: "The passkey did not give the wallet its key.",
  SealAuth: "That passkey does not open this wallet.",
  Mnemonic: "That recovery phrase did not check out.",
  PhraseLength: "A recovery phrase is 12, 15, 18, 21 or 24 words.",
  VaultPresent: "A wallet is already stored in this browser.",
  KeyShape: "That private key is not valid: 64 hex digits of a real key.",
  Entropy: "This browser gave no randomness. Nothing was made.",
};

const prove = {
  SeedEntropy: "This browser gave no randomness for the proof. Try again.",
  SeedReused: "A proof needs fresh randomness. Try again.",
  WitnessUnsatisfied: "The notes could not be proved against the pool. Refresh, then try again.",
  Unbalanced: "The amounts do not add up. Nothing was sent.",
  SelfVerify: "The proof did not check out here. Nothing was sent. Try again.",
  Cancelled: "Proving was stopped. Nothing was sent.",
  Encoding: "The proof could not be packed. Nothing was sent.",
  RootNotPublished: "The pool moved while the proof was made. Try again.",
};

function net(detail) {
  if (detail.startsWith("Rejected")) {
    const code = detail.match(/\d+/)?.[0] ?? "";
    return `The network refused that (code ${code}). Nothing changed.`;
  }
  if (detail === "WrongChain")
    return "A server answered for the wrong network. Nothing was signed.";
  if (detail === "ReplyShape" || detail === "ReplyTooLarge")
    return "A server answered in a form the wallet does not read. Nothing changed.";
  if (detail === "ProxyRefused") return "That service cannot be reached from a browser.";
  return "The network could not be reached. Try again. Nothing was sent.";
}

export function failureText(e) {
  switch (e?.kind) {
    case "Custody":
      return custody[e.detail] ?? "The stored wallet could not be opened in this browser.";
    case "Net":
      return net(e.detail ?? "");
    case "Store":
      return "The note store could not be read.";
    case "Prove":
      return prove[e.detail] ?? "The proof stopped. Nothing was sent.";
    case "Stopped":
      return "Stopped. Nothing was sent.";
    default:
      return wallet[e?.kind] ?? "Something went wrong.";
  }
}
