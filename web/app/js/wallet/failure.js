// A refusal from the core: which layer refused, which case, and the core's own sentence.

export class WalletFailure extends Error {
  constructor({ kind, detail, text }) {
    super(text);
    this.kind = kind;
    this.detail = detail;
  }
}
