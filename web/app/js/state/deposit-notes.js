// What the active account holds in notes from its own deposits. Only a received note is sealed to
// the wallet's key, so these are the notes the recovery words cannot bring back while unspent.

export async function readDepositNotes(app) {
  app.depositNotes = await app.call("depositNotes").catch(() => app.depositNotes);
}
