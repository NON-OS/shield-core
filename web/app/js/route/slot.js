// Where the page writes the answer to a request the wallet's worker is blocked on: four words of
// head, then the body. The worker waits on the first word, so the answer is whole before it wakes.
// The core refuses a reply above 16 MiB, so the body has room for the largest it would read.

const HEAD = 16;
const ROOM = 16 * 1024 * 1024;

export const slot = {
  REPLY: 1,
  REFUSED: 2,
  DIRECT: 3,

  create() {
    return new SharedArrayBuffer(HEAD + ROOM);
  },

  /** Clear the slot before a request is sent, so a wait cannot read the last answer. */
  clear(buffer) {
    Atomics.store(new Int32Array(buffer, 0, 4), 0, 0);
  },

  /** Block until the page has answered. Only a worker may. */
  wait(buffer) {
    const head = new Int32Array(buffer, 0, 4);
    while (Atomics.load(head, 0) === 0) Atomics.wait(head, 0, 0);
    const [, kind, status, length] = head;
    const text = new TextDecoder().decode(new Uint8Array(buffer, HEAD, length).slice());
    return { kind, status, text };
  },

  /** Write an answer and wake the worker. A body too large for the slot is refused. */
  answer(buffer, { kind, status = 0, bytes }) {
    const head = new Int32Array(buffer, 0, 4);
    const body = bytes ? new Uint8Array(bytes) : new Uint8Array();
    if (body.length > ROOM) return this.answer(buffer, { kind: this.REFUSED });
    new Uint8Array(buffer, HEAD, body.length).set(body);
    head[1] = kind;
    head[2] = status;
    head[3] = body.length;
    Atomics.store(head, 0, 1);
    Atomics.notify(head, 0);
  },
};
