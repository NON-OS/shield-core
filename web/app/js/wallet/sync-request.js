// What the core sees as the browser's synchronous request (core/src/net/tor_web/xhr.rs uses only
// open, setRequestHeader, send, status and responseText). It hands each request to the page and
// blocks until the page answers: with the reply that came back through the mixnet, with a refusal,
// or with leave to send it directly, which only the user gives. The direct request is the
// browser's own, as before the mixnet.

import { slot } from "../route/slot.js";

export function syncRequest(port, Native) {
  const buffer = slot.create();
  let turn = 0;
  class Request {
    status = 0;
    responseText = "";
    #method = "GET";
    #url = "";
    #headers = [];

    open(method, url) {
      this.#method = method;
      this.#url = url;
    }

    setRequestHeader(name, value) {
      this.#headers.push([name, value]);
    }

    send(body = null) {
      slot.clear(buffer);
      const request = { method: this.#method, url: this.#url, headers: this.#headers, body };
      port.postMessage({ buffer, turn, ...request });
      const { kind, status, text } = slot.wait(buffer);
      if (kind === slot.REPLY) [this.status, this.responseText] = [status, text];
      if (kind === slot.DIRECT) this.#direct(request);
    }

    #direct({ method, url, headers, body }) {
      const xhr = new Native();
      try {
        xhr.open(method, url, false);
        for (const [name, value] of headers) xhr.setRequestHeader(name, value);
        xhr.send(body);
        [this.status, this.responseText] = [xhr.status, xhr.responseText];
      } catch {
        this.status = 0;
      }
    }
  }
  return {
    Request,
    /** Mark the start of a wallet call, so a choice the user makes holds for that call alone. */
    next() {
      turn += 1;
    },
  };
}
