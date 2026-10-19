// The mixnet's worker. It runs mix-fetch, which starts its own worker for the Nym client, and
// carries the requests the page hands it. One tunnel lives as long as this worker, so the page
// moves to another gateway by ending this worker and starting a new one.

import { mixFetch, setupMixTunnel } from "../../nym/mix-fetch.js";

async function setup({ gateway, clientId }) {
  await setupMixTunnel({ preferredGateway: gateway, clientId, forceTls: true });
  return {};
}

async function request({ method, url, headers, body }) {
  const init = { method, headers: Object.fromEntries(headers) };
  if (body != null) init.body = body;
  const res = await mixFetch(url, init);
  return { status: res.status, bytes: await res.arrayBuffer() };
}

onmessage = async ({ data }) => {
  try {
    const answer = data.op === "setup" ? await setup(data) : await request(data);
    postMessage({ id: data.id, ...answer }, answer.bytes ? [answer.bytes] : []);
  } catch (e) {
    postMessage({ id: data.id, failure: String(e?.message ?? e) });
  }
};
