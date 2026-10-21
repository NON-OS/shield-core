// How long one request through the mixnet may take. The mixnet carries a request as many small
// packets, each delayed on purpose, so a large one, such as a settlement's proof, takes far longer
// than a read. The allowance grows with the bytes sent.

const BASE_MS = 90_000;
const PER_BYTE_MS = 0.5;

export function patience(body) {
  const bytes = typeof body === "string" ? body.length : (body?.byteLength ?? 0);
  return BASE_MS + Math.round(bytes * PER_BYTE_MS);
}
