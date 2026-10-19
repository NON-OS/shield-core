// The periodic cache the prover starts from, shipped with the release in chunks. Each chunk's
// SHA-256 is checked against the release before it is used, and the prover checks the whole
// cache again against the root it is built for, so a wrong file is refused twice over.

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function loadCache({ chunks, sha256 }) {
  try {
    const parts = await Promise.all(
      chunks.map(async ({ path, sha256: want }) => {
        const bytes = await (await fetch(path)).arrayBuffer();
        if (hex(await crypto.subtle.digest("SHA-256", bytes)) !== want) throw new Error(path);
        return new Uint8Array(bytes);
      }),
    );
    const whole = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    parts.reduce((at, p) => (whole.set(p, at), at + p.length), 0);
    if (hex(await crypto.subtle.digest("SHA-256", whole)) !== sha256) return null;
    return whole;
  } catch {
    return null;
  }
}
