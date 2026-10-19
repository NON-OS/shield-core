// Why this device will not make a private send, told before the user fills anything in.

const elsewhere =
  "Private sends need the NØNOS app or a computer. Deposits, receiving and the public account work here as they are.";

export function cannotProve(proving) {
  switch (proving?.state) {
    case "unmeasured":
      return {
        line: "This device has not made a proof yet.",
        lead: `A proof needs about 1 GiB of memory, and a phone browser may end a page that asks for that without warning. Time one test proof here first: it spends nothing, takes a few minutes, and if the page reloads instead of finishing, this device cannot prove. ${elsewhere}`,
        measure: true,
      };
    case "stopped":
      return {
        line: "This device could not finish a test proof.",
        lead: `The browser ended the page before the proof was made, so a private send would end the same way. ${elsewhere}`,
        measure: false,
      };
    case "unable":
      return {
        line: "This browser cannot run the prover.",
        lead: `It has no WebAssembly. ${elsewhere}`,
        measure: false,
      };
    default:
      return null;
  }
}
