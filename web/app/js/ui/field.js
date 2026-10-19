import { h } from "./h.js";

let next = 0;

/** A labelled input. `hint` is read out with it. Returns the wrapper with `.input` on it. */
export function field(label, { hint, value = "", mono = true, multiline = false, ...attrs } = {}) {
  const id = `field-${++next}`;
  const hintId = hint ? `${id}-hint` : null;
  const input = h(multiline ? "textarea" : "input", {
    id,
    "aria-describedby": hintId,
    autocomplete: "off",
    autocapitalize: "off",
    spellcheck: "false",
    class: mono ? "mono" : null,
    ...attrs,
  });
  input.value = value;
  const wrap = h("div", { class: "field" }, h("label", { for: id }, label), input);
  if (hint) wrap.append(h("p", { id: hintId, class: "muted" }, hint));
  wrap.input = input;
  return wrap;
}
