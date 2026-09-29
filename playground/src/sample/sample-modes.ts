export const SAMPLE_MODES = [
  { id: "text", label: "Text", inline: true },
  { id: "base64", label: "Base64", inline: true },
  { id: "hex", label: "Hex", inline: true },
  { id: "file", label: "File", inline: false },
] as const;

export type SampleMode = (typeof SAMPLE_MODES)[number]["id"];

export type InlineSampleMode = Extract<
  (typeof SAMPLE_MODES)[number],
  { readonly inline: true }
>["id"];

export const INLINE_SAMPLE_MODES = SAMPLE_MODES.filter(
  (
    definition,
  ): definition is Extract<
    (typeof SAMPLE_MODES)[number],
    { readonly inline: true }
  > => definition.inline,
);

export function isInlineSampleMode(mode: string): mode is InlineSampleMode {
  return INLINE_SAMPLE_MODES.some((definition) => definition.id === mode);
}
