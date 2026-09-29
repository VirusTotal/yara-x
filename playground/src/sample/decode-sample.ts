import type { InlineSampleMode } from "./sample-modes";

const textEncoder = new TextEncoder();

function decodeBase64Sample(source: string): Uint8Array {
  const normalized = source.replace(/\s+/g, "");

  if (normalized.length === 0) {
    return new Uint8Array();
  }

  try {
    const decoded = atob(normalized);
    const bytes = new Uint8Array(decoded.length);

    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index);
    }

    return bytes;
  } catch {
    throw new Error("Sample is not valid base64.");
  }
}

function decodeHexSample(source: string): Uint8Array {
  const normalized = source.replace(/\s+/g, "");

  if (normalized.length === 0) {
    return new Uint8Array();
  }

  if (normalized.length % 2 !== 0 || /[^0-9a-f]/i.test(normalized)) {
    throw new Error("Sample is not valid hex.");
  }

  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return bytes;
}

export function decodeSampleInput(
  mode: InlineSampleMode,
  source: string,
): Uint8Array {
  switch (mode) {
    case "text":
      return textEncoder.encode(source);
    case "base64":
      return decodeBase64Sample(source);
    case "hex":
      return decodeHexSample(source);
  }
}
