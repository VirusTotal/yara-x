export function readStoredJson(key: string): unknown | null {
  if (typeof localStorage === "undefined") {
    return null;
  }

  try {
    const value = localStorage.getItem(key);
    return value == null ? null : JSON.parse(value);
  } catch {
    return null;
  }
}

export function writeStoredJson(key: string, value: unknown) {
  if (typeof localStorage === "undefined") {
    return;
  }

  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage failures in private mode or constrained environments.
  }
}
