import { ExtensionContext } from "vscode";
import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | null = null;

export async function activate(_context: ExtensionContext) {
  const serverExecutable: Executable = {
    command: process.env.CARGO_BIN_EXE_yr_ls!,
    args: [],
  };

  let clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "yara" }],
  };

  client = new LanguageClient(
    "yara-x-ls",
    "YARA-X LSP",
    serverExecutable,
    clientOptions
  );

  await client.start();
}

export function deactivate() {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
