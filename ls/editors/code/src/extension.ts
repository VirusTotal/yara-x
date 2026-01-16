import { ExtensionContext, window } from "vscode";
import {
  Executable,
  LanguageClient,
  LanguageClientOptions,
} from "vscode-languageclient/node";

import * as os from "os";
import * as path from "path";

let client: LanguageClient | null = null;

export async function activate(context: ExtensionContext) {
  const platform = os.platform();
  const arch = os.arch();

  let binaryName: string;
  if (platform === "win32" && arch === "x64") {
    binaryName = "yr-ls.exe";
  } else if (platform === "darwin" && (arch === "x64" || arch === "arm64")) {
    binaryName = "yr-ls";
  } else if (platform === "linux" && arch === "x64") {
    binaryName = "yr-ls";
  } else {
    window.showErrorMessage(`Unsupported platform: ${platform}-${arch}`);
    return;
  }

  const serverPath = context.asAbsolutePath(path.join("dist", binaryName));

  const serverExecutable: Executable = {
    command: serverPath,
    args: [],
  };

  const outputChannel = window.createOutputChannel("YARA-X Language Server");

  let clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "yara" }],
    outputChannel: outputChannel,
    traceOutputChannel: outputChannel,
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
