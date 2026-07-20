import "@codingame/monaco-vscode-editor-api/esm/vs/editor/contrib/format/browser/formatActions.js";

import * as monaco from "@codingame/monaco-vscode-editor-api";

import {
  BrowserMessageReader,
  BrowserMessageWriter,
} from "vscode-languageserver-protocol/browser";
import { CloseAction, ErrorAction } from "vscode-languageclient/browser.js";

import { MonacoLanguageClient } from "monaco-languageclient";
import { MonacoVscodeApiWrapper } from "monaco-languageclient/vscodeApiWrapper";
import { configureDefaultWorkerFactory } from "monaco-languageclient/workerFactory";
import {
  createDefaultYaraConfig,
  type YaraConfig,
} from "../settings/playground-settings";
import { createLanguageServerWorker } from "../language-server/language-server-worker-client";

const RULE_URI = monaco.Uri.file("/workspace/main.yar");
const SAMPLE_URI = monaco.Uri.file("/workspace/sample.txt");
const THEME_NAME = "yara-studio";

export const YARA_CONFIG: YaraConfig = createDefaultYaraConfig();

export function updateYaraConfig(nextConfig: YaraConfig) {
  YARA_CONFIG.codeFormatting = { ...nextConfig.codeFormatting };
  YARA_CONFIG.metadataValidation = nextConfig.metadataValidation.map(
    (rule) => ({ ...rule }),
  );
  YARA_CONFIG.ruleNameValidation = nextConfig.ruleNameValidation;
  YARA_CONFIG.cacheWorkspace = nextConfig.cacheWorkspace;
}

const YARA_KEYWORDS = [
  "rule",
  "meta",
  "strings",
  "condition",
  "private",
  "global",
  "import",
];

const YARA_OPERATORS = [
  "all",
  "and",
  "any",
  "ascii",
  "at",
  "base64",
  "base64wide",
  "contains",
  "entrypoint",
  "false",
  "filesize",
  "for",
  "fullword",
  "in",
  "matches",
  "nocase",
  "none",
  "not",
  "of",
  "or",
  "them",
  "true",
  "wide",
  "xor",
];

export type EditorHandle = {
  editor: monaco.editor.IStandaloneCodeEditor;
  languageServerVersion: string | null;
  getValue: () => string;
  setValue: (value: string) => void;
  layout: () => void;
  setHighlights: (highlights: EditorHighlight[]) => void;
  clearHighlights: () => void;
  revealRange: (start: number, end: number) => boolean;
  onDidChangeValue: (listener: () => void) => { dispose: () => void };
  format: () => Promise<boolean>;
  dispose: () => void;
};

export type EditorActionHandlers = {
  onFormatRequest?: () => void;
  onRunRequest?: () => void;
};

export type EditorHighlight = {
  start: number;
  end: number;
  hoverMessage?: string;
  isActive?: boolean;
};

let vscodeApiInitPromise: Promise<void> | undefined;
let themeRegistered = false;

function registerStudioTheme() {
  if (themeRegistered) return;

  monaco.editor.defineTheme(THEME_NAME, {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "keyword", foreground: "e9c46a" },
      { token: "variable", foreground: "5ce1e6" },
      { token: "identifier", foreground: "d6e6f2" },
      { token: "string", foreground: "7ce8a2" },
      { token: "number", foreground: "ffa770" },
      { token: "comment", foreground: "547282" },
    ],
    colors: {
      "editor.background": "#04111b",
      "editor.lineHighlightBackground": "#0b2230",
      "editor.foreground": "#d8e5ef",
      "editorCursor.foreground": "#1ee3cf",
      "editorLineNumber.foreground": "#527084",
      "editorLineNumber.activeForeground": "#8fb7c8",
      "editor.selectionBackground": "#12374b",
      "editor.inactiveSelectionBackground": "#0d2c3d",
      "editorIndentGuide.background1": "#0b2330",
      "editorIndentGuide.activeBackground1": "#1f5665",
      "editorWidget.background": "#071825",
      "editorWidget.border": "#133141",
    },
  });

  themeRegistered = true;
}

async function ensureVscodeApi() {
  vscodeApiInitPromise ??= (async () => {
    const apiWrapper = new MonacoVscodeApiWrapper({
      $type: "classic",
      viewsConfig: { $type: "EditorService" },
      userConfiguration: {
        json: JSON.stringify({
          "editor.colorDecorators": false,
        }),
      },
      advanced: {
        loadThemes: false,
        loadExtensionServices: false,
      },
      monacoWorkerFactory: configureDefaultWorkerFactory,
    });

    await apiWrapper.start();
    registerStudioTheme();
    monaco.editor.setTheme(THEME_NAME);
  })();

  await vscodeApiInitPromise;
}

function registerYaraLanguage() {
  if (monaco.languages.getLanguages().some((lang) => lang.id === "yara"))
    return;

  monaco.languages.register({
    id: "yara",
    extensions: [".yar", ".yara"],
    aliases: ["YARA", "yara"],
  });

  monaco.languages.setLanguageConfiguration("yara", {
    comments: {
      lineComment: "//",
      blockComment: ["/*", "*/"],
    },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"', notIn: ["string"] },
      { open: "/*", close: " */", notIn: ["string"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
    ],
  });

  monaco.languages.setMonarchTokensProvider("yara", {
    keywords: YARA_KEYWORDS,
    operators: YARA_OPERATORS,
    tokenizer: {
      root: [
        [/\$[a-zA-Z_]\w*/, "variable"],
        [
          /[a-zA-Z_][\w]*/,
          {
            cases: {
              "@keywords": "keyword",
              "@operators": "keyword",
              "@default": "identifier",
            },
          },
        ],
        [/\/\*/, "comment", "@comment"],
        [/\/\/.*$/, "comment"],
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/"/, { token: "string.quote", bracket: "@open", next: "@string" }],
        [/\b\d+(?:\.\d+)?\b/, "number"],
        [/[{}()[\]]/, "@brackets"],
        [/[=><!~?:&|+\-*\/%^]+/, "operator"],
      ],
      comment: [
        [/[^\/*]+/, "comment"],
        [/\*\//, "comment", "@pop"],
        [/[\/*]/, "comment"],
      ],
      string: [
        [/[^\\"]+/, "string"],
        [/\\./, "string.escape"],
        [/"/, { token: "string.quote", bracket: "@close", next: "@pop" }],
      ],
    },
  });
}

async function createEditorModel(
  uri: monaco.Uri,
  initialValue: string,
  language: string,
) {
  const modelRef = await monaco.editor.createModelReference(uri, initialValue);
  const model = modelRef.object.textEditorModel;

  if (!model) {
    modelRef.dispose();
    throw new Error(`Unable to resolve editor model for ${uri.toString()}.`);
  }

  monaco.editor.setModelLanguage(model, language);

  return {
    model,
    modelRef,
  };
}

async function createYaraLanguageClient() {
  const worker = await createLanguageServerWorker();
  const reader = new BrowserMessageReader(worker);
  const writer = new BrowserMessageWriter(worker);

  const client = new MonacoLanguageClient({
    id: "yara-x-playground",
    name: "YARA-X Playground Language Client",
    clientOptions: {
      documentSelector: [{ language: "yara", scheme: "file" }],
      initializationOptions: YARA_CONFIG,
      errorHandler: {
        error: () => ({ action: ErrorAction.Continue }),
        closed: () => ({ action: CloseAction.DoNotRestart }),
      },
      middleware: {
        workspace: {
          configuration: async () => [YARA_CONFIG],
        },
      },
    },
    messageTransports: { reader, writer },
  });

  await client.start();

  return {
    languageServerVersion: client.initializeResult?.serverInfo?.version ?? null,
    dispose: () => {
      void client
        .stop()
        .catch((error) => {
          console.error("failed to stop yara-x language client", error);
        })
        .finally(() => {
          worker.terminate();
        });
    },
  };
}

function buildEditor(
  element: HTMLElement,
  model: monaco.editor.ITextModel,
  options: monaco.editor.IStandaloneEditorConstructionOptions,
): monaco.editor.IStandaloneCodeEditor {
  return monaco.editor.create(element, {
    model,
    automaticLayout: true,
    colorDecorators: false,
    fixedOverflowWidgets: true,
    links: false,
    minimap: { enabled: true },
    scrollBeyondLastLine: false,
    fontSize: 14,
    lineHeight: 22,
    fontFamily: "IBM Plex Mono, ui-monospace, SFMono-Regular, monospace",
    padding: { top: 18, bottom: 18 },
    theme: THEME_NAME,
    ...options,
  });
}

function registerEditorActions(
  editor: monaco.editor.IStandaloneCodeEditor,
  handlers: EditorActionHandlers,
) {
  const actions: monaco.IDisposable[] = [];
  const { onFormatRequest, onRunRequest } = handlers;

  if (onFormatRequest) {
    actions.push(
      editor.addAction({
        id: "yara-x.format-document",
        label: "Format YARA document",
        keybindings: [
          monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS,
          monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF,
        ],
        run: onFormatRequest,
      }),
    );
  }

  if (onRunRequest) {
    actions.push(
      editor.addAction({
        id: "yara-x.run-scan",
        label: "Run YARA rule",
        keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter],
        run: onRunRequest,
      }),
    );
  }

  return {
    dispose: () => {
      for (const action of actions) {
        action.dispose();
      }
    },
  };
}

function toHandle(
  editor: monaco.editor.IStandaloneCodeEditor,
  modelRef: { dispose: () => void },
  extraDispose?: () => void,
  languageServerVersion: string | null = null,
): EditorHandle {
  const decorations = editor.createDecorationsCollection();

  return {
    editor,
    languageServerVersion,
    getValue: () => editor.getValue(),
    setValue: (value) => editor.setValue(value),
    layout: () => editor.layout(),
    setHighlights: (highlights) => {
      const model = editor.getModel();

      if (!model) {
        decorations.clear();
        editor
          .getDomNode()
          ?.parentElement?.classList.remove("has-active-match");
        return;
      }

      const nextDecorations: monaco.editor.IModelDeltaDecoration[] = [];
      let hasActiveMatch = false;

      for (const highlight of highlights) {
        if (highlight.end <= highlight.start) {
          continue;
        }

        const start = model.getPositionAt(highlight.start);
        const end = model.getPositionAt(highlight.end);

        if (highlight.isActive === true) {
          hasActiveMatch = true;
        }

        nextDecorations.push({
          range: {
            startLineNumber: start.lineNumber,
            startColumn: start.column,
            endLineNumber: end.lineNumber,
            endColumn: end.column,
          },
          options: {
            inlineClassName: highlight.isActive
              ? "sample-match-highlight is-active"
              : "sample-match-highlight",
            hoverMessage: highlight.hoverMessage
              ? {
                  value: highlight.hoverMessage,
                }
              : undefined,
          },
        });
      }

      editor
        .getDomNode()
        ?.parentElement?.classList.toggle("has-active-match", hasActiveMatch);
      decorations.set(nextDecorations);
    },
    clearHighlights: () => {
      decorations.clear();
      editor.getDomNode()?.parentElement?.classList.remove("has-active-match");
    },
    revealRange: (start, end) => {
      const model = editor.getModel();

      if (!model || start < 0 || end <= start) {
        return false;
      }

      const startPosition = model.getPositionAt(start);
      const endPosition = model.getPositionAt(end);
      const range = new monaco.Range(
        startPosition.lineNumber,
        startPosition.column,
        endPosition.lineNumber,
        endPosition.column,
      );

      editor.revealRangeInCenter(range, monaco.editor.ScrollType.Smooth);
      return true;
    },
    onDidChangeValue: (listener) =>
      editor.onDidChangeModelContent(() => {
        listener();
      }),
    format: async () => {
      const action = editor.getAction("editor.action.formatDocument");
      if (!action) return false;
      await action.run();
      return true;
    },
    dispose: () => {
      extraDispose?.();
      decorations.clear();
      editor.dispose();
      modelRef.dispose();
    },
  };
}

export async function createYaraEditor(
  element: HTMLElement,
  initialValue: string,
  actionHandlers: EditorActionHandlers,
): Promise<EditorHandle> {
  await ensureVscodeApi();
  registerYaraLanguage();

  const { modelRef, model } = await createEditorModel(
    RULE_URI,
    initialValue,
    "yara",
  );
  const editor = buildEditor(element, model, {
    quickSuggestions: true,
    suggestOnTriggerCharacters: true,
    tabSize: 2,
    insertSpaces: true,
  });
  const editorActions = registerEditorActions(editor, actionHandlers);
  const languageClient = await createYaraLanguageClient();

  return toHandle(
    editor,
    modelRef,
    () => {
      editorActions.dispose();
      languageClient.dispose();
    },
    languageClient.languageServerVersion,
  );
}

export async function createPlainTextEditor(
  element: HTMLElement,
  initialValue: string,
  actionHandlers: EditorActionHandlers,
): Promise<EditorHandle> {
  await ensureVscodeApi();

  const { modelRef, model } = await createEditorModel(
    SAMPLE_URI,
    initialValue,
    "plaintext",
  );
  const editor = buildEditor(element, model, {
    lineNumbers: "off",
    glyphMargin: false,
    folding: false,
    wordWrap: "on",
    tabSize: 2,
    insertSpaces: true,
    quickSuggestions: false,
    suggestOnTriggerCharacters: false,
  });
  const editorActions = registerEditorActions(editor, actionHandlers);

  return toHandle(editor, modelRef, () => editorActions.dispose());
}
