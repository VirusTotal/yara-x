import "@codingame/monaco-vscode-editor-api/esm/vs/editor/contrib/format/browser/formatActions.js";

import * as monaco from "@codingame/monaco-vscode-editor-api";

import { MonacoVscodeApiWrapper } from "monaco-languageclient/vscodeApiWrapper";
import { configureDefaultWorkerFactory } from "monaco-languageclient/workerFactory";
import { createModelReference } from "@codingame/monaco-vscode-api/monaco";

const RULE_URI = monaco.Uri.file("/workspace/main.yar");
const SAMPLE_URI = monaco.Uri.file("/workspace/sample.txt");
const THEME_NAME = "yara-studio";

export const YARA_CONFIG = {
  codeFormatting: {
    alignMetadata: true,
    alignPatterns: true,
    indentSectionHeaders: true,
    indentSectionContents: true,
    newlineBeforeCurlyBrace: false,
    emptyLineBeforeSectionHeader: false,
    emptyLineAfterSectionHeader: false,
  },
  metadataValidation: [],
  ruleNameValidation: null,
  cacheWorkspace: false,
};

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
  getValue: () => string;
  setValue: (value: string) => void;
  format: () => Promise<boolean>;
  dispose: () => void;
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
  const modelRef = await createModelReference(uri, initialValue);
  const model = modelRef.object.textEditorModel;

  if (!model) {
    throw new Error(`failed to create ${language} model`);
  }

  monaco.editor.setModelLanguage(model as never, language);

  return { modelRef, model };
}

function buildEditor(
  element: HTMLElement,
  model: unknown,
  options: monaco.editor.IStandaloneEditorConstructionOptions,
): monaco.editor.IStandaloneCodeEditor {
  return monaco.editor.create(element, {
    model: model as never,
    automaticLayout: true,
    colorDecorators: false,
    fixedOverflowWidgets: true,
    links: false,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 14,
    lineHeight: 22,
    fontFamily: "IBM Plex Mono, ui-monospace, SFMono-Regular, monospace",
    padding: { top: 18, bottom: 18 },
    theme: THEME_NAME,
    ...options,
  });
}

function registerYaraEditorActions(
  editor: monaco.editor.IStandaloneCodeEditor,
) {
  return editor.addAction({
    id: "yara-x.format-document",
    label: "Format YARA document",
    keybindings: [
      monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS,
      monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF,
    ],
    run: async () => {
      const action = editor.getAction("editor.action.formatDocument");
      await action?.run();
    },
  });
}

function toHandle(
  editor: monaco.editor.IStandaloneCodeEditor,
  modelRef: { dispose: () => void },
  extraDispose?: () => void,
): EditorHandle {
  return {
    editor,
    getValue: () => editor.getValue(),
    setValue: (value) => editor.setValue(value),
    format: async () => {
      const action = editor.getAction("editor.action.formatDocument");
      if (!action) return false;
      await action.run();
      return true;
    },
    dispose: () => {
      extraDispose?.();
      editor.dispose();
      modelRef.dispose();
    },
  };
}

export async function createYaraEditor(
  element: HTMLElement,
  initialValue: string,
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
  const editorAction = registerYaraEditorActions(editor);

  // TODO(@kevinmuoz): Wire the browser language server package here once the
  // upstream worker entrypoint and distribution strategy are settled.

  return toHandle(editor, modelRef, () => {
    editorAction.dispose();
  });
}

export async function createPlainTextEditor(
  element: HTMLElement,
  initialValue: string,
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

  return toHandle(editor, modelRef);
}
