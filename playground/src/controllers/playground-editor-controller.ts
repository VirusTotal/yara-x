import type { ReactiveController, ReactiveControllerHost } from "lit";

import {
  createPlainTextEditor,
  createYaraEditor,
  type EditorActionHandlers,
  type EditorHandle,
} from "../editor/yara-monaco";
import type { LanguageServerStatus } from "../language-server/language-server";

type PlaygroundEditorEvents = {
  onLanguageServerVersion: (version: string | null) => void;
  onStatus: (status: LanguageServerStatus) => void;
  onFormatRequest: () => void;
  onRunRequest: () => void;
};

export class PlaygroundEditorController implements ReactiveController {
  private ruleEditor?: EditorHandle;
  private sampleEditor?: EditorHandle;
  private readonly events: PlaygroundEditorEvents;

  constructor(host: ReactiveControllerHost, events: PlaygroundEditorEvents) {
    this.events = events;
    host.addController(this);
  }

  get isReady() {
    return Boolean(this.ruleEditor && this.sampleEditor);
  }

  get rule() {
    return this.ruleEditor;
  }

  get sample() {
    return this.sampleEditor;
  }

  async initialize(
    ruleHost: HTMLElement,
    sampleHost: HTMLElement,
    ruleSource: string,
    sampleSource: string,
  ) {
    this.dispose();
    this.events.onStatus("loading");

    try {
      const [ruleEditor, sampleEditor] = await Promise.all([
        createYaraEditor(ruleHost, ruleSource, this.ruleEditorActions),
        createPlainTextEditor(
          sampleHost,
          sampleSource,
          this.sampleEditorActions,
        ),
      ]);

      this.ruleEditor = ruleEditor;
      this.sampleEditor = sampleEditor;
      this.events.onLanguageServerVersion(ruleEditor.languageServerVersion);
      this.events.onStatus("ready");

      return { ruleEditor, sampleEditor };
    } catch (error) {
      this.dispose();
      this.events.onStatus("error");
      throw error;
    }
  }

  async recreateRuleEditor(ruleHost: HTMLElement) {
    const ruleSource = this.ruleEditor?.getValue();

    if (ruleSource == null) {
      return null;
    }

    this.events.onStatus("loading");
    this.ruleEditor?.dispose();
    this.ruleEditor = undefined;
    this.events.onLanguageServerVersion(null);

    try {
      const ruleEditor = await createYaraEditor(
        ruleHost,
        ruleSource,
        this.ruleEditorActions,
      );
      this.ruleEditor = ruleEditor;
      this.events.onLanguageServerVersion(ruleEditor.languageServerVersion);
      this.events.onStatus("ready");
      return ruleEditor;
    } catch (error) {
      this.events.onStatus("error");
      throw error;
    }
  }

  async formatRule() {
    if (!this.ruleEditor) {
      return false;
    }

    return this.ruleEditor.format();
  }

  hostDisconnected() {
    this.dispose();
  }

  private dispose() {
    this.ruleEditor?.dispose();
    this.sampleEditor?.dispose();
    this.ruleEditor = undefined;
    this.sampleEditor = undefined;
  }

  private get ruleEditorActions(): EditorActionHandlers {
    return {
      onFormatRequest: this.events.onFormatRequest,
      onRunRequest: this.events.onRunRequest,
    };
  }

  private get sampleEditorActions(): EditorActionHandlers {
    return {
      onRunRequest: this.events.onRunRequest,
    };
  }
}
