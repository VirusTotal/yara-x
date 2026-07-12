import type { ReactiveController, ReactiveControllerHost } from "lit";

import type { EditorHandle } from "../editor/yara-monaco";
import {
  loadStoredPlaygroundSession,
  storePlaygroundSession,
} from "../persistence/playground-session-storage";
import type { InlineSampleMode } from "../sample/sample-modes";
import type { PlaygroundSession } from "../session/playground-session";

type Disposable = {
  dispose(): void;
};

type PlaygroundSessionEvents = {
  onSampleChange: () => void;
};

export class PlaygroundSessionController implements ReactiveController {
  private readonly sampleDrafts: PlaygroundSession["sampleDrafts"];
  private ruleValue: string;
  private activeInlineSampleMode: InlineSampleMode;
  private sampleEditor?: EditorHandle;
  private ruleEditorSubscription?: Disposable;
  private sampleEditorSubscription?: Disposable;
  private persistTimeoutId?: number;
  private readonly events: PlaygroundSessionEvents;

  constructor(
    host: ReactiveControllerHost,
    defaultRule: string,
    defaultSample: string,
    events: PlaygroundSessionEvents,
  ) {
    const session = loadStoredPlaygroundSession(defaultRule, defaultSample);

    this.ruleValue = session.rule;
    this.activeInlineSampleMode = session.sampleMode;
    this.sampleDrafts = { ...session.sampleDrafts };
    this.events = events;
    host.addController(this);
  }

  get initialRuleValue() {
    return this.ruleValue;
  }

  get inlineSampleMode() {
    return this.activeInlineSampleMode;
  }

  getSampleDraft(mode: InlineSampleMode) {
    return this.sampleDrafts[mode];
  }

  bindRuleEditor(editor: EditorHandle) {
    this.ruleEditorSubscription?.dispose();
    this.ruleValue = editor.getValue();
    this.ruleEditorSubscription = editor.onDidChangeValue(() => {
      this.ruleValue = editor.getValue();
      this.schedulePersist();
    });
  }

  bindSampleEditor(editor: EditorHandle) {
    this.sampleEditorSubscription?.dispose();
    this.sampleEditor = editor;
    this.captureActiveSampleDraft();
    this.sampleEditorSubscription = editor.onDidChangeValue(() => {
      this.captureActiveSampleDraft();
      this.events.onSampleChange();
      this.schedulePersist();
    });
  }

  selectInlineSampleMode(mode: InlineSampleMode) {
    this.captureActiveSampleDraft();
    this.activeInlineSampleMode = mode;
    this.restoreSampleDraft(mode);
    this.schedulePersist();
  }

  selectFileMode() {
    this.captureActiveSampleDraft();
    this.schedulePersist();
  }

  restoreActiveSampleDraft() {
    this.restoreSampleDraft(this.activeInlineSampleMode);
  }

  private captureActiveSampleDraft() {
    if (!this.sampleEditor) {
      return;
    }

    this.sampleDrafts[this.activeInlineSampleMode] =
      this.sampleEditor.getValue();
  }

  private restoreSampleDraft(mode: InlineSampleMode) {
    if (!this.sampleEditor) {
      return;
    }

    const nextValue = this.sampleDrafts[mode];

    if (this.sampleEditor.getValue() !== nextValue) {
      this.sampleEditor.setValue(nextValue);
    }
  }

  schedulePersist() {
    if (this.persistTimeoutId != null) {
      window.clearTimeout(this.persistTimeoutId);
    }

    this.persistTimeoutId = window.setTimeout(() => {
      this.persistTimeoutId = undefined;
      this.persist();
    }, 250);
  }

  hostDisconnected() {
    this.persist();

    if (this.persistTimeoutId != null) {
      window.clearTimeout(this.persistTimeoutId);
      this.persistTimeoutId = undefined;
    }

    this.ruleEditorSubscription?.dispose();
    this.sampleEditorSubscription?.dispose();
    this.ruleEditorSubscription = undefined;
    this.sampleEditorSubscription = undefined;
    this.sampleEditor = undefined;
  }

  private persist() {
    this.captureActiveSampleDraft();
    storePlaygroundSession({
      rule: this.ruleValue,
      sampleMode: this.activeInlineSampleMode,
      sampleDrafts: { ...this.sampleDrafts },
    });
  }
}
