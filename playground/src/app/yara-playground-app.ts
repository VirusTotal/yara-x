import { DEFAULT_SAMPLE_INPUT, DEFAULT_SAMPLE_RULE } from "../data/sample";
import { LitElement, html, type PropertyValues } from "lit";
import { customElement, query, state } from "lit/decorators.js";

import { YaraFile } from "../components/yara-file";
import "../components/yara-help-dialog";
import "../components/yara-result-panel";
import "../components/yara-settings-dialog";
import "../components/yara-status-bar";
import { PlaygroundEditorController } from "../controllers/playground-editor-controller";
import { PlaygroundSessionController } from "../controllers/playground-session-controller";
import { SplitResizeController } from "../controllers/split-resize-controller";
import { updateYaraConfig } from "../editor/yara-monaco";
import {
  loadStoredPlaygroundSettings,
  storePlaygroundSettings,
} from "../persistence/playground-settings-storage";
import type {
  ExecutionState,
  MatchRange,
  ResultMode,
} from "../results/result-types";
import { summarizeResult } from "../results/summarize-result";
import {
  createSampleHighlights,
  mapSampleByteRangeToEditorRange,
} from "../sample/sample-highlights";
import type { LoadedSampleFile } from "../sample/sample-file";
import { isInlineSampleMode, type SampleMode } from "../sample/sample-modes";
import {
  ScanCancelledError,
  type ScanInput,
  type ScanService,
  type ScanProgressStage,
} from "../scan/scan-service";
import { createScanWorkerClient } from "../scan/scan-worker-client";
import {
  clonePlaygroundSettings,
  createDefaultPlaygroundSettings,
  toYaraConfig,
  type PlaygroundSettings,
} from "../settings/playground-settings";
import type { LanguageServerStatus } from "../language-server/language-server";

const INITIAL_EXECUTION: ExecutionState = {
  raw: {
    message: "Local YARA-X playground ready",
    hint: "Edit the rule, tweak the sample text, then run the scanner.",
  },
  consoleOutput: [],
  durationMs: null,
  summary: summarizeResult({}, "scan"),
};

const MIN_SCAN_INDICATOR_MS = 300;

@customElement("yara-playground-app")
export class YaraPlaygroundApp extends LitElement {
  @query(".rule-editor")
  private ruleEditorHost!: HTMLDivElement;

  @query(".sample-editor")
  private sampleEditorHost!: HTMLDivElement;

  @query(".editor-region")
  private editorRegion!: HTMLDivElement;

  @query(".workspace")
  private workspace!: HTMLDivElement;

  @query("yara-file")
  private filePane!: YaraFile;

  @state()
  private resultMode: ResultMode = "summary";

  @state()
  private sampleMode: SampleMode = "text";

  @state()
  private scanStage: ScanProgressStage = "idle";

  @state()
  private lspStatus: LanguageServerStatus = "idle";

  @state()
  private editorSplit = 49.6;

  @state()
  private workspaceSplit = 50;

  @state()
  private execution = INITIAL_EXECUTION;

  @state()
  private loadedSampleFile: LoadedSampleFile | null = null;

  @state()
  private settingsModalOpen = false;

  @state()
  private helpModalOpen = false;

  @state()
  private languageServerVersion: string | null = null;

  @state()
  private settings = createDefaultPlaygroundSettings();

  @state()
  private canNavigateMatches = false;

  @state()
  private activeMatchRange: MatchRange | null = null;

  private scanService?: ScanService;
  private sampleEditorLayoutFrameId?: number;

  private readonly sessionController = new PlaygroundSessionController(
    this,
    DEFAULT_SAMPLE_RULE,
    DEFAULT_SAMPLE_INPUT,
    {
      onSampleChange: () => {
        this.clearSampleHighlights();
        this.invalidateMatchNavigation();
      },
    },
  );

  private readonly editorController = new PlaygroundEditorController(this, {
    onLanguageServerVersion: (version) => {
      this.languageServerVersion = version;
    },
    onStatus: (status) => {
      this.lspStatus = status;
    },
    onFormatRequest: () => {
      void this.formatRule();
    },
    onRunRequest: () => {
      void this.runScan();
    },
  });

  private readonly editorResizeController = new SplitResizeController(this, {
    getElement: () => this.editorRegion ?? null,
    getAxis: () => (this.isCompactLayout ? "y" : "x"),
    min: 28,
    max: 72,
    onChange: (value) => {
      this.editorSplit = value;
    },
  });

  private readonly workspaceResizeController = new SplitResizeController(this, {
    getElement: () => this.workspace ?? null,
    getAxis: () => "y",
    min: 32,
    max: 78,
    onChange: (value) => {
      this.workspaceSplit = value;
    },
  });

  protected createRenderRoot() {
    // Disable Shadow DOM so Monaco and its floating widgets can render correctly.
    return this;
  }

  private readonly handleKeydown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      if (this.settingsModalOpen) {
        event.preventDefault();
        this.handleSettingsClose();
        return;
      }

      if (this.helpModalOpen) {
        event.preventDefault();
        this.handleHelpClose();
        return;
      }
    }

    if (event.defaultPrevented) {
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      event.key.toLowerCase() === "s"
    ) {
      event.preventDefault();
      void this.formatRule();
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      event.shiftKey &&
      event.key.toLowerCase() === "f"
    ) {
      event.preventDefault();
      void this.formatRule();
      return;
    }

    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      void this.runScan();
    }
  };

  connectedCallback() {
    super.connectedCallback();
    this.sampleMode = this.sessionController.inlineSampleMode;
    this.settings = loadStoredPlaygroundSettings();
    updateYaraConfig(toYaraConfig(this.settings));
    window.addEventListener("keydown", this.handleKeydown);
  }

  protected async firstUpdated() {
    await this.filePane.updateComplete;

    try {
      const { ruleEditor, sampleEditor } =
        await this.editorController.initialize(
          this.ruleEditorHost,
          this.sampleEditorHost,
          this.sessionController.initialRuleValue,
          this.sessionController.getSampleDraft(
            this.sessionController.inlineSampleMode,
          ),
        );

      this.sessionController.bindRuleEditor(ruleEditor);
      this.sessionController.bindSampleEditor(sampleEditor);
    } catch (error) {
      console.error("failed to initialize editors", error);
      this.execution = {
        raw: {
          errors: [error instanceof Error ? error.message : String(error)],
          warnings: [],
          matching_rules: [],
          non_matching_rules: [],
        },
        consoleOutput: [],
        durationMs: null,
        summary: summarizeResult(
          {
            errors: [error instanceof Error ? error.message : String(error)],
          },
          "scan",
        ),
      };
    }
  }

  disconnectedCallback() {
    window.removeEventListener("keydown", this.handleKeydown);
    if (this.sampleEditorLayoutFrameId != null) {
      window.cancelAnimationFrame(this.sampleEditorLayoutFrameId);
    }
    this.scanService?.dispose();
    super.disconnectedCallback();
  }

  protected updated(changedProperties: PropertyValues) {
    if (changedProperties.has("sampleMode") && this.sampleMode !== "file") {
      this.scheduleSampleEditorLayout();
    }
  }

  private get editorsReady() {
    return this.editorController.isReady;
  }

  private get isBusy() {
    return this.scanStage !== "idle";
  }

  private get canRun() {
    return (
      this.editorsReady &&
      !this.isBusy &&
      (this.sampleMode !== "file" || this.loadedSampleFile !== null)
    );
  }

  private get isCompactLayout() {
    return window.innerWidth <= 900;
  }

  private clearSampleHighlights() {
    this.editorController.sample?.clearHighlights();
  }

  private syncSampleHighlights(raw: unknown, mode: SampleMode, source: string) {
    if (!this.editorController.sample || mode === "file" || mode === "base64") {
      this.clearSampleHighlights();
      return;
    }

    this.editorController.sample.setHighlights(
      createSampleHighlights(raw, mode, source, this.activeMatchRange),
    );
  }

  private refreshCurrentSampleHighlights() {
    if (!isInlineSampleMode(this.sampleMode)) {
      return;
    }

    const source = this.editorController.sample?.getValue();
    if (!source) {
      return;
    }

    this.syncSampleHighlights(this.execution.raw, this.sampleMode, source);
  }

  private invalidateMatchNavigation() {
    this.activeMatchRange = null;
    this.canNavigateMatches = false;
  }

  private scheduleSampleEditorLayout() {
    if (!this.editorController.sample) return;

    if (this.sampleEditorLayoutFrameId != null) {
      window.cancelAnimationFrame(this.sampleEditorLayoutFrameId);
    }

    this.sampleEditorLayoutFrameId = window.requestAnimationFrame(() => {
      this.sampleEditorLayoutFrameId = undefined;
      this.editorController.sample?.layout();
    });
  }

  private ensureScanService() {
    if (!this.scanService) {
      this.scanService = createScanWorkerClient({
        onStage: (stage) => {
          this.scanStage = stage;
        },
      });
    }

    return this.scanService;
  }

  private async waitForMinimumScanIndicator(startedAt: number) {
    const remainingMs = MIN_SCAN_INDICATOR_MS - (performance.now() - startedAt);

    if (remainingMs <= 0) {
      return;
    }

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, remainingMs);
    });
  }

  private createScanInput(): ScanInput {
    const ruleSource = this.editorController.rule?.getValue() ?? "";
    const maxMatchesPerPattern = this.settings.scanner.maxMatchesPerPattern;

    if (this.sampleMode === "file") {
      const file = this.loadedSampleFile?.file;

      if (!file) {
        throw new Error("Choose a file before running the scan.");
      }

      return {
        ruleSource,
        sample: { mode: "file", file },
        maxMatchesPerPattern,
      };
    }

    return {
      ruleSource,
      sample: {
        mode: this.sampleMode,
        source: this.editorController.sample?.getValue() ?? "",
      },
      maxMatchesPerPattern,
    };
  }

  private setScanExecution(
    raw: unknown,
    consoleOutput: string[],
    durationMs: number,
  ) {
    this.execution = {
      raw,
      consoleOutput,
      durationMs,
      summary: summarizeResult(raw, "scan"),
    };
  }

  private async publishScanExecution(
    raw: unknown,
    consoleOutput: string[],
    startedAt: number,
    finishedAt: number,
  ) {
    await this.waitForMinimumScanIndicator(startedAt);
    this.setScanExecution(
      raw,
      consoleOutput,
      Math.round(finishedAt - startedAt),
    );
  }

  private syncScanHighlights(raw: unknown, input: ScanInput) {
    if (
      input.sample.mode === "file" ||
      input.sample.mode === "base64" ||
      input.sample.mode !== this.sampleMode ||
      this.editorController.sample?.getValue() !== input.sample.source
    ) {
      this.clearSampleHighlights();
      return false;
    }

    this.syncSampleHighlights(raw, input.sample.mode, input.sample.source);
    return true;
  }

  private async runScan() {
    if (!this.canRun) return;

    const hadActiveMatchRange = this.activeMatchRange !== null;
    this.invalidateMatchNavigation();
    if (hadActiveMatchRange) {
      this.refreshCurrentSampleHighlights();
    }
    this.scanStage = "preparing";
    const startedAt = performance.now();

    try {
      const input = this.createScanInput();
      const scanResponse = await this.ensureScanService().run(input);
      const finishedAt = performance.now();

      await this.publishScanExecution(
        scanResponse.raw,
        scanResponse.consoleOutput,
        startedAt,
        finishedAt,
      );
      this.canNavigateMatches = this.syncScanHighlights(
        scanResponse.raw,
        input,
      );
    } catch (error) {
      if (error instanceof ScanCancelledError) {
        const raw = { cancelled: true };

        this.setScanExecution(
          raw,
          [],
          Math.round(performance.now() - startedAt),
        );
        this.clearSampleHighlights();
        this.invalidateMatchNavigation();
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      const finishedAt = performance.now();
      const raw = {
        errors: [message],
        warnings: [],
        matching_rules: [],
        non_matching_rules: [],
      };

      await this.publishScanExecution(raw, [], startedAt, finishedAt);
      this.clearSampleHighlights();
      this.invalidateMatchNavigation();
    } finally {
      this.scanStage = "idle";
    }
  }

  private async formatRule() {
    if (!this.editorController.rule || this.lspStatus !== "ready") return;

    const formatted = await this.editorController.formatRule();
    if (!formatted) {
      console.warn("format action is not available for the YARA editor");
    }
  }

  private handleRunRequest = () => {
    void this.runScan();
  };

  private handleCancelRequest = () => {
    this.scanService?.cancel();
  };

  private handleSampleModeChange = (event: CustomEvent<SampleMode>) => {
    if (event.detail === this.sampleMode) return;

    this.sampleMode = event.detail;

    if (isInlineSampleMode(event.detail)) {
      this.sessionController.selectInlineSampleMode(event.detail);
    } else {
      this.sessionController.selectFileMode();
    }

    this.clearSampleHighlights();
    this.invalidateMatchNavigation();
  };

  private handleSampleFileLoad = (event: CustomEvent<LoadedSampleFile>) => {
    this.sessionController.selectFileMode();
    this.loadedSampleFile = event.detail;
    this.sampleMode = "file";
    this.clearSampleHighlights();
    this.invalidateMatchNavigation();
  };

  private handleSampleFileClear = () => {
    const inlineSampleMode = this.sessionController.inlineSampleMode;

    this.loadedSampleFile = null;
    this.sampleMode = inlineSampleMode;
    this.sessionController.restoreActiveSampleDraft();
    this.clearSampleHighlights();
    this.invalidateMatchNavigation();
  };

  private handleResultModeChange = (event: CustomEvent<ResultMode>) => {
    this.resultMode = event.detail;
  };

  private handleMatchRangeRequest = (event: CustomEvent<MatchRange>) => {
    if (
      !this.canNavigateMatches ||
      (this.sampleMode !== "text" && this.sampleMode !== "hex")
    ) {
      return;
    }

    const source = this.editorController.sample?.getValue();
    if (!source) {
      return;
    }

    const isActiveRange =
      this.activeMatchRange?.start === event.detail.start &&
      this.activeMatchRange.end === event.detail.end;

    if (isActiveRange) {
      this.activeMatchRange = null;
      this.syncSampleHighlights(this.execution.raw, this.sampleMode, source);
      return;
    }

    const range = mapSampleByteRangeToEditorRange(
      this.sampleMode,
      source,
      event.detail,
    );

    if (range) {
      this.activeMatchRange = event.detail;
      this.syncSampleHighlights(this.execution.raw, this.sampleMode, source);
      this.editorController.sample?.revealRange(range.start, range.end);
    }
  };

  private handleSettingsRequest = () => {
    this.settingsModalOpen = true;
  };

  private handleSettingsClose = () => {
    this.settingsModalOpen = false;
  };

  private handleHelpRequest = () => {
    this.helpModalOpen = true;
  };

  private handleHelpClose = () => {
    this.helpModalOpen = false;
  };

  private async recreateRuleEditor() {
    if (!this.editorController.rule) return;

    try {
      const ruleEditor = await this.editorController.recreateRuleEditor(
        this.ruleEditorHost,
      );

      if (ruleEditor) {
        this.sessionController.bindRuleEditor(ruleEditor);
      }
    } catch (error) {
      console.error("failed to reinitialize yara editor", error);
    }
  }

  private handleSettingsApply = async (
    event: CustomEvent<PlaygroundSettings>,
  ) => {
    const nextSettings = clonePlaygroundSettings(event.detail);
    const lspSettingsChanged =
      JSON.stringify(toYaraConfig(this.settings)) !==
      JSON.stringify(toYaraConfig(nextSettings));

    this.settings = nextSettings;
    updateYaraConfig(toYaraConfig(nextSettings));
    storePlaygroundSettings(nextSettings);
    this.settingsModalOpen = false;

    if (lspSettingsChanged) {
      await this.recreateRuleEditor();
    }
  };

  render() {
    return html`
      <main class="studio">
        <yara-status-bar
          .isBusy=${this.isBusy}
          .canRun=${this.canRun}
          @run-request=${this.handleRunRequest}
          @cancel-request=${this.handleCancelRequest}
          @help-request=${this.handleHelpRequest}
          @settings-request=${this.handleSettingsRequest}
        ></yara-status-bar>

        <section
          class="workspace"
          style=${`--workspace-split: ${this.workspaceSplit.toFixed(2)}%;`}
        >
          <section
            class="editor-region"
            style=${`--editor-split: ${this.editorSplit.toFixed(2)}%;`}
          >
            <article class="pane">
              <header class="pane-head">
                <div class="pane-head-copy">
                  <h2>Rule editor</h2>
                </div>
                <span class="pane-meta">main.yar</span>
              </header>
              <div class="editor-shell rule-editor"></div>
            </article>

            <div
              class="editor-divider"
              role="separator"
              aria-label="Resize editors"
              aria-orientation=${this.isCompactLayout
                ? "horizontal"
                : "vertical"}
              @pointerdown=${this.editorResizeController.start}
            >
              <div class="divider-handle"></div>
            </div>

            <yara-file
              .sampleMode=${this.sampleMode}
              .loadedSampleFile=${this.loadedSampleFile}
              @sample-mode-change=${this.handleSampleModeChange}
              @sample-file-load=${this.handleSampleFileLoad}
              @sample-file-clear=${this.handleSampleFileClear}
            ></yara-file>
          </section>

          <div
            class="workspace-divider"
            role="separator"
            aria-label="Resize results"
            aria-orientation="horizontal"
            @pointerdown=${this.workspaceResizeController.start}
          >
            <div class="divider-handle horizontal"></div>
          </div>

          <yara-result-panel
            .resultMode=${this.resultMode}
            .execution=${this.execution}
            .canNavigateMatches=${this.canNavigateMatches}
            .activeMatchRange=${this.activeMatchRange}
            @result-mode-change=${this.handleResultModeChange}
            @match-range-request=${this.handleMatchRangeRequest}
          ></yara-result-panel>
        </section>

        <yara-settings-dialog
          .open=${this.settingsModalOpen}
          .settings=${this.settings}
          @settings-close=${this.handleSettingsClose}
          @settings-apply=${this.handleSettingsApply}
        ></yara-settings-dialog>

        <yara-help-dialog
          .open=${this.helpModalOpen}
          .languageServerVersion=${this.languageServerVersion}
          @help-close=${this.handleHelpClose}
        ></yara-help-dialog>
      </main>
    `;
  }
}
