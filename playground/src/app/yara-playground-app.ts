import { DEFAULT_SAMPLE_INPUT, DEFAULT_SAMPLE_RULE } from "../data/sample";
import type {
  ExecutionState,
  LoadedSampleFile,
  ResultMode,
  SampleMode,
} from "../types/execution";
import { LitElement, html } from "lit";
import { customElement, query, state } from "lit/decorators.js";

import { YaraFile } from "../components/yara-file";
import "../components/yara-result-panel";
import "../components/yara-status-bar";
import { SplitResizeController } from "../controllers/split-resize-controller";
import {
  createPlainTextEditor,
  createYaraEditor,
  type EditorHandle,
} from "../editor/yara-monaco";
import { summarizeResult } from "../results/summarize-result";
import { getWasmYaraEngine } from "../services/wasm-yara-engine";
import type { ServiceStatus } from "../types/service-status";
import type { YaraEngine } from "../services/yara-engine";

const INITIAL_EXECUTION: ExecutionState = {
  raw: {
    message: "Local YARA-X playground ready",
    hint: "Edit the rule, tweak the sample text, then run the scanner.",
  },
  durationMs: null,
  summary: summarizeResult({}, "scan"),
};

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
  private isBusy = false;

  @state()
  private lspStatus: ServiceStatus = "idle";

  @state()
  private coreStatus: ServiceStatus = "idle";

  @state()
  private editorSplit = 49.6;

  @state()
  private workspaceSplit = 50;

  @state()
  private execution = INITIAL_EXECUTION;

  @state()
  private loadedSampleFile: LoadedSampleFile | null = null;

  private ruleEditor?: EditorHandle;
  private sampleEditor?: EditorHandle;
  private engine?: YaraEngine;

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
    window.addEventListener("keydown", this.handleKeydown);
  }

  protected async firstUpdated() {
    await this.filePane.updateComplete;

    try {
      const [ruleEditor, sampleEditor] = await Promise.all([
        createYaraEditor(this.ruleEditorHost, DEFAULT_SAMPLE_RULE),
        createPlainTextEditor(this.sampleEditorHost, DEFAULT_SAMPLE_INPUT),
      ]);

      this.ruleEditor = ruleEditor;
      this.sampleEditor = sampleEditor;
      this.lspStatus = "idle";
    } catch (error) {
      console.error("failed to initialize editors", error);
      this.lspStatus = "error";
      this.execution = {
        raw: {
          errors: [error instanceof Error ? error.message : String(error)],
          warnings: [],
          matching_rules: [],
          non_matching_rules: [],
        },
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
    this.ruleEditor?.dispose();
    this.sampleEditor?.dispose();
    super.disconnectedCallback();
  }

  private get editorsReady() {
    return Boolean(
      this.ruleEditor && this.sampleEditor && this.lspStatus === "ready",
    );
  }

  private get canRun() {
    return (
      this.editorsReady &&
      !this.isBusy &&
      (this.sampleMode === "text" || this.loadedSampleFile !== null)
    );
  }

  private get isCompactLayout() {
    return window.innerWidth <= 900;
  }

  private async ensureEngine() {
    this.coreStatus = "loading";

    try {
      if (!this.engine) {
        this.engine = getWasmYaraEngine();
      }

      this.coreStatus = "ready";
      return this.engine;
    } catch (error) {
      this.coreStatus = "error";
      throw error;
    }
  }

  private async runScan() {
    if (!this.canRun) return;

    this.isBusy = true;
    const startedAt = performance.now();

    try {
      const engine = await this.ensureEngine();
      let sampleBytes: Uint8Array;

      if (this.sampleMode === "file") {
        sampleBytes = this.loadedSampleFile?.bytes ?? new Uint8Array();
      } else {
        sampleBytes = new TextEncoder().encode(
          this.sampleEditor?.getValue() ?? "",
        );
      }

      const compiler = await engine.createCompiler();
      compiler.addSource(this.ruleEditor?.getValue() ?? "");

      const rules = compiler.build();
      const raw = rules.scan(sampleBytes);

      this.execution = {
        raw,
        durationMs: Math.round(performance.now() - startedAt),
        summary: summarizeResult(raw, "scan"),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const raw = {
        errors: [message],
        warnings: [],
        matching_rules: [],
        non_matching_rules: [],
      };

      this.execution = {
        raw,
        durationMs: Math.round(performance.now() - startedAt),
        summary: summarizeResult(raw, "scan"),
      };
    } finally {
      this.isBusy = false;
    }
  }

  private async formatRule() {
    if (!this.ruleEditor || this.lspStatus !== "ready") return;

    const formatted = await this.ruleEditor.format();
    if (!formatted) {
      console.warn("format action is not available for the YARA editor");
    }
  }

  private handleRunRequest = () => {
    void this.runScan();
  };

  private handleSampleModeChange = (event: CustomEvent<SampleMode>) => {
    this.sampleMode = event.detail;
  };

  private handleSampleFileLoad = (event: CustomEvent<LoadedSampleFile>) => {
    this.loadedSampleFile = event.detail;
    this.sampleMode = "file";
  };

  private handleSampleFileClear = () => {
    this.loadedSampleFile = null;
    this.sampleMode = "text";
  };

  private handleResultModeChange = (event: CustomEvent<ResultMode>) => {
    this.resultMode = event.detail;
  };

  render() {
    return html`
      <main class="studio">
        <yara-status-bar
          .coreStatus=${this.coreStatus}
          .lspStatus=${this.lspStatus}
          .isBusy=${this.isBusy}
          .canRun=${this.canRun}
          @run-request=${this.handleRunRequest}
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
            @result-mode-change=${this.handleResultModeChange}
          ></yara-result-panel>
        </section>
      </main>
    `;
  }
}
