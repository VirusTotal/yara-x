import { LitElement, html, nothing } from "lit";
import { customElement, property, query, state } from "lit/decorators.js";

import { classMap } from "lit/directives/class-map.js";
import type { LoadedSampleFile } from "../sample/sample-file";
import { SAMPLE_MODES, type SampleMode } from "../sample/sample-modes";

@customElement("yara-file")
export class YaraFile extends LitElement {
  @property({ type: String })
  sampleMode: SampleMode = "text";

  @property({ attribute: false })
  loadedSampleFile: LoadedSampleFile | null = null;

  @query("#sample-file-input")
  private sampleFileInput!: HTMLInputElement;

  @state()
  private isDragActive = false;

  protected createRenderRoot() {
    return this;
  }

  private dispatchSampleModeChange(mode: SampleMode) {
    this.dispatchEvent(
      new CustomEvent<SampleMode>("sample-mode-change", {
        detail: mode,
        bubbles: true,
        composed: true,
      }),
    );
  }

  private createLoadedSampleFile(file: File): LoadedSampleFile {
    return {
      file,
      name: file.name,
      size: file.size,
    };
  }

  private emitLoadedSampleFile(file: File) {
    const loadedSampleFile = this.createLoadedSampleFile(file);

    this.dispatchEvent(
      new CustomEvent<LoadedSampleFile>("sample-file-load", {
        detail: loadedSampleFile,
        bubbles: true,
        composed: true,
      }),
    );
  }

  private openSampleFilePicker = () => {
    this.sampleFileInput?.click();
  };

  private handleFileChange(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];

    if (!file) return;

    this.emitLoadedSampleFile(file);
    input.value = "";
  }

  private handleDragEnter = (event: DragEvent) => {
    if (this.sampleMode !== "file") return;
    if (!event.dataTransfer?.types.includes("Files")) return;

    event.preventDefault();
    this.isDragActive = true;
  };

  private handleDragOver = (event: DragEvent) => {
    if (this.sampleMode !== "file") return;
    if (!event.dataTransfer?.types.includes("Files")) return;

    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    this.isDragActive = true;
  };

  private handleDragLeave = (event: DragEvent) => {
    if (this.sampleMode !== "file") return;

    const nextTarget = event.relatedTarget as Node | null;

    if (nextTarget && event.currentTarget instanceof Node) {
      if (event.currentTarget.contains(nextTarget)) return;
    }

    this.isDragActive = false;
  };

  private handleDrop = (event: DragEvent) => {
    if (this.sampleMode !== "file") return;

    event.preventDefault();
    this.isDragActive = false;

    const file = event.dataTransfer?.files?.[0];

    if (!file) return;

    this.emitLoadedSampleFile(file);
  };

  private clearLoadedFile = () => {
    this.dispatchEvent(
      new CustomEvent("sample-file-clear", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private formatBytes(size: number) {
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }

  private renderModeChip({ id, label }: (typeof SAMPLE_MODES)[number]) {
    const hasTooltip = id === "base64";

    return html`
      <label
        class=${classMap({
          "mode-chip": true,
          active: this.sampleMode === id,
          "has-tooltip": hasTooltip,
        })}
      >
        <input
          type="radio"
          name="sample-mode"
          .checked=${this.sampleMode === id}
          aria-describedby=${hasTooltip ? "base64-mode-tooltip" : nothing}
          @change=${() => {
            this.dispatchSampleModeChange(id);
          }}
        />
        <span class="mode-chip-label">${label}</span>
        ${hasTooltip
          ? html`
              <span
                id="base64-mode-tooltip"
                class="mode-tooltip"
                role="tooltip"
              >
                Decoded before scanning. For the <code>base64</code> modifier,
                use Text mode.
              </span>
            `
          : nothing}
      </label>
    `;
  }

  private renderFileState() {
    if (!this.loadedSampleFile) {
      return html`
        <div class=${classMap({ "file-state": true, empty: true })}>
          <div class="file-state-copy">
            <span class="eyebrow">File mode</span>
            <h3>No file selected yet</h3>
            <p>
              Choose a file or drag one here to keep everything local in your
              browser. Nothing leaves your device.
            </p>
          </div>
          <button
            type="button"
            class="secondary-button"
            @click=${this.openSampleFilePicker}
          >
            Choose file
          </button>
        </div>
      `;
    }

    return html`
      <div class=${classMap({ "file-state": true, loaded: true })}>
        <div class="file-state-copy">
          <span class="eyebrow">File ready</span>
          <h3>${this.loadedSampleFile.name}</h3>
          <p>
            ${this.formatBytes(this.loadedSampleFile.size)} ready to scan
            locally in this browser session. Drop another file here to replace
            it.
          </p>
        </div>
        <div class="file-state-actions">
          <button
            type="button"
            class="secondary-button"
            @click=${this.openSampleFilePicker}
          >
            Replace
          </button>
          <button
            type="button"
            class="ghost-button"
            @click=${this.clearLoadedFile}
          >
            Cancel
          </button>
        </div>
      </div>
    `;
  }

  render() {
    return html`
      <article class="pane sample-pane">
        <header class="pane-head">
          <div class="pane-head-copy">
            <h2>Sample editor</h2>
          </div>
        </header>
        <div class="sample-pane-controls">
          <div class="sample-head-actions">
            <div class="mode-switch" role="tablist" aria-label="Sample source">
              ${SAMPLE_MODES.map((mode) => this.renderModeChip(mode))}
            </div>

            <input
              id="sample-file-input"
              type="file"
              hidden
              @change=${this.handleFileChange}
            />
          </div>
        </div>
        <div
          class=${classMap({
            "sample-pane-shell": true,
            "is-file-mode": this.sampleMode === "file",
            "is-drag-active": this.isDragActive,
          })}
          @dragenter=${this.handleDragEnter}
          @dragover=${this.handleDragOver}
          @dragleave=${this.handleDragLeave}
          @drop=${this.handleDrop}
        >
          <div class="editor-shell sample-editor"></div>
          <div class="file-state-shell playground-scroll">
            ${this.renderFileState()}
          </div>
        </div>
      </article>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "yara-file": YaraFile;
  }
}
