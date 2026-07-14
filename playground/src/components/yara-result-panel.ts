import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import { classMap } from "lit/directives/class-map.js";
import type {
  ExecutionState,
  MatchRange,
  ResultMode,
} from "../results/result-types";
import { summarizeResult } from "../results/summarize-result";

const EMPTY_EXECUTION: ExecutionState = {
  raw: {},
  consoleOutput: [],
  durationMs: null,
  summary: summarizeResult({}, "scan"),
};

type CopyableResultMode = "raw" | "console";

const RAW_OUTPUT_CLASS = "raw-output output-content playground-scroll";
const CONSOLE_OUTPUT_CLASS = `${RAW_OUTPUT_CLASS} console-output`;

function formatSeconds(durationMs: number) {
  return (durationMs / 1000).toFixed(2).replace(/\.?0+$/, "");
}

function formatDuration(durationMs: number | null) {
  if (durationMs === null) {
    return "--";
  }

  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }

  if (durationMs < 60_000) {
    return `${formatSeconds(durationMs)} s`;
  }

  const minutes = Math.floor(durationMs / 60_000);
  const remainingMs = durationMs % 60_000;

  return remainingMs === 0
    ? `${minutes} min`
    : `${minutes} min ${formatSeconds(remainingMs)} s`;
}

@customElement("yara-result-panel")
export class YaraResultPanel extends LitElement {
  @property({ type: String })
  resultMode: ResultMode = "summary";

  @property({ attribute: false })
  execution: ExecutionState = EMPTY_EXECUTION;

  @property({ type: Boolean })
  canNavigateMatches = false;

  @property({ attribute: false })
  activeMatchRange: MatchRange | null = null;

  @state()
  private copiedMode: CopyableResultMode | null = null;

  private copyFeedbackTimeoutId: number | null = null;

  protected createRenderRoot() {
    return this;
  }

  disconnectedCallback() {
    if (this.copyFeedbackTimeoutId !== null) {
      window.clearTimeout(this.copyFeedbackTimeoutId);
      this.copyFeedbackTimeoutId = null;
    }

    super.disconnectedCallback();
  }

  private get resultLabel() {
    switch (this.execution.summary.tone) {
      case "match":
        return "Match";
      case "clean":
        return "Clean";
      case "warning":
        return "Warnings";
      case "issues":
        return "Issues";
      case "cancelled":
        return "Cancelled";
      default:
        return "Ready";
    }
  }

  private dispatchResultModeChange(mode: ResultMode) {
    this.dispatchEvent(
      new CustomEvent<ResultMode>("result-mode-change", {
        detail: mode,
        bubbles: true,
        composed: true,
      }),
    );
  }

  private dispatchMatchRangeRequest(range: MatchRange) {
    this.dispatchEvent(
      new CustomEvent<MatchRange>("match-range-request", {
        detail: range,
        bubbles: true,
        composed: true,
      }),
    );
  }

  private isActiveMatchRange(range: MatchRange) {
    return (
      this.activeMatchRange?.start === range.start &&
      this.activeMatchRange.end === range.end
    );
  }

  private renderStat(label: string, value: number) {
    return html`
      <div class="stat">
        <span>${label}</span>
        <strong>${value}</strong>
      </div>
    `;
  }

  private renderIssues(
    title: string,
    issues: string[],
    kind: "warnings" | "errors",
  ) {
    if (issues.length === 0) return nothing;

    return html`
      <section class=${classMap({ "result-section": true, [kind]: true })}>
        <div class="section-heading">${title}</div>
        <ul class=${classMap({ "issue-list": true, [kind]: true })}>
          ${issues.map((issue) => html`<li>${issue}</li>`)}
        </ul>
      </section>
    `;
  }

  private renderMatches() {
    const { matchingRules } = this.execution.summary;

    return html`
      <section class="result-section">
        <div class="result-row">
          <div class="section-heading">Matching rules</div>
          <span class="muted">${matchingRules.length}</span>
        </div>

        ${matchingRules.length === 0
          ? html`
              <p class="empty-copy">
                No matching rules for the current sample.
              </p>
            `
          : html`
              <div class="match-list">
                ${matchingRules.map(
                  (rule) => html`
                    <article class="match-item">
                      <div class="result-row">
                        <div>
                          <h3>${rule.identifier}</h3>
                          <p class="muted">${rule.namespace}</p>
                        </div>
                        <span class="hit-pill">${rule.hits} hits</span>
                      </div>
                      <div class="pattern-list">
                        ${rule.patterns.map(
                          (pattern) => html`
                            <div class="pattern-row">
                              <span>${pattern.identifier}</span>
                              <div class="match-range-list">
                                ${pattern.ranges.length === 0
                                  ? html`<code>No ranges</code>`
                                  : pattern.ranges.map((range) => {
                                      const isActive =
                                        this.isActiveMatchRange(range);

                                      return html`
                                        <button
                                          type="button"
                                          class=${classMap({
                                            "match-range-button": true,
                                            "is-active": isActive,
                                          })}
                                          title=${this.canNavigateMatches
                                            ? "Show this match in the sample editor"
                                            : "Scan in progress"}
                                          aria-pressed=${isActive
                                            ? "true"
                                            : "false"}
                                          ?disabled=${!this.canNavigateMatches}
                                          @click=${() => {
                                            this.dispatchMatchRangeRequest(
                                              range,
                                            );
                                          }}
                                        >
                                          ${range.start}-${range.end}
                                        </button>
                                      `;
                                    })}
                              </div>
                            </div>
                          `,
                        )}
                      </div>
                    </article>
                  `,
                )}
              </div>
            `}
      </section>
    `;
  }

  private renderNonMatches() {
    const { nonMatchingRules } = this.execution.summary;

    if (nonMatchingRules.length === 0) return nothing;

    return html`
      <section class="result-section">
        <div class="section-heading">Non-matching rules</div>
        <div class="token-row">
          ${nonMatchingRules.map(
            (rule) => html`<span class="token">${rule}</span>`,
          )}
        </div>
      </section>
    `;
  }

  private renderSummaryResults() {
    const { summary } = this.execution;

    return html`
      <section class="metrics-grid">
        ${this.renderStat("Matches", summary.matches)}
        ${this.renderStat("Non-matches", summary.nonMatches)}
        ${this.renderStat("Warnings", summary.warnings)}
        ${this.renderStat("Errors", summary.errors)}
      </section>

      <section
        class=${classMap({
          "headline-strip": true,
          [summary.tone]: true,
        })}
      >
        <div class="result-row">
          <p>${summary.headline}</p>
          <span
            class=${classMap({
              "hit-pill": true,
              [summary.tone]: true,
            })}
          >
            ${this.resultLabel}
          </span>
        </div>
      </section>

      ${this.renderIssues("Warnings", summary.warningsList, "warnings")}
      ${this.renderIssues("Errors", summary.errorsList, "errors")}
      ${this.renderMatches()} ${this.renderNonMatches()}
    `;
  }

  private get rawOutputText() {
    return JSON.stringify(this.execution.raw, null, 2) ?? "null";
  }

  private get consoleOutputText() {
    return this.execution.consoleOutput.join("\n");
  }

  private async writeTextToClipboard(text: string) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }

  private async copyOutput(mode: CopyableResultMode, text: string) {
    if (!text) {
      return;
    }

    try {
      await this.writeTextToClipboard(text);
      this.copiedMode = mode;

      if (this.copyFeedbackTimeoutId !== null) {
        window.clearTimeout(this.copyFeedbackTimeoutId);
      }

      this.copyFeedbackTimeoutId = window.setTimeout(() => {
        this.copiedMode = null;
        this.copyFeedbackTimeoutId = null;
      }, 1600);
    } catch {
      this.copiedMode = null;
    }
  }

  private renderCopyButton(mode: CopyableResultMode, text: string) {
    if (text.trim().length === 0) {
      return nothing;
    }

    const isCopied = this.copiedMode === mode;

    return html`
      <button
        type="button"
        class="copy-output-button"
        @click=${() => {
          void this.copyOutput(mode, text);
        }}
      >
        ${isCopied ? "Copied" : "Copy"}
      </button>
    `;
  }

  private renderRawResults() {
    return html`
      <section class="output-shell">
        <div class="output-toolbar">
          <div class="section-heading">Raw output</div>
          ${this.renderCopyButton("raw", this.rawOutputText)}
        </div>
        <pre class=${RAW_OUTPUT_CLASS}>${this.rawOutputText}</pre>
      </section>
    `;
  }

  private renderConsoleResults() {
    if (this.execution.consoleOutput.length === 0) {
      return html`
        <section class="output-shell">
          <div class="output-toolbar">
            <div class="section-heading">Console output</div>
            ${this.renderCopyButton("console", this.consoleOutputText)}
          </div>
          <div class="console-empty-state output-content playground-scroll">
            <p class="empty-copy">
              Nothing here yet. Import the <code>console</code> module and call
              <code>console.log()</code> in your rule to see output after
              running a scan.
            </p>
            <div class="console-example-block">
              <span class="eyebrow">Example</span>
              <pre class="raw-output console-output">
import "console"

rule debug_console_example {
    condition:
        console.log("Hello") and console.log("World!")
}</pre
              >
            </div>
          </div>
        </section>
      `;
    }

    return html`
      <section class="output-shell">
        <div class="output-toolbar">
          <div class="section-heading">Console output</div>
          ${this.renderCopyButton("console", this.consoleOutputText)}
        </div>
        <pre class=${CONSOLE_OUTPUT_CLASS}>${this.consoleOutputText}</pre>
      </section>
    `;
  }

  private renderModeChip(mode: ResultMode, label: string) {
    return html`
      <label
        class=${classMap({
          "mode-chip": true,
          active: this.resultMode === mode,
        })}
      >
        <input
          type="radio"
          name="result-mode"
          .checked=${this.resultMode === mode}
          @change=${() => {
            this.dispatchResultModeChange(mode);
          }}
        />
        <span class="mode-chip-label">${label}</span>
      </label>
    `;
  }

  render() {
    return html`
      <section class="results-region">
        <header class="results-head">
          <div>
            <h2>Scan results</h2>
          </div>

          <div class="results-controls">
            <div class="mode-switch" role="tablist" aria-label="Result mode">
              ${this.renderModeChip("summary", "Summary")}
              ${this.renderModeChip("raw", "Raw")}
              ${this.renderModeChip("console", "Console")}
            </div>
            <span class="duration-chip">
              ${formatDuration(this.execution.durationMs)}
            </span>
          </div>
        </header>

        <div class="results-body playground-scroll">
          ${this.resultMode === "summary"
            ? this.renderSummaryResults()
            : this.resultMode === "raw"
              ? this.renderRawResults()
              : this.renderConsoleResults()}
        </div>
      </section>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "yara-result-panel": YaraResultPanel;
  }
}
