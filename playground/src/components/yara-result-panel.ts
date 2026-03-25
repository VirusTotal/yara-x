import type { ExecutionState, ResultMode } from "../types/execution";
import { LitElement, html, nothing } from "lit";
import { customElement, property } from "lit/decorators.js";

import { classMap } from "lit/directives/class-map.js";
import { summarizeResult } from "../results/summarize-result";

const EMPTY_EXECUTION: ExecutionState = {
  raw: {},
  durationMs: null,
  summary: summarizeResult({}, "scan"),
};

@customElement("yara-result-panel")
export class YaraResultPanel extends LitElement {
  @property({ type: String })
  resultMode: ResultMode = "summary";

  @property({ attribute: false })
  execution: ExecutionState = EMPTY_EXECUTION;

  protected createRenderRoot() {
    return this;
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
                              <code
                                >${pattern.ranges.join(", ") ||
                                "No ranges"}</code
                              >
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
      ${this.renderMatches()}
      ${this.renderNonMatches()}
    `;
  }

  private renderRawResults() {
    return html`<pre class="raw-output">
${JSON.stringify(this.execution.raw, null, 2)}</pre
    >`;
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
        <span>${label}</span>
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
            </div>
            <span class="duration-chip">
              ${this.execution.durationMs === null
                ? "--"
                : `${this.execution.durationMs} ms`}
            </span>
          </div>
        </header>

        <div class="results-body">
          ${this.resultMode === "summary"
            ? this.renderSummaryResults()
            : this.renderRawResults()}
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
