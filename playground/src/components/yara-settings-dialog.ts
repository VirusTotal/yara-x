import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import {
  clonePlaygroundSettings,
  createDefaultPlaygroundSettings,
  createEmptyMetadataValidationRule,
  parseScannerMaxMatches,
  type MetadataValidationType,
  type PlaygroundMetadataValidationRule,
  type PlaygroundSettings,
} from "../settings/playground-settings";

type SettingsTab = "editor" | "scanner";

@customElement("yara-settings-dialog")
export class YaraSettingsDialog extends LitElement {
  @property({ type: Boolean })
  open = false;

  @property({ attribute: false })
  settings: PlaygroundSettings = createDefaultPlaygroundSettings();

  @state()
  private activeTab: SettingsTab = "editor";

  @state()
  private draftSettings: PlaygroundSettings = createDefaultPlaygroundSettings();

  @state()
  private metadataValidationError: string | null = null;

  @state()
  private maxMatchesPerPatternInput = "";

  @state()
  private maxMatchesPerPatternError: string | null = null;

  protected createRenderRoot() {
    return this;
  }

  protected willUpdate(changedProperties: Map<string, unknown>) {
    if (changedProperties.has("open") && this.open) {
      this.activeTab = "editor";
      this.draftSettings = clonePlaygroundSettings(this.settings);
      this.metadataValidationError = null;
      this.maxMatchesPerPatternInput =
        this.settings.scanner.maxMatchesPerPattern?.toString() ?? "";
      this.maxMatchesPerPatternError = null;
      return;
    }

    if (changedProperties.has("settings") && !this.open) {
      this.draftSettings = clonePlaygroundSettings(this.settings);
    }
  }

  private dispatchClose = () => {
    this.dispatchEvent(
      new CustomEvent("settings-close", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private dispatchApply = () => {
    if (this.maxMatchesPerPatternError) {
      this.activeTab = "scanner";
      return;
    }

    const hasEmptyIdentifier =
      this.draftSettings.editor.metadataValidation.some(
        (rule) => rule?.identifier?.trim()?.length === 0,
      );

    if (hasEmptyIdentifier) {
      this.metadataValidationError =
        "Each metadata rule needs an identifier before you apply changes.";
      return;
    }

    this.dispatchEvent(
      new CustomEvent<PlaygroundSettings>("settings-apply", {
        detail: clonePlaygroundSettings(this.draftSettings),
        bubbles: true,
        composed: true,
      }),
    );
  };

  private updateFormattingSetting(
    key: keyof PlaygroundSettings["editor"]["formatting"],
    checked: boolean,
  ) {
    this.draftSettings = {
      ...this.draftSettings,
      editor: {
        ...this.draftSettings.editor,
        formatting: {
          ...this.draftSettings.editor.formatting,
          [key]: checked,
        },
      },
    };
  }

  private updateRuleNameValidation(value: string) {
    this.draftSettings = {
      ...this.draftSettings,
      editor: {
        ...this.draftSettings.editor,
        ruleNameValidation: value,
      },
    };
  }

  private addMetadataRule = () => {
    this.draftSettings = {
      ...this.draftSettings,
      editor: {
        ...this.draftSettings.editor,
        metadataValidation: [
          ...this.draftSettings.editor.metadataValidation,
          createEmptyMetadataValidationRule(),
        ],
      },
    };
    this.metadataValidationError = null;
  };

  private updateMetadataRule(
    index: number,
    nextRule: PlaygroundMetadataValidationRule,
  ) {
    const metadataValidation = [
      ...this.draftSettings.editor.metadataValidation,
    ];
    metadataValidation[index] = nextRule;

    this.draftSettings = {
      ...this.draftSettings,
      editor: {
        ...this.draftSettings.editor,
        metadataValidation,
      },
    };
    this.metadataValidationError = null;
  }

  private removeMetadataRule(index: number) {
    this.draftSettings = {
      ...this.draftSettings,
      editor: {
        ...this.draftSettings.editor,
        metadataValidation: this.draftSettings.editor.metadataValidation.filter(
          (_, ruleIndex) => ruleIndex !== index,
        ),
      },
    };
    this.metadataValidationError = null;
  }

  private updateMaxMatchesPerPattern(input: HTMLInputElement) {
    const value = input.value;
    this.maxMatchesPerPatternInput = value;

    const maxMatchesPerPattern = parseScannerMaxMatches(value);

    if (
      input.validity.badInput ||
      (value.trim().length > 0 && maxMatchesPerPattern === null)
    ) {
      this.maxMatchesPerPatternError =
        "Enter a positive whole number, such as 100.";
      return;
    }

    this.maxMatchesPerPatternError = null;
    this.draftSettings = {
      ...this.draftSettings,
      scanner: {
        ...this.draftSettings.scanner,
        maxMatchesPerPattern,
      },
    };
  }

  private renderTabButton(tab: SettingsTab, label: string) {
    return html`
      <button
        type="button"
        role="tab"
        aria-selected=${this.activeTab === tab ? "true" : "false"}
        class=${this.activeTab === tab ? "settings-tab active" : "settings-tab"}
        @click=${() => {
          this.activeTab = tab;
        }}
      >
        ${label}
      </button>
    `;
  }

  private renderFormattingToggle(
    key: keyof PlaygroundSettings["editor"]["formatting"],
    label: string,
    hint: string,
  ) {
    return html`
      <label class="settings-toggle">
        <input
          type="checkbox"
          .checked=${this.draftSettings.editor.formatting[key]}
          @change=${(event: Event) => {
            const target = event.target as HTMLInputElement;
            this.updateFormattingSetting(key, target.checked);
          }}
        />
        <span class="settings-toggle-copy">
          <strong>${label}</strong>
          <small>${hint}</small>
        </span>
      </label>
    `;
  }

  private renderMetadataRuleRow(
    rule: PlaygroundMetadataValidationRule,
    index: number,
  ) {
    const isInvalid =
      this.metadataValidationError !== null && rule.identifier.trim() === "";

    return html`
      <article class="settings-row-card">
        <div class="settings-row-grid metadata">
          <label class="settings-field">
            <span>Identifier</span>
            <input
              type="text"
              .value=${rule.identifier}
              placeholder="author"
              aria-invalid=${isInvalid ? "true" : "false"}
              @input=${(event: Event) => {
                const target = event.target as HTMLInputElement;
                this.updateMetadataRule(index, {
                  ...rule,
                  identifier: target.value,
                });
              }}
            />
          </label>

          <label class="settings-field compact">
            <span>Type</span>
            <select
              .value=${rule.type}
              @change=${(event: Event) => {
                const target = event.target as HTMLSelectElement;
                this.updateMetadataRule(index, {
                  ...rule,
                  type: target.value as MetadataValidationType,
                });
              }}
            >
              <option value="string">string</option>
              <option value="integer">integer</option>
              <option value="float">float</option>
              <option value="bool">bool</option>
              <option value="date">date</option>
            </select>
          </label>

          <label class="settings-check">
            <input
              type="checkbox"
              .checked=${rule.required}
              @change=${(event: Event) => {
                const target = event.target as HTMLInputElement;
                this.updateMetadataRule(index, {
                  ...rule,
                  required: target.checked,
                });
              }}
            />
            <span>Required</span>
          </label>

          <button
            type="button"
            class="settings-remove"
            @click=${() => {
              this.removeMetadataRule(index);
            }}
          >
            Remove
          </button>
        </div>

        ${rule.type === "date"
          ? html`
              <label class="settings-field">
                <span>Date format</span>
                <input
                  type="text"
                  .value=${rule.format}
                  placeholder="%Y-%m-%d"
                  @input=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.updateMetadataRule(index, {
                      ...rule,
                      format: target.value,
                    });
                  }}
                />
              </label>
            `
          : nothing}
        ${rule.type === "string"
          ? html`
              <label class="settings-field">
                <span>Regex</span>
                <input
                  type="text"
                  .value=${rule.regex}
                  placeholder="^(APT|MAL)_"
                  @input=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.updateMetadataRule(index, {
                      ...rule,
                      regex: target.value,
                    });
                  }}
                />
              </label>
            `
          : nothing}
      </article>
    `;
  }

  private renderEditorTab() {
    return html`
      <section class="settings-section">
        <div class="settings-section-head">
          <div>
            <h3>Formatting</h3>
            <p>
              Keep formatting rules close to what the language server already
              understands.
            </p>
          </div>
        </div>

        <div class="settings-toggle-grid">
          ${this.renderFormattingToggle(
            "alignMetadata",
            "Align metadata",
            "Vertically align metadata entries inside the meta section.",
          )}
          ${this.renderFormattingToggle(
            "alignPatterns",
            "Align patterns",
            "Keep string identifiers and assignments visually aligned.",
          )}
          ${this.renderFormattingToggle(
            "indentSectionHeaders",
            "Indent section headers",
            "Indent section labels such as meta, strings and condition.",
          )}
          ${this.renderFormattingToggle(
            "indentSectionContents",
            "Indent section contents",
            "Indent entries inside each section.",
          )}
          ${this.renderFormattingToggle(
            "newlineBeforeCurlyBrace",
            "New line before brace",
            "Move the opening brace to its own line.",
          )}
          ${this.renderFormattingToggle(
            "emptyLineBeforeSectionHeader",
            "Empty line before section",
            "Add spacing before each section header.",
          )}
          ${this.renderFormattingToggle(
            "emptyLineAfterSectionHeader",
            "Empty line after section",
            "Add spacing right after each section header.",
          )}
        </div>
      </section>

      <section class="settings-section">
        <div class="settings-section-head">
          <div>
            <h3>Validation</h3>
            <p>
              These settings affect diagnostics and editor feedback from the
              language server.
            </p>
          </div>
        </div>

        <label class="settings-field">
          <span>Rule name regex</span>
          <input
            type="text"
            .value=${this.draftSettings.editor.ruleNameValidation}
            placeholder="^APT_.+$"
            @input=${(event: Event) => {
              const target = event.target as HTMLInputElement;
              this.updateRuleNameValidation(target.value);
            }}
          />
        </label>

        <div class="settings-subsection">
          <div class="settings-list-head">
            <div>
              <h4>Metadata validation</h4>
              <p>Define required metadata fields and expected types.</p>
            </div>
            <button
              type="button"
              class="secondary-button"
              @click=${this.addMetadataRule}
            >
              Add rule
            </button>
          </div>

          ${this.draftSettings.editor.metadataValidation.length > 0
            ? html`
                ${this.metadataValidationError
                  ? html`
                      <p class="settings-validation-error" role="alert">
                        ${this.metadataValidationError}
                      </p>
                    `
                  : nothing}
                <div class="settings-list">
                  ${this.draftSettings.editor.metadataValidation.map(
                    (rule, index) => this.renderMetadataRuleRow(rule, index),
                  )}
                </div>
              `
            : html`
                <p class="settings-empty">
                  No metadata rules yet. Add one if you want the editor to
                  enforce team conventions.
                </p>
              `}
        </div>
      </section>
    `;
  }

  private renderScannerTab() {
    return html`
      <section class="settings-section">
        <div class="settings-section-head">
          <div>
            <h3>Match limits</h3>
            <p>Useful for keeping noisy rules readable in the results panel.</p>
          </div>
        </div>

        <label class="settings-field compact narrow">
          <span>Max matches per pattern</span>
          <input
            type="number"
            min="1"
            step="1"
            inputmode="numeric"
            .value=${this.maxMatchesPerPatternInput}
            placeholder="1"
            aria-invalid=${this.maxMatchesPerPatternError ? "true" : "false"}
            aria-describedby=${this.maxMatchesPerPatternError
              ? "max-matches-per-pattern-error"
              : nothing}
            @input=${(event: Event) => {
              const target = event.target as HTMLInputElement;
              this.updateMaxMatchesPerPattern(target);
            }}
          />
          ${this.maxMatchesPerPatternError
            ? html`
                <small
                  id="max-matches-per-pattern-error"
                  class="settings-validation-error"
                  role="alert"
                >
                  ${this.maxMatchesPerPatternError}
                </small>
              `
            : nothing}
        </label>
      </section>
    `;
  }

  render() {
    if (!this.open) {
      return nothing;
    }

    return html`
      <div
        class="settings-modal-shell"
        @click=${(event: MouseEvent) => {
          if (event.target === event.currentTarget) {
            this.dispatchClose();
          }
        }}
      >
        <section class="settings-modal" role="dialog" aria-modal="true">
          <header class="settings-modal-head">
            <div class="settings-modal-copy">
              <h2>Playground settings</h2>
              <p>
                Tune editor feedback and scan behavior without leaving the
                playground.
              </p>
            </div>

            <button
              type="button"
              class="settings-close"
              @click=${this.dispatchClose}
            >
              Close
            </button>
          </header>

          <div
            class="settings-tabs"
            role="tablist"
            aria-label="Settings sections"
          >
            ${this.renderTabButton("editor", "Editor")}
            ${this.renderTabButton("scanner", "Scanner")}
          </div>

          <div class="settings-modal-body playground-scroll">
            ${this.activeTab === "editor"
              ? this.renderEditorTab()
              : this.renderScannerTab()}
          </div>

          <footer class="settings-modal-foot">
            <div class="settings-foot-actions">
              <button
                type="button"
                class="ghost-button"
                @click=${this.dispatchClose}
              >
                Cancel
              </button>
              <button
                type="button"
                class="settings-primary-button"
                @click=${this.dispatchApply}
              >
                Apply changes
              </button>
            </div>
          </footer>
        </section>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "yara-settings-dialog": YaraSettingsDialog;
  }
}
