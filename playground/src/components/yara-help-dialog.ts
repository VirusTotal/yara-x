import { LitElement, html, nothing } from "lit";
import { customElement, property } from "lit/decorators.js";

const GETTING_STARTED_URL =
  "https://virustotal.github.io/yara-x/docs/intro/getting-started/";
const DOCUMENTATION_URL = "https://virustotal.github.io/yara-x/docs/";
const RULE_WRITING_URL =
  "https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/";
const LANGUAGE_SERVER_BLOG_URL =
  "https://virustotal.github.io/yara-x/blog/introducing-the-yara-language-server/";
const METADATA_STANDARDS_BLOG_URL =
  "https://virustotal.github.io/yara-x/blog/enforcing-yara-metadata-standards/";
const CLI_COMMANDS_URL =
  "https://virustotal.github.io/yara-x/docs/cli/commands/";
const PLAYGROUND_SOURCE_URL =
  "https://github.com/VirusTotal/yara-x/tree/main/playground";
const PLAYGROUND_ISSUES_URL = "https://github.com/VirusTotal/yara-x/issues/new";

@customElement("yara-help-dialog")
export class YaraHelpDialog extends LitElement {
  @property({ type: Boolean })
  open = false;

  @property({ type: String })
  languageServerVersion: string | null = null;

  protected createRenderRoot() {
    return this;
  }

  private dispatchClose = () => {
    this.dispatchEvent(
      new CustomEvent("help-close", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private renderShortcut(keys: string[], label: string) {
    return html`
      <span class="help-shortcut" aria-label=${label}>
        ${keys.map(
          (key, index) => html`
            ${index > 0
              ? html`
                  <span class="help-shortcut-separator" aria-hidden="true">
                    ${key === "Ctrl" ? "/" : "+"}
                  </span>
                `
              : nothing}
            <kbd>${key}</kbd>
          `,
        )}
      </span>
    `;
  }

  private renderExternalLink(href: string, label: string) {
    return html`
      <a href=${href} target="_blank" rel="noreferrer">
        <span>${label}</span>
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M7 17 17 7M9 7h8v8"
            fill="none"
            stroke="currentColor"
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="1.9"
          ></path>
        </svg>
      </a>
    `;
  }

  render() {
    if (!this.open) {
      return nothing;
    }

    return html`
      <div
        class="help-modal-shell"
        @click=${(event: MouseEvent) => {
          if (event.target === event.currentTarget) {
            this.dispatchClose();
          }
        }}
      >
        <section
          class="help-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="playground-help-title"
        >
          <header class="help-modal-head">
            <div>
              <h2 id="playground-help-title">Help</h2>
              <p>Quick guide to writing and testing rules locally.</p>
            </div>
            <button
              type="button"
              class="help-close"
              @click=${this.dispatchClose}
            >
              Close
            </button>
          </header>

          <div class="help-modal-body playground-scroll">
            <section class="help-intro">
              <p>
                If you are completely new to YARA, start by learning
                <a href=${RULE_WRITING_URL} target="_blank" rel="noreferrer"
                  >how to write YARA rules</a
                >.
              </p>
            </section>

            <section class="help-item">
              <h3>Shortcuts</h3>
              <div class="help-shortcut-list">
                <div class="help-shortcut-row">
                  <span>Format the current rule</span>
                  ${this.renderShortcut(
                    ["Cmd", "Ctrl", "S"],
                    "Command or Control plus S",
                  )}
                </div>
                <div class="help-shortcut-row">
                  <span>Trigger autocompletion</span>
                  ${this.renderShortcut(
                    ["Cmd", "Ctrl", "Space"],
                    "Command or Control plus Space",
                  )}
                </div>
                <div class="help-shortcut-row">
                  <span>Run the current rule against the sample</span>
                  ${this.renderShortcut(
                    ["Cmd", "Ctrl", "Enter"],
                    "Command or Control plus Enter",
                  )}
                </div>
              </div>
            </section>

            <section class="help-item">
              <h3>Sample modes & highlights</h3>
              <p>
                Text, Hex and File are scanned as-is.
                <strong>Base64 mode decodes your input before scanning</strong>,
                so use it for encoded binary content.
              </p>
              <p>
                YARA's <code>base64</code> string modifier is different: it
                looks for base64-encoded text in the scanned data. Use Text mode
                when testing that modifier.
              </p>
              <p>
                Text and Hex highlight matching ranges in the editor. Click a
                match range in Summary to focus it, or hover a highlight to see
                the rule, pattern, and exact byte range.
              </p>
            </section>

            <section class="help-item">
              <h3>Language server</h3>
              <p>
                Get guided feedback while you write: real-time diagnostics,
                autocomplete for keywords and modules, hover information, go to
                definition, and formatting. Read more about the
                <a
                  href=${LANGUAGE_SERVER_BLOG_URL}
                  target="_blank"
                  rel="noreferrer"
                  >YARA-X Language Server</a
                >.
              </p>
            </section>

            <section class="help-item">
              <h3>Metadata standards</h3>
              <p>
                Use Settings to define metadata standards for your team:
                required fields and types that the language server enforces as
                you write. Its metadata and formatting settings follow the same
                configuration shape as the VS Code extension. Learn about
                <a
                  href=${METADATA_STANDARDS_BLOG_URL}
                  target="_blank"
                  rel="noreferrer"
                  >metadata validation</a
                >.
              </p>
            </section>

            <section class="help-item">
              <h3>Scope & performance</h3>
              <p>
                Use the playground to write, validate, and test a rule against a
                sample without leaving your browser. Files stay on your device.
              </p>
              <p>
                YARA-X reports warnings for slow patterns as you write. For
                large or noisy samples, set Max matches per pattern in Settings
                to keep the browser responsive. For maximum performance or very
                large files, use the
                <a href=${CLI_COMMANDS_URL} target="_blank" rel="noreferrer"
                  >YARA-X CLI</a
                >.
              </p>
            </section>

            <section class="help-item help-item-last">
              <h3>Privacy & feedback</h3>
              <p>
                Rules and inline sample drafts are saved in this browser's Local
                Storage so a reload does not lose your work. Nothing is uploaded
                or shared. You can inspect the
                <a
                  href=${PLAYGROUND_SOURCE_URL}
                  target="_blank"
                  rel="noreferrer"
                  >source code</a
                >, or open a
                <a
                  href=${PLAYGROUND_ISSUES_URL}
                  target="_blank"
                  rel="noreferrer"
                  >GitHub issue</a
                >
                with feedback.
              </p>
            </section>

            <div class="help-links">
              ${this.renderExternalLink(
                GETTING_STARTED_URL,
                "Getting started guide",
              )}
              ${this.renderExternalLink(
                DOCUMENTATION_URL,
                "YARA-X documentation",
              )}
            </div>
          </div>

          <footer class="help-modal-foot">
            <span>Versions:</span>
            <div class="help-versions">
              <span>YARA-X <kbd>${__YARA_X_VERSION__}</kbd></span>
              <span>
                Language server
                <kbd>${this.languageServerVersion ?? "unavailable"}</kbd>
              </span>
            </div>
          </footer>
        </section>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "yara-help-dialog": YaraHelpDialog;
  }
}
