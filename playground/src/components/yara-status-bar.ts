import { LitElement, html } from "lit";
import { customElement, property } from "lit/decorators.js";

const yaraMarkUrl = `${import.meta.env.BASE_URL}yara-mark.svg`;

@customElement("yara-status-bar")
export class YaraStatusBar extends LitElement {
  @property({ type: Boolean })
  isBusy = false;

  @property({ type: Boolean })
  canRun = false;

  protected createRenderRoot() {
    return this;
  }

  private dispatchRunRequest = () => {
    this.dispatchEvent(
      new CustomEvent("run-request", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private dispatchSettingsRequest = () => {
    this.dispatchEvent(
      new CustomEvent("settings-request", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private dispatchHelpRequest = () => {
    this.dispatchEvent(
      new CustomEvent("help-request", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  private dispatchCancelRequest = () => {
    this.dispatchEvent(
      new CustomEvent("cancel-request", {
        bubbles: true,
        composed: true,
      }),
    );
  };

  render() {
    return html`
      <header class="topbar">
        <div class="brand">
          <div class="brand-mark">
            <img src=${yaraMarkUrl} alt="" class="brand-mark-icon" />
          </div>
          <div class="brand-copy">
            <strong>YARA-X Playground</strong>
            <span>Local-first playground</span>
          </div>
        </div>

        <div class="topbar-actions">
          <button
            type="button"
            class="toolbar-button"
            @click=${this.dispatchHelpRequest}
          >
            <span class="toolbar-button-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <circle
                  cx="12"
                  cy="12"
                  r="8.5"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.8"
                ></circle>
                <path
                  d="M9.7 9.2a2.4 2.4 0 1 1 3.7 2c-.9.6-1.4 1-1.4 2.3"
                  fill="none"
                  stroke="currentColor"
                  stroke-linecap="round"
                  stroke-width="1.8"
                ></path>
                <circle cx="12" cy="16.6" r="1" fill="currentColor"></circle>
              </svg>
            </span>
            <span>Help</span>
          </button>

          <button
            type="button"
            class="toolbar-button"
            @click=${this.dispatchSettingsRequest}
          >
            <span class="toolbar-button-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path
                  d="M19.14 12.94a7.64 7.64 0 0 0 .05-.94 7.64 7.64 0 0 0-.05-.94l2.03-1.58a.5.5 0 0 0 .12-.64l-1.92-3.32a.5.5 0 0 0-.6-.22l-2.39.96a7.16 7.16 0 0 0-1.63-.94l-.36-2.54a.5.5 0 0 0-.49-.42h-3.84a.5.5 0 0 0-.49.42l-.36 2.54c-.58.22-1.12.53-1.63.94l-2.39-.96a.5.5 0 0 0-.6.22L2.71 8.84a.5.5 0 0 0 .12.64l2.03 1.58a7.64 7.64 0 0 0-.05.94c0 .32.02.63.05.94l-2.03 1.58a.5.5 0 0 0-.12.64l1.92 3.32a.5.5 0 0 0 .6.22l2.39-.96c.5.4 1.05.72 1.63.94l.36 2.54a.5.5 0 0 0 .49.42h3.84a.5.5 0 0 0 .49-.42l.36-2.54c.58-.22 1.13-.54 1.63-.94l2.39.96a.5.5 0 0 0 .6-.22l1.92-3.32a.5.5 0 0 0-.12-.64l-2.03-1.58ZM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7Z"
                  fill="currentColor"
                ></path>
              </svg>
            </span>
            <span>Settings</span>
          </button>

          <button
            class="run-button"
            @click=${this.isBusy
              ? this.dispatchCancelRequest
              : this.dispatchRunRequest}
            ?disabled=${this.isBusy ? false : !this.canRun}
          >
            <span class="run-icon" aria-hidden="true">
              ${this.isBusy
                ? html`
                    <svg viewBox="0 0 24 24" class="spinner">
                      <circle
                        cx="12"
                        cy="12"
                        r="9"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2.4"
                        stroke-linecap="round"
                        stroke-dasharray="42 18"
                      ></circle>
                    </svg>
                  `
                : html`
                    <svg viewBox="0 0 24 24">
                      <path
                        d="M8 6.5v11l9-5.5-9-5.5Z"
                        fill="currentColor"
                      ></path>
                    </svg>
                  `}
            </span>
            <span>${this.isBusy ? "Cancel" : "Run"}</span>
            <span class="run-tooltip" role="tooltip">
              ${this.isBusy ? "Stop current scan" : "Cmd/Ctrl + Enter"}
            </span>
          </button>
        </div>
      </header>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "yara-status-bar": YaraStatusBar;
  }
}
