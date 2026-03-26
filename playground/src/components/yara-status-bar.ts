import { LitElement, html } from "lit";
import { customElement, property } from "lit/decorators.js";

import type { ServiceStatus } from "../types/service-status";
import { classMap } from "lit/directives/class-map.js";

const yaraMarkUrl = `${import.meta.env.BASE_URL}yara-mark.svg`;

function getServiceLabel(kind: "core" | "lsp", status: ServiceStatus) {
  if (kind === "core") {
    switch (status) {
      case "loading":
        return "Core loading";
      case "ready":
        return "Core ready";
      case "error":
        return "Core error";
      default:
        return "Core idle";
    }
  }

  switch (status) {
    case "loading":
      return "LSP starting";
    case "ready":
      return "LSP ready";
    case "error":
      return "LSP error";
    default:
      return "LSP idle";
  }
}

@customElement("yara-status-bar")
export class YaraStatusBar extends LitElement {
  @property({ type: String })
  coreStatus: ServiceStatus = "idle";

  @property({ type: String })
  lspStatus: ServiceStatus = "idle";

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

  private renderServiceChip(label: string, status: ServiceStatus) {
    return html`
      <span class=${classMap({ "service-chip": true, [status]: true })}>
        ${label}
      </span>
    `;
  }

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
          <div class="status-row">
            ${this.renderServiceChip(
              getServiceLabel("core", this.coreStatus),
              this.coreStatus,
            )}
            ${this.renderServiceChip(
              getServiceLabel("lsp", this.lspStatus),
              this.lspStatus,
            )}
          </div>

          <button
            class="run-button"
            @click=${this.dispatchRunRequest}
            ?disabled=${!this.canRun}
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
            <span>${this.isBusy ? "Running..." : "Run"}</span>
            <span class="run-tooltip" role="tooltip">Cmd/Ctrl + Enter</span>
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
