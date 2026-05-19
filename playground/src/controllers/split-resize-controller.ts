import type { ReactiveController, ReactiveControllerHost } from "lit";

type SplitAxis = "x" | "y";

type SplitResizeConfig = {
  getElement: () => HTMLElement | null;
  getAxis: () => SplitAxis;
  min: number;
  max: number;
  onChange: (value: number) => void;
};

export class SplitResizeController implements ReactiveController {
  private cleanup?: () => void;
  private readonly config: SplitResizeConfig;

  constructor(host: ReactiveControllerHost, config: SplitResizeConfig) {
    this.config = config;
    host.addController(this);
  }

  hostDisconnected() {
    this.stop();
  }

  readonly start = (event: PointerEvent) => {
    event.preventDefault();
    this.updateFromPointer(event);
    document.body.style.userSelect = "none";
    document.body.style.cursor =
      this.config.getAxis() === "y" ? "row-resize" : "col-resize";

    const onMove = (moveEvent: PointerEvent) => {
      this.updateFromPointer(moveEvent);
    };

    const onUp = () => {
      this.stop();
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    this.cleanup = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      this.cleanup = undefined;
    };
  };

  private updateFromPointer(event: PointerEvent) {
    const element = this.config.getElement();

    if (!element) return;

    const rect = element.getBoundingClientRect();
    const size = this.config.getAxis() === "y" ? rect.height : rect.width;

    if (size <= 0) return;

    const offset =
      this.config.getAxis() === "y"
        ? event.clientY - rect.top
        : event.clientX - rect.left;
    const next = (offset / size) * 100;

    this.config.onChange(
      Math.min(this.config.max, Math.max(this.config.min, next)),
    );
  }

  private stop() {
    this.cleanup?.();
  }
}
