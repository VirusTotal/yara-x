/* tslint:disable */
/* eslint-disable */

/**
 * Starts the language server inside a browser dedicated worker.
 *
 * Messages received through `postMessage` are adapted to the LSP
 * `Content-Length` framing expected by [`crate::serve`]. Outgoing LSP
 * messages are parsed and posted back as JSON values when possible, or
 * as raw strings otherwise.
 */
export function runWorkerServer(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly runWorkerServer: () => [number, number];
    readonly wasm_bindgen__closure__destroy__haec1d41666d082cd: (a: number, b: number) => void;
    readonly wasm_bindgen__closure__destroy__h336cf33eb97e424f: (a: number, b: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__hd7b2ac8475ad8621: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__hd2325b3c85219782: (a: number, b: number, c: any) => void;
    readonly __wbindgen_malloc_command_export: (a: number, b: number) => number;
    readonly __wbindgen_realloc_command_export: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free_command_export: (a: number, b: number, c: number) => void;
    readonly __wbindgen_exn_store_command_export: (a: number) => void;
    readonly __externref_table_alloc_command_export: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc_command_export: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
