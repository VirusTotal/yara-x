# YARA Language Server

This repository contains the official implementation of the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
(LSP) for the YARA language. It contains both an LSP server written in Rust, and an LSP client for Visual Studio Code written
in TypeScript (see: editors/code).


# Instructions for developers

1. Compile the language server (`yr-ls`) and move the binary to `ls/editors/code/dist`, for example:
    ```sh
    $ cargo build --bin yr-ls --release && mv target/release/yr-ls ls/editors/code/dist
    ```

2. Move to the `ls/editors/code`, install dependencies and compile the extension:
    ```sh
    $ npm i
    $ npm run compile
    ```

3. You can start extension development host with `code` CLI tool with specified absolute path to `yara-x/ls/editors/code` folder for `--extensionDevelopmentPath`:
    ```sh
    $ code --extensionDevelopmentPath=/path/to/yara-x/ls/editors/code
    ```