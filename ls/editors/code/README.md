# Run Extension Development Host

1. Compile the CLI tool and set `CARGO_BIN_EXE_yr` environment variable with absolute path to the binary, for example:
    ```sh
    $ cargo build --release
    $ export CARGO_BIN_EXE_yr=/path/to/yr
    ```

2. Move to the `yara-x/ls/editors/code`, install dependecies and compile the extension:
    ```sh
    $ npm i
    $ npm run compile
    ```

3. You can start extension development host with `code` CLI tool with specified absolute path to `yara-x/ls/editors/code` folder for `--extensionDevelopmentPath`:
    ```sh
    $ code --extensionDevelopmentPath=/path/to/yara-x/ls/editors/code
    ```