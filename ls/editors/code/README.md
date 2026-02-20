# YARA-X for Visual Studio Code

This extension brings support for the [YARA](https://virustotal.github.io/yara-x/)
language to Visual Studio Code, powered by the official YARA-X Language Server. It
provides a rich set of features to enhance your YARA rule development workflow.

## Features

*   **Syntax Highlighting**: Advanced, token-based syntax highlighting for YARA rules.
*   **Completions**: Autocompletion for modules, rule identifiers, and more.
*   **Diagnostics**: Real-time error checking and diagnostics to help you write valid rules.
*   **Hover Information**: Hover over any identifier to see its type, documentation, and other information.
*   **Go to Definition**: Navigate to the definition of a rule or pattern.
*   **Find References**: Find all references to a specific rule or identifier.
*   **Code Formatting**: Format your YARA rules according to the standard style.
*   **Rename**: Safely rename rule identifiers and variables across your files.
*   **Document outline**: See a symbol tree of your document for quick navigation.
*   **Code Actions**: Quick fixes and refactoring suggestions.

An image is worth a thousand words...

<p align="center">
<img src="images/demo.gif" width="95%" alt="Demo">
<br/>
<em>(Demo)</em>
</p>

<p align="center">
<img src="images/outline.gif" width="95%" alt="Navigation demo">
<br/>
<em>(Navigation)</em>
</p>

<p align="center">
<img src="images/quickfix.gif" width="95%" alt="Quick fix demo">
<br/>
<em>(Quick fix)</em>
</p>

## Quick Start

1.  Install the extension from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=VirusTotal.yara-x-ls).
2.  Open a `.yara` or `.yar` file.
3.  The extension will automatically activate, and you can start using the features.

## Configuration

This extension provides configurations through VSCode's configuration settings. All configurations are under `YARA.*`.

```json
"YARA.ruleNameValidation": "^APT_.+$",
"YARA.metadataValidation": [
  {
    "identifier": "author",
    "required": true,
    "type": "string"
  },
  {
    "identifier": "version",
    "required": true,
    "type": "integer"
  }
]
```

### `YARA.ruleNameValidation`

Type: `string`
Default: `""` (no validation)

A regular expression that rule names must conform to. If a rule name does not match this pattern, a warning will be 
generated.

### `YARA.metadataValidation`

Type: `array` of objects
Default: `[]` (no validation)

An array of objects, where each object defines validation rules for a specific metadata field. Each object can have
the following properties:

*   `identifier` (string, required): The name of the metadata field to validate (e.g., `author`, `version`).
*   `required` (boolean, optional): If `true`, the metadata field must be present in the rule. Defaults to `false`.
*   `type` (string, optional): Specifies the expected type of the metadata value. Valid values are
    `"string"`, `"integer"`, `"float"`, and `"bool"`. If the value does not match the specified type, a warning will
    be generated.

For accessing these settings go to the Settings

<p align="center">
<img src="images/settings.gif" width="95%" alt="Demo">
<br/>
<em>(Demo)</em>
</p>
