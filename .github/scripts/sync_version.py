import json
import toml

# Paths to the files
cargo_toml_path = 'Cargo.toml'
vsc_ext_package = 'ls/editors/code/package.json'
npm_package = 'js-wasm/package.json'

# Read the version from Cargo.toml
with open(cargo_toml_path, 'r') as f:
    cargo_toml = toml.load(f)

version = cargo_toml['workspace']['package']['version']

with open(vsc_ext_package, 'r') as f:
    vsc_ext_package_json = json.load(f)
    vsc_ext_package_json['version'] = version

with open(vsc_ext_package, 'w') as f:
    json.dump(vsc_ext_package_json, f, indent=2)

print(f"Updated version in {vsc_ext_package} to {version}")

with open(npm_package, 'r') as f:
    npm_package_json = json.load(f)
    npm_package_json['version'] = version

with open(npm_package, 'w') as f:
    json.dump(npm_package_json, f, indent=2)

print(f"Updated version in {npm_package} to {version}")