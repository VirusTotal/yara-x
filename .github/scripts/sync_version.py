import json
import toml

# Paths to the files
cargo_toml_path = 'ls/Cargo.toml'
package_json_path = 'ls/editors/code/package.json'

# Read the version from Cargo.toml
with open(cargo_toml_path, 'r') as f:
    cargo_toml = toml.load(f)
version = cargo_toml['package']['version']

# Read package.json
with open(package_json_path, 'r') as f:
    package_json = json.load(f)

# Update the version
package_json['version'] = version

# Write the updated package.json
with open(package_json_path, 'w') as f:
    json.dump(package_json, f, indent=2)

print(f"Updated version in {package_json_path} to {version}")
