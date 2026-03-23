async function main() {
  /**
   * TODO(@kevinmuoz): Replace this placeholder with the upstream browser
   * worker package once the "yara-x-ls" worker entrypoint and packaging
   * strategy are agreed.
   *
   * Possible future config:
   *
   * import initYaraLs, { runWorkerServer } from "@virustotal/yara-x-ls-web";
   *
   * await initYaraLs();
   * runWorkerServer();
   */
}

void main().catch((error) => {
  console.error("failed to start yara-x-ls worker", error);
});
