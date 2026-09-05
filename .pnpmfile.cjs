"use strict";

const QUICK_LAUNCH_NEXT_VERSION = "15.5.25";
const PATCHED_POSTCSS_VERSION = "8.5.28";

module.exports = {
  hooks: {
    readPackage(manifest) {
      if (manifest.name === "next" && manifest.version === QUICK_LAUNCH_NEXT_VERSION) {
        manifest.dependencies = {
          ...manifest.dependencies,
          postcss: PATCHED_POSTCSS_VERSION,
        };
      }
      return manifest;
    },
  },
};
