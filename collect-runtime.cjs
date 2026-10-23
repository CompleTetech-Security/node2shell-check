#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
// Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
'use strict';

// This collector intentionally never decompresses data, loads an application,
// reads environment variables, or opens a network connection. Run it with the
// same trusted Node.js binary that runs the application being inventoried.
const versions = process.versions || {};
if (!versions.node || versions.bun || versions.deno || versions.electron) {
  process.stderr.write('collect-runtime.cjs requires a standalone Node.js runtime; other runtimes require their own vendor assessment.\n');
  process.exitCode = 2;
} else {
  try {
    const zlib = require('node:zlib');
    const constant = zlib.constants && zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
    const metadata = {
      schema_version: 1,
      label: 'local-node',
      runtime: 'node',
      node_version: versions.node,
      build_source: 'unknown',
      brotli_version: versions.brotli || '',
      brotli_decompress_available:
        typeof zlib.brotliDecompress === 'function' &&
        typeof zlib.brotliDecompressSync === 'function' &&
        typeof zlib.createBrotliDecompress === 'function',
      brotli_block_switch_error: typeof constant === 'number' ? constant : null,
      platform: process.platform,
      architecture: process.arch,
    };
    process.stdout.write(JSON.stringify(metadata, null, 2) + '\n');
  } catch (_) {
    process.stderr.write('Unable to read built-in Node.js Brotli metadata. No application code or decompression was attempted.\n');
    process.exitCode = 2;
  }
}
