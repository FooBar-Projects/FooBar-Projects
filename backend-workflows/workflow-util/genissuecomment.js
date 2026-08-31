import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { genIssueComment } from './util.js';

async function main() {
    const config = {
      options: {
        runId: { type: 'string', short: 'r' },
        verifier: { type: 'string', short: 'v' },
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.runId ) {
      console.log('Missing run ID argument. Specify with -r <run ID>');
      process.exit(1);
    }
    if (!values.verifier) {
      console.log('Missing verifier argument. Specify with -v <verifier>');
      process.exit(1);
    }

    // Decode issue body and decrypt
    const issueComment = await genIssueComment(values.runId, values.verifier, process.env.RESULT_ENCRYPTION_KEY);

    // Print to standard output, to be captured by shell
    console.log(issueComment);
}

await main();
