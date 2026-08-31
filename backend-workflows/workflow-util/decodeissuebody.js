import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { decodeIssueBody } from './util.js';

async function main() {
    const config = {
      options: {
        data: { type: 'string', short: 'd' }
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.data ) {
      console.log('Missing data argument. Specify with -d <data>');
      process.exit(1);
    }

    // Decode issue body and decrypt
    const workflow_inputs_json = await decodeIssueBody(values.data, process.env.CLASSROOM_RSA_PRIVATE_KEY);

    // Print to standard output, to be captured by shell
    console.log(workflow_inputs_json);
}

await main();
