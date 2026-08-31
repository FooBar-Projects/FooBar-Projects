import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { secureResults } from './util.js';

async function main() {
    const config = {
      options: {
        file: { type: 'string', short: 'f' }
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.file ) {
      console.log('Missing file argument. Specify with -f <file>');
      process.exit(1);
    }

    // Load file to encrypt
    const fileBuffer = await readFile(values.file);

    // Generate secure results in result/ folder
    const resultDirPath = join(process.cwd(), 'result');
    await secureResults(resultDirPath, fileBuffer, values.file, process.env.RESULT_ENCRYPTION_KEY);
}

await main();
