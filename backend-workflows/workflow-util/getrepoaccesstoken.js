import { execFile } from 'node:child_process';
import { parseArgs } from 'node:util';

import { getRepoAccessToken } from './util.js'

async function main() {
    const config = {
      options: {
        repository: { type: 'string', short: 'r' },
        permissions: { type: 'string', short: 'p' },
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.repository ) {
      console.log('Missing repository argument. Specify with -r <repository_name>');
      process.exit(1);
    }
    let permissions
    if (values.permissions) {
        permissions = JSON.parse(values.permissions)
    }
    const installationAccessToken = await getRepoAccessToken(
        values.repository,
        permissions
    );
    console.log(installationAccessToken);
}

await main();
