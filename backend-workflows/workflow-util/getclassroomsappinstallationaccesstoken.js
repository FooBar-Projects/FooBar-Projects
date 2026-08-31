import { execFile } from 'node:child_process';

import { getClassroomsAppInstallationAccessToken as getInstallationAccessToken } from './util.js'

async function main() {
    const installationAccessToken = await getInstallationAccessToken();
    console.log(installationAccessToken);
}

await main();
