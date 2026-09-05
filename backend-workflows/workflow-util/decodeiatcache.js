import { webcrypto } from 'crypto';
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { decryptAES } from './util.js'

async function main() {
    const config = {
      options: {
        file: { type: 'string', short: 'f' }
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.file) {
      console.log('Missing file argument. Specify with -f <file>');
      process.exit(1);
    }

    const encryptedIatStructureJson = await readFile(values.file, 'utf8');
    const encryptedIatStructure = JSON.parse(encryptedIatStructureJson);
    const iv = Buffer.from(encryptedIatStructure['iv'], 'base64');
    const encryptedIatBuffer = Buffer.from(encryptedIatStructure['encryptedIat'], 'base64');

    const cacheAESKeyBuffer = Buffer.from(process.env.CACHE_AES_KEY, 'base64');
    const cacheAESKey = await webcrypto.subtle.importKey(
        'raw',
        cacheAESKeyBuffer,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );

    const iatPayloadBuffer = await decryptAES(encryptedIatBuffer, cacheAESKey, iv);
    const iatPayloadJson = (new TextDecoder('utf-8')).decode(iatPayloadBuffer);
    const iatPayload = JSON.parse(iatPayloadJson);

    const iatExpiration = new Date(iatPayload['expiration']);
    const now = new Date();
    if (now.getTime() >= iatExpiration.getTime()) {
        // Expired. Print nothing to standard output.
        return;
    }

    // Not expired. Print token to standard output.
    console.log(iatPayload['token']);
}

await main();
