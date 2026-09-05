import { webcrypto } from 'crypto';
import { writeFile } from 'node:fs/promises';
import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { encryptAES } from './util.js'

async function main() {
    const config = {
      options: {
        token: { type: 'string', short: 't' },
        expiration: { type: 'string', short: 'e' },
        file: { type: 'string', short: 'f' }
      },
      strict: true
    };

    const { values, _ } = parseArgs(config);

    if (!values.token) {
      console.log('Missing token argument. Specify with -t <token>');
      process.exit(1);
    }
    if (!values.expiration) {
      console.log('Missing expiration argument. Specify with -e <YYYY-MM-DDThh:mm:ssZ>');
      process.exit(1);
    }
    if (!values.file) {
      console.log('Missing file argument. Specify with -f <file>');
      process.exit(1);
    }

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

    const iatPayload = {
        'token': values.token,
        'expiration': values.expiration
    };
    const iatPayloadJson = JSON.stringify(iatPayload);
    const iatPayloadBuffer = (new TextEncoder('utf-8')).encode(iatPayloadJson);

    const encryptionResult = await encryptAES(iatPayloadBuffer, cacheAESKey);
    const encryptedIatBuffer = encryptionResult['ciphertext'];
    const iv = encryptionResult['iv'];

    const encryptedIatStructure = {
        'encryptedIat': Buffer.from(encryptedIatBuffer).toString('base64'),
        'iv': Buffer.from(iv).toString('base64')
    };
    const encryptedIatStructureJson = JSON.stringify(encryptedIatStructure);

    const parentDir = path.dirname(values.file);
    await fs.mkdir(parentDir, { recursive: true });
    await writeFile(values.file, encryptedIatStructureJson, 'utf8');
}

await main();
