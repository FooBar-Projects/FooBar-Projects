import { webcrypto } from 'crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { App } from 'octokit';
import { createAppAuth } from '@octokit/auth-app';

export async function getAssignmentCreationAppInstallation() {
    const assignmentCreationApp = new App({
        appId: process.env.ASSIGNMENT_CREATION_APP_ID,
        privateKey: process.env.ASSIGNMENT_CREATION_APP_PRIVATE_KEY,
    });

    return await assignmentCreationApp.getInstallationOctokit(Number(process.env.ASSIGNMENT_CREATION_APP_INSTALLATION_ID));
}

export async function getAssignmentCreationAppInstallationAccessToken() {
    const auth = createAppAuth({
      appId: process.env.ASSIGNMENT_CREATION_APP_ID,
      privateKey: process.env.ASSIGNMENT_CREATION_APP_PRIVATE_KEY,
    });

    // Retrieve the raw installation access token
    const installationAuth = await auth({
      type: "installation",
      installationId: Number(process.env.ASSIGNMENT_CREATION_APP_INSTALLATION_ID),
    });

    return installationAuth.token;
}

export async function getClassroomsAppInstallationAccessToken() {
    const auth = createAppAuth({
      appId: process.env.CLASSROOMS_APP_ID,
      privateKey: process.env.CLASSROOMS_APP_PRIVATE_KEY,
    });

    // Retrieve the raw installation access token
    const installationAuth = await auth({
      type: "installation",
      installationId: Number(process.env.CLASSROOMS_APP_INSTALLATION_ID),
    });

    return installationAuth.token;
}

async function generateAESKey() {
  const key = await webcrypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  return key;
}

async function encryptAES(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    plaintext
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv: iv
  };
}

async function encryptRSA(plaintext, key) {
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    key,
    plaintext
  );

  return new Uint8Array(ciphertext);
}

export async function decryptAES(ciphertext, key, iv) {
  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext
  );

  return new Uint8Array(plaintextBuffer);
}

export async function decryptRSA(ciphertext, key) {
  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    key,
    ciphertext
  );

  return new Uint8Array(plaintextBuffer);
}

export async function secureResults(contentDir, contents, contentsBaseFilename, rsaPublicKeyBase64) {
    // Generate AES key
    const aesKey = await generateAESKey();

    // Encrypt contents with AES key
    const encryptContentsResult = await encryptAES(contents, aesKey);
    const ciphertext = encryptContentsResult.ciphertext;
    const iv = encryptContentsResult.iv;

    // Encrypt AES key with specified RSA public key
    const rsaPublicKeyBuffer = Buffer.from(rsaPublicKeyBase64, 'base64');
    const rsaPublicKey = await webcrypto.subtle.importKey(
      'spki',
      rsaPublicKeyBuffer,
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
        hash: "SHA-256",
      },
      true,
      ['encrypt']
    );
    const aesKeyBuffer = new Uint8Array(await webcrypto.subtle.exportKey('raw', aesKey));
    const encryptedAESKey = await encryptRSA(aesKeyBuffer, rsaPublicKey);

    // Write aes key, iv, and ciphertext to files
    mkdir(contentDir, { recursive: true });
    await writeFile(join(contentDir, 'aes-key.enc'), encryptedAESKey);
    await writeFile(join(contentDir, 'iv.bin'), iv);
    await writeFile(join(contentDir, `${contentsBaseFilename}.enc`), ciphertext);
}

export async function decodeIssueBody(issueBodyBase64, classroomRSAPrivateKeyBase64) {
    // Decode issue body into JSON and parse
    const issueBodyJson = Buffer.from(issueBodyBase64, 'base64').toString('utf-8');
    const issueBody = JSON.parse(issueBodyJson);
    
    // Extract + decode aes key, iv, and inputs
    const encryptedClientAESKeyBuffer = Buffer.from(issueBody.aesKey, 'base64');
    const clientIV = Buffer.from(issueBody.iv, 'base64');
    const encryptedInputsBuffer = Buffer.from(issueBody.inputs, 'base64');

    // Import CLASSROOM_RSA_PRIVATE_KEY
    const classroomRSAPrivateKeyBuffer = Buffer.from(classroomRSAPrivateKeyBase64, 'base64');
    const classroomRSAPrivateKey = await webcrypto.subtle.importKey(
      'pkcs8',
      classroomRSAPrivateKeyBuffer,
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
        hash: "SHA-256",
      },
      true,
      ['decrypt']
    );

    // Decrypt encryptedClientAESKeyBuffer using classroomRSAPrivateKey
    const clientAESKeyBuffer = await decryptRSA(encryptedClientAESKeyBuffer, classroomRSAPrivateKey);
    const clientAESKey = await webcrypto.subtle.importKey(
        'raw',
        clientAESKeyBuffer,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );

    // Decrypt encryptedInputsBuffer with clientAESKey and clientIV
    const inputsBuffer = await decryptAES(encryptedInputsBuffer, clientAESKey, clientIV);
    const inputsJson = (new TextDecoder('utf-8')).decode(inputsBuffer);

    return inputsJson;
}

export async function genIssueComment(runId, verifier, rsaPublicKeyBase64) {
    // Generate payload
    const payloadJson = JSON.stringify({
        'runId': runId,
        'verifier': verifier
    });
    const payloadBuffer = Buffer.from(payloadJson, 'utf-8');

    // Generate AES key and encrypt payloadBuffer
    const aesKey = await generateAESKey();
    const encryptPayloadResult = await encryptAES(payloadBuffer, aesKey);
    const encryptedPayload = encryptPayloadResult.ciphertext;
    const iv = encryptPayloadResult.iv;

    // Encrypt AES key with result encryption key
    const rsaPublicKeyBuffer = Buffer.from(rsaPublicKeyBase64, 'base64');
    const rsaPublicKey = await webcrypto.subtle.importKey(
      'spki',
      rsaPublicKeyBuffer,
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
        hash: "SHA-256",
      },
      true,
      ['encrypt']
    );
    const aesKeyBuffer = new Uint8Array(await webcrypto.subtle.exportKey('raw', aesKey));
    const encryptedAESKey = await encryptRSA(aesKeyBuffer, rsaPublicKey);
    
    // Base64-encode encrypted AES key, iv, and encrypted payload
    const encryptedAESKeyBase64 = Buffer.from(encryptedAESKey).toString('base64');
    const ivBase64 = Buffer.from(iv).toString('base64');
    const encryptedPayloadBase64 = Buffer.from(encryptedPayload).toString('base64');

    // Package as JSON and base64-encode
    const issueCommentJson = JSON.stringify({
        'aesKey': encryptedAESKeyBase64,
        'iv': ivBase64,
        'payload': encryptedPayloadBase64
    });
    const issueComment = Buffer.from(issueCommentJson, 'utf-8').toString('base64')

    // Return
    return issueComment
}
