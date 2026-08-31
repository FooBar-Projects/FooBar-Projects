import { App } from 'octokit';
import JSZip from 'jszip';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function setCookie(name, value, path, maxAgeSeconds, sameSite, allowInsecure) {
    if (!path) {
        path = '/';
    }

    let cookieStr = encodeURIComponent(name) + '=';
    if (value !== null) {
        cookieStr += encodeURIComponent(value);
    }
    cookieStr += `; path=${path}`;
    if (maxAgeSeconds) {
        cookieStr += `; max-age=${maxAgeSeconds}`;
    }
    if (sameSite) {
        cookieStr += `; SameSite=${sameSite}`;
    }
    if (!allowInsecure) {
        cookieStr += `; Secure`;
    }
    document.cookie = cookieStr;
}

export function getCookie(name) {
    const parts = `; ${document.cookie}`.split(`; ${encodeURIComponent(name)}=`);
    if (parts.length === 2) {
        return decodeURIComponent(parts.pop().split(';').shift());
    }
    return null;
}

export function generateSecureString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    const randomValues = new Uint8Array(length);
    window.crypto.getRandomValues(randomValues);
    return [...randomValues].map(val => chars[val % chars.length]).join('');
}

export async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return new Uint8Array(hashBuffer);
}

export async function generateRSAKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    return keyPair
}

async function generateAESKey() {
  const key = await window.crypto.subtle.generateKey(
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

export async function getClassroomRSAPublicKey(organizationName, userOctokit) {
    // Get classroomRSAPublicKeyBase64 from backend-workflows repo variable
    const getClassroomRSAPublicKeyResponse = await userOctokit.request(`GET /repos/${organizationName}/backend-workflows/actions/variables/CLASSROOM_RSA_PUBLIC_KEY`, {
        owner: organizationName,
        repo: 'backend-workflows',
        name: 'CLASSROOM_RSA_PUBLIC_KEY',
        headers: {
            'X-GitHub-Api-Version': '2026-03-10'
        }
    });
    const classroomRSAPublicKeyBase64 = getClassroomRSAPublicKeyResponse.data['value'];
    const classroomRSAPublicKeyBuffer = Uint8Array.fromBase64(classroomRSAPublicKeyBase64);
    const classroomRSAPublicKey = await window.crypto.subtle.importKey(
      'spki',
      classroomRSAPublicKeyBuffer,
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
        hash: "SHA-256",
      },
      true,
      ['encrypt']
    );
    return classroomRSAPublicKey;
}

export async function dispatchWorkflowViaIssue(organizationName, workflowEventName, workflowInputs, statusUpdateCallback, pollDelay, userOctokit, classroomRSAPublicKey) {
    if (!pollDelay) {
        pollDelay = 2000;
    }

    if (!workflowInputs) {
        workflowInputs = {};
    }

    // Embed workflowEventName in workflowInputs['eventName']
    workflowInputs['eventName'] = workflowEventName

    // Generate RSA key pair. The backend will use the public key to encrypt
    // workflow results. This function will then use the private key to
    // decrypt them.
    const resultRSAKeyPair = await generateRSAKeys();

    // Export public key to SPKI format, then convert to Base64 and embed in
    // workflow inputs
    const exportedResponsePublicKey = await window.crypto.subtle.exportKey("spki", resultRSAKeyPair.publicKey);
    const resultEncryptionKeyBase64 =
        new Uint8Array(exportedResponsePublicKey)
        .toBase64({ omitPadding: true });

    workflowInputs['resultEncryptionKey'] = resultEncryptionKeyBase64;
    
    // Embed random verifier string in workflow inputs for preventing replay
    // attacks / backend-workflow spoofing (perhaps a bit redundant since
    // resultEncryptionKey is generated per-request)
    const verifier = generateSecureString(32);
    workflowInputs['verifier'] = verifier;

    // Convert workflow inputs to buffer for encryption
    const workflowInputsJson = JSON.stringify(workflowInputs);
    const workflowInputsBuffer = new TextEncoder().encode(workflowInputsJson);

    // Generate AES key and encrypt workflowInputsBuffer
    const aesKey = await generateAESKey();
    const encryptWorkflowInputsResult = await encryptAES(workflowInputsBuffer, aesKey);
    const workflowInputsCiphertext = encryptWorkflowInputsResult.ciphertext;
    const iv = encryptWorkflowInputsResult.iv;
    const ivBase64 = iv.toBase64();
    const workflowInputsCiphertextBase64 = workflowInputsCiphertext.toBase64();

    // Encrypt AES key using classroom's public RSA key and encode in base64
    const aesKeyBuffer = new Uint8Array(await window.crypto.subtle.exportKey('raw', aesKey));
    const encryptedAESKey = await encryptRSA(aesKeyBuffer, classroomRSAPublicKey);
    const encryptedAESKeyBase64 = encryptedAESKey.toBase64();

    // Package into JSON, stringify, and base64-encode to serve as issue
    // body
    const issueBody = JSON.stringify({
        aesKey: encryptedAESKeyBase64,
        iv: ivBase64,
        inputs: workflowInputsCiphertextBase64
    });
    const issueBodyBase64 = new TextEncoder().encode(issueBody).toBase64();

    // Post issue
    let postIssueResponseData;
    try {
        const postIssueResponse = await userOctokit.request(`POST /repos/${organizationName}/backend-workflows/issues`, {
            owner: organizationName,
            repo: 'backend-workflows',
            title: `[securely-dispatch-workflow]`,
            body: issueBodyBase64,
            headers: {
                'X-GitHub-Api-Version': '2026-03-10'
            }
        });
        postIssueResponseData = postIssueResponse.data
    } catch (error) {
        console.log(error);
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Failed to post workflow-dispatch issue'
            });
        }
        return;
    }

    const issueNumber = postIssueResponseData['number'];

    if (statusUpdateCallback) {
        statusUpdateCallback({
            status: 'polling'
        });
    }

    // Poll issue for response comment with workflow run ID
    let issuePollResponseData;
    let runId = null;
    do {
        await sleep(pollDelay);

        try {
            const issuePollResponse = await userOctokit.request(`GET /repos/${organizationName}/backend-workflows/issues/${issueNumber}/comments`, {
                owner: organizationName,
                repo: 'backend-workflows',
                issue_number: issueNumber,
                headers: {
                    'X-GitHub-Api-Version': '2026-03-10',
                    'If-None-Match': ''
                }
            });
            issuePollResponseData = issuePollResponse.data
        } catch (error) {
            console.log(error);
            if (statusUpdateCallback) {
                statusUpdateCallback({
                    status: 'error',
                    message: 'Failed to poll issue response'
                });
            }
            return;
        }
        
        for (const comment of issuePollResponseData) {
            const utf8Decoder = new TextDecoder('utf-8');
            const commentResponseBodyJson = utf8Decoder.decode(Uint8Array.fromBase64(comment['body']));
            const commentResponseBody = JSON.parse(commentResponseBodyJson);

            const encryptedCommentResponseAESKeyBuffer = Uint8Array.fromBase64(commentResponseBody['aesKey']);
            const commentResponseIV = Uint8Array.fromBase64(commentResponseBody['iv']);
            const encryptedCommentPayload = Uint8Array.fromBase64(commentResponseBody['payload']);

            // Decrypt encryptedCommentResponseAESKeyBuffer with resultRSAKeyPair.privateKey
            const commentResponseAESKeyBuffer = await decryptRSA(encryptedCommentResponseAESKeyBuffer, resultRSAKeyPair.privateKey);
            const commentResponseAESKey = await window.crypto.subtle.importKey(
                'raw',
                commentResponseAESKeyBuffer,
                {
                    name: 'AES-GCM',
                    length: 256,
                },
                true,
                ['encrypt', 'decrypt']
            );

            // Decrypt encryptedCommentPayload with commentResponseAESKey
            const commentPayloadBuffer = await decryptAES(encryptedCommentPayload, commentResponseAESKey, commentResponseIV);
            const commentPayloadJson = (new TextDecoder('utf-8')).decode(commentPayloadBuffer);
            const commentPayload = JSON.parse(commentPayloadJson);

            // Verify random state string to prevent replay attacks
            if (commentPayload['verifier'] != verifier) {
                continue;
            }

            // Store run ID and break loop
            runId = commentPayload['runId'];
            break;
        }
    } while(runId === null);

    // Poll workflow run until done
    let runStatus = null;
    let runConclusion = null;
    do {
        await sleep(pollDelay);
        
        try {
            const pollResponse = await userOctokit.request(`GET /repos/${organizationName}/backend-workflows/actions/runs/${runId}`, {
                owner: organizationName,
                repo: 'backend-workflows',
                run_id: runId,
                headers: {
                    'X-GitHub-Api-Version': '2026-03-10',
                    'If-None-Match': ''
                }
            })

            runStatus = pollResponse.data['status'];
            runConclusion = pollResponse.data['conclusion'];
        } catch (error) {
            console.log(error);
            if (statusUpdateCallback) {
                statusUpdateCallback({
                    status: 'error',
                    message: 'Failed to poll workflow run status'
                });
            }
            return;
        }
    } while (runConclusion === null);

    if (runConclusion !== 'success') {
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: `Workflow run failed. Got conclusion "${runConclusion}" and status "${runStatus}"`
            });
        }
        return;
    }
    
    if (statusUpdateCallback) {
        statusUpdateCallback({
            status: 'retrieving-results'
        });
    }

    // Retrieve metadata of all workflow run artifacts
    let artifactMetadataResponseData;
    try {
        const artifactMetadataResponse = await userOctokit.request(`GET /repos/${organizationName}/backend-workflows/actions/runs/${runId}/artifacts`, {
            owner: organizationName,
            repo: 'backend-workflows',
            run_id: runId,
            headers: {
                'X-GitHub-Api-Version': '2026-03-10',
                'If-None-Match': ''
            }
        });
        artifactMetadataResponseData = artifactMetadataResponse.data;
    } catch (error) {
        console.log(error);
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Failed to retrieve workflow run artifacts'
            });
        }
        return;
    }

    // Extract result artifact metadata
    const resultArtifactsMetadata = artifactMetadataResponseData['artifacts'].filter(x => x.name == 'result');
    if (resultArtifactsMetadata.length == 0) {
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'No result artifact found'
            });
        }
        return;
    }
    
    // Download the result artifact archive
    let resultArtifactResponseData;
    try {
        const resultArtifactResponse = await userOctokit.rest.actions.downloadArtifact({
            owner: organizationName,
            repo: 'backend-workflows',
            artifact_id: resultArtifactsMetadata[0].id,
            archive_format: 'zip',
        });
        resultArtifactResponseData = resultArtifactResponse.data;
    } catch (error) {
        console.log(error);
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Failed to retrieve archive for result artifact'
            });
        }
        return;
    }

    // Extract archive contents with JSZip
    const secureZip = await JSZip.loadAsync(resultArtifactResponseData);
    
    if (!Object.hasOwn(secureZip.files, 'aes-key.enc')) {
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Secure artifact result archive missing aes-key.enc'
            });
        }
        return;
    }

    if (!Object.hasOwn(secureZip.files, 'iv.bin')) {
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Secure artifact result archive missing iv.bin'
            });
        }
        return;
    }

    if (!Object.hasOwn(secureZip.files, 'result.zip.enc')) {
        if (statusUpdateCallback) {
            statusUpdateCallback({
                status: 'error',
                message: 'Secure artifact result archive missing result.zip.enc'
            });
        }
        return;
    }

    // Decrypt contained AES key using result RSA private key
    const encryptedResponseAESKey = await secureZip.files['aes-key.enc'].async('uint8array');
    const responseAESKeyBuffer = await decryptRSA(encryptedResponseAESKey, resultRSAKeyPair.privateKey);
    const responseAESKey = await window.crypto.subtle.importKey(
        'raw',
        responseAESKeyBuffer,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );
    
    // Use AES key and iv to decrypt result zip
    const responseIV = await secureZip.files['iv.bin'].async('uint8array');

    const resultCiphertext = await secureZip.files['result.zip.enc'].async('uint8array');
    const resultPlaintext = await decryptAES(resultCiphertext, responseAESKey, responseIV);

    // Extract contents of result.zip using JSZip and return it
    const zip = await JSZip.loadAsync(resultPlaintext);

    if (statusUpdateCallback) {
        statusUpdateCallback({
            status: 'done'
        });
    }

    return zip;
}

export async function getAccessToken() {
    // Request access token using HTTP-only session token cookie
    const getAccessTokenResponse = await fetch(
        '/access-token',
        {
            method: 'POST'
        }
    );
    if (getAccessTokenResponse.status == 401) {
        // Unauthorized. Refresh failed. Auth flow will need to be redone.
        return {
            accessToken: null,
            status: 'bad-auth'
        };
    } else if (!getAccessTokenResponse.ok) {
        // Unexpected error
        return {
            accessToken: null,
            status: 'error'
        };
    }

    // Access token retrieved. Return it.
    const getAccessTokenResponseJson = await getAccessTokenResponse.json();

    return {
        accessToken: getAccessTokenResponseJson['access_token'],
        status: 'success'
    };
}
