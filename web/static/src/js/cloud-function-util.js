export async function getOrganizationCloudFunctionEndpoint(organizationName, userOctokit) {
    // Get classroomRSAPublicKeyBase64 from backend-workflows repo
    const getBackendConfigJsonResponse = await userOctokit.request(
        `GET /repos/${organizationName}/backend-workflows/contents/backend.json`,
        {
            owner: organizationName,
            repo: 'backend-workflows',
            path: 'backend.json',
            headers: {
                'X-GitHub-Api-Version': '2026-03-10'
            }
        }
    );
    // /contents endpoint b64-encodes contents with newlines, which must
    // be removed
    const backendConfigJsonBase64 = getBackendConfigJsonResponse.data['content'].replace(/\n/g, '');
    
    // Base64-decode
    const utf8Decoder = new TextDecoder('utf-8');
    const backendConfigJson = utf8Decoder.decode(Uint8Array.fromBase64(backendConfigJsonBase64));

    // Parse JSON
    const backendConfig = JSON.parse(backendConfigJson);

    // Get cloud function endpoint
    if (Object.hasOwn(backendConfig, 'gcloud') &&
            Object.hasOwn(backendConfig['gcloud'], 'endpoint')) {
        return backendConfig['gcloud']['endpoint'];
    }

    // Failed to find endpoint in config
    return null;
}

export async function acceptAssignmentViaCloudFunction(acceptAssignmentRequestInputs, cloudFunctionEndpoint) {
    const acceptAssignmentResponse = await fetch(
        cloudFunctionEndpoint,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(acceptAssignmentRequestInputs)
        }
    );

    const contentType = acceptAssignmentResponse.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
        const responseJson = await acceptAssignmentResponse.json();
        return {
            jsonBody: responseJson,
            errorMessage: null
        };
    } else {
        return {
            jsonBody: null,
            errorMessage: await acceptAssignmentResponse.text()
        };
    }
}
