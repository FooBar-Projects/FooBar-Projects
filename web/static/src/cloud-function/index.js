import { Octokit } from 'octokit';

import * as util from '@/js/util.js'
import * as cloudFunctionUtil from '@/js/cloud-function-util.js'
import siteConfig from '@/config/conf.yaml'

function showError(message) {
    const loadingContentContainer = document.getElementById('loading-content-container');
    const errorContentContainer = document.getElementById('error-content-container');
    const errorStatusText = document.getElementById('error-status-text');
    
    errorStatusText.textContent = `Error: ${message}`;
    
    loadingContentContainer.style.display = 'none';
    errorContentContainer.style.display = 'block';
}

async function authenticate() {
    const redirectingContentContainer = document.getElementById('redirecting-content-container');
    const loadingContentContainer = document.getElementById('loading-content-container');
    redirectingContentContainer.style.display = 'block';
    loadingContentContainer.style.display = 'none';

    const body = {
        'deep_link_redirect': window.location.href
    };
    const startSessionResponse = await fetch(
        `https://${siteConfig.authServerExternalHostname}/start-session`,
        {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body),
            credentials: 'include'
        }
    );
    
    if (startSessionResponse.ok) {
        const startSessionResponseJson = await startSessionResponse.json();
        window.location.replace(startSessionResponseJson['oauth_login_uri']);
    }

    return startSessionResponse;
}

async function acceptAssignment(accessToken, accessTokenOctokit, assignmentName, assignmentAcceptKey, cloudFunctionEndpoint) {
    let failedAuth = 0;
    let succeeded = false;
    let acceptAssignmentResponse;
    while (failedAuth < 2 && !succeeded) {
        let acceptAssignmentRequestInputs = {
            'user_access_token': accessToken,
            'assignment_name': assignmentName
        }
        if (assignmentAcceptKey !== null) {
            acceptAssignmentRequestInputs['assignment_accept_key'] = assignmentAcceptKey;
        }
        acceptAssignmentResponse = await cloudFunctionUtil.acceptAssignmentViaCloudFunction(acceptAssignmentRequestInputs, cloudFunctionEndpoint);

        if (acceptAssignmentResponse.jsonBody === null) {
            // Failed to get proper JSON response (e.g., internal server
            // error). Display error message.
            showError(acceptAssignmentResponse.errorMessage);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                response: acceptAssignmentResponse.jsonBody
            };
        }

        if (acceptAssignmentResponse.jsonBody['status'] === 'unknown-assignment') {
            showError(`Assignment "${assignmentName}" not found.`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                response: acceptAssignmentResponse.jsonBody
            };
        } else if (acceptAssignmentResponse.jsonBody['status'] === 'denied') {
            showError('Assignment access denied. Perhaps your accept key is bad, or the assignment is not currently released for your class section.')
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                response: acceptAssignmentResponse.jsonBody
            };
        } else if (acceptAssignmentResponse.jsonBody['status'] == 'bad-auth') {
            failedAuth++;
            if (failedAuth < 2) {
                const getAccessTokenResults = await util.getAccessToken();
                if (getAccessTokenResults.status === 'success') {
                    accessToken = getAccessTokenResults.accessToken;
                    accessTokenOctokit = new Octokit({
                        auth: accessToken
                    });
                } else if (getAccessTokenResults.status === 'bad-auth') {
                    // Session or refresh token is expired. Redirect to GitHub
                    // OAuth login.
                    const startSessionResponse = await authenticate();
                    if (!startSessionResponse.ok) {
                        showError('Failed to start session');
                        return {
                            refreshedAccessToken: accessToken,
                            refreshedAccessTokenOctokit: accessTokenOctokit,
                            succeeded: false,
                            response: null
                        };
                    }
                    return { // Shouldn't happen (should've redirected away)
                        refreshedAccessToken: accessToken,
                        refreshedAccessTokenOctokit: accessTokenOctokit,
                        succeeded: false,
                        response: null
                    };
                } else {
                    // Failed to get access token for unexpected reason. Display
                    // error message and halt.
                    showError(`Failed to authenticate user with GitHub`);
                    return {
                        refreshedAccessToken: accessToken,
                        refreshedAccessTokenOctokit: accessTokenOctokit,
                        succeeded: false,
                        response: null
                    };
                }
            } else {
                showError(`Failed to authenticate user with GitHub`);
                return {
                    refreshedAccessToken: accessToken,
                    refreshedAccessTokenOctokit: accessTokenOctokit,
                    succeeded: false,
                    response: null
                };
            }
        } else if (acceptAssignmentResponse.jsonBody['status'] == 'duplicate-username') {
            showError(`Repository already exists but somehow belongs to a different student (perhaps you recently changed your username, or you modified the STUDENT_ID repository variable). Instructor intervention is required.`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                response: null
            };
        } else if (acceptAssignmentResponse.jsonBody['status'] != 'success') {
            showError(`Assignment accept endpoint reported non-success status "${acceptAssignmentResponse.jsonBody['status']}"`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                response: null
            };
        } else {
            succeeded = true;
        }
    }
    
    return {
        refreshedAccessToken: accessToken,
        refreshedAccessTokenOctokit: accessTokenOctokit,
        succeeded: succeeded,
        response: acceptAssignmentResponse.jsonBody
    };
}

document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const assignmentName = urlParams.get('assignment-name');
    const assignmentAcceptKey = urlParams.get('assignment-accept-key');
    const organizationName = urlParams.get('organization-name');

    if (assignmentName == null || assignmentName == "") {
        showError("Missing assignment name in this page's URL");
        return;
    }

    if (organizationName == null || organizationName == "") {
        showError("Missing organization name in this page's URL");
        return;
    }
    
    // Get access token
    const getAccessTokenResults = await util.getAccessToken();
    let accessToken;
    let accessTokenOctokit;
    if (getAccessTokenResults.status == 'success') {
        accessToken = getAccessTokenResults.accessToken;
        accessTokenOctokit = new Octokit({
            auth: accessToken
        });
    } else if (getAccessTokenResults.status == 'bad-auth') {
        // Session or refresh token is expired. Redirect to GitHub OAuth login.
        const startSessionResponse = await authenticate();
        if (!startSessionResponse.ok) {
            // Failed to start session for some reason. Display
            // error message and halt.
            showError('Failed to start session');
            return;
        }
        return;
    } else {
        // Failed to get access token for unexpected reason. Display error
        // and halt.
        showError(`Failed to authenticate user with GitHub`);
        return;
    }

    // Logged in. Show loading content
    
    const assignmentAcceptTitle = document.getElementById('assignment-accept-title');
    assignmentAcceptTitle.textContent = `Accepting assignment "${assignmentName}"`;
    
    // Get cloud function endpoint for organization
    const cloudFunctionEndpoint = await cloudFunctionUtil.getOrganizationCloudFunctionEndpoint(organizationName, accessTokenOctokit)

    // Dispatch backend workflow to accept assignment.
    const acceptResults = await acceptAssignment(
        accessToken,
        accessTokenOctokit,
        assignmentName,
        assignmentAcceptKey,
        cloudFunctionEndpoint
    );

    accessToken = acceptResults.refreshedAccessToken;
    accessTokenOctokit = acceptResults.refreshedAccessTokenOctokit;

    if (!acceptResults.succeeded) {
        return;
    }

    if (Object.hasOwn(acceptResults.response, 'repositoryAccessToken')) {
        // Store repository access token and repo remote URL in window globals
        // so that browser automation tool can grab them
        window.repositoryAccessToken = acceptResults.response.repositoryAccessToken;
        window.repositoryRemoteURL = acceptResults.response.repositoryRemoteURL;
        console.log(`repositoryAccessToken: retrieved`);
    } else if (Object.hasOwn(acceptResults.response, 'repositoryURL')) {
        window.location.replace(acceptResults.response.repositoryURL);
    }
});
