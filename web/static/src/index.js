import { Octokit } from 'octokit';
import JSZip from 'jszip';

import * as util from '@/js/util.js'
import siteConfig from '@/config/conf.yaml'

function resetProgress() {
    const redirectingContentContainer = document.getElementById('redirecting-content-container');
    const loadingContentContainer = document.getElementById('loading-content-container');
    const progressBar = document.getElementById('loading-progress-bar');
    const loadingStatusTextContainer = document.getElementById('loading-status-text-container');

    progressBar.querySelectorAll('.progress-chunk-visible').forEach((chunk) => {
        chunk.classList.remove('progress-chunk-visible');
    });

    loadingStatusTextContainer
        .querySelector('.status-text-visible')
        .classList
        .remove('status-text-visible');

    loadingStatusTextContainer
        .querySelector('.status-text')
        .classList
        .add('status-text-visible');

    redirectingContentContainer.style.display = 'none';
    loadingContentContainer.style.display = 'block';
}

function stepProgress() {
    const progressBar = document.getElementById('loading-progress-bar');
    const loadingStatusTextContainer = document.getElementById('loading-status-text-container');
    const visibleStatusText = loadingStatusTextContainer.querySelector('.status-text-visible');
    const nextStatusText = visibleStatusText.nextElementSibling;
    const nextProgressChunk = progressBar.querySelector(':not(.progress-chunk-visible)');

    if (nextStatusText !== null) {
        visibleStatusText.classList.remove('status-text-visible');
        nextStatusText.classList.add('status-text-visible');
    }
    if (nextProgressChunk !== null) {
        nextProgressChunk.classList.add('progress-chunk-visible');
    }
}

function showError(message) {
    const loadingContentContainer = document.getElementById('loading-content-container');
    const errorContentContainer = document.getElementById('error-content-container');
    const errorStatusText = document.getElementById('error-status-text');
    
    errorStatusText.textContent = `Error: ${message}`;
    
    loadingContentContainer.style.display = 'none';
    errorContentContainer.style.display = 'block';
}

function updateWorkflowStatus(statusUpdate) {
    if (statusUpdate.status == 'error') {
        showError(statusUpdate.message);
    } else {
        stepProgress()
    }
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

async function acceptAssignment(organizationName, accessToken, accessTokenOctokit, assignmentName, assignmentAcceptKey, classroomRSAPublicKey) {
    let failedAuth = 0;
    let succeeded = false;
    let zip;
    while (failedAuth < 2 && !succeeded) {
        resetProgress();
        let workflowInputs = {
            'userAccessToken': accessToken,
            'assignmentName': assignmentName
        }
        if (assignmentAcceptKey !== null) {
            workflowInputs['assignmentAcceptKey'] = assignmentAcceptKey;
        }
        zip = await util.dispatchWorkflowViaIssue(organizationName, 'accept-assignment', workflowInputs, updateWorkflowStatus, siteConfig.pollDelay, accessTokenOctokit, classroomRSAPublicKey);

        if (zip === null) {
            // Workflow failed. Error message should already be displayed via
            // statusUpdateCallback functional parameter
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        }

        if (!Object.hasOwn(zip.files, 'result/status.json')) {
            showError("Artifact result archive missing status.json");
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        }

        const statusJson = await zip.files['result/status.json'].async('string');
        const statusObj = JSON.parse(statusJson);
        if (statusObj.status == 'unknown-assignment') {
            showError(`Assignment "${assignmentName}" not found.`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        } else if (statusObj.status == 'invalid-key') {
            if (assignmentAcceptKey !== null) {
                showError(`Incorrect assignment accept key "${assignmentAcceptKey}".`);
            } else {
                showError('Missing assignment accept key.');
            }
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        } else if (statusObj.status == 'bad-auth') {
            failedAuth++;
            if (failedAuth < 2) {
                const getAccessTokenResults = await util.getAccessToken();
                if (getAccessTokenResults.status == 'success') {
                    accessToken = getAccessTokenResults.accessToken;
                    accessTokenOctokit = new Octokit({
                        auth: accessToken
                    });
                } else if (getAccessTokenResults.status == 'bad-auth') {
                    // Session or refresh token is expired. Redirect to GitHub
                    // OAuth login.
                    const startSessionResponse = await authenticate();
                    if (!startSessionResponse.ok && startSessionResponse.status != 409) {
                        // 409 (StatusConflict) means session already exists and
                        // has valid (non-expired) refresh token. Anything
                        // else is an error. Display error message and halt.
                        showError('Failed to start session');
                        return {
                            refreshedAccessToken: accessToken,
                            refreshedAccessTokenOctokit: accessTokenOctokit,
                            succeeded: false
                        };
                    }
                    return {
                        refreshedAccessToken: accessToken,
                        refreshedAccessTokenOctokit: accessTokenOctokit,
                        succeeded: false
                    };
                } else {
                    // Failed to get access token for unexpected reason. Display
                    // error message and halt.
                    showError(`Failed to authenticate user with GitHub`);
                    return {
                        refreshedAccessToken: accessToken,
                        refreshedAccessTokenOctokit: accessTokenOctokit,
                        succeeded: false
                    };
                }
            } else {
                showError(`Failed to authenticate user with GitHub`);
                return {
                    refreshedAccessToken: accessToken,
                    refreshedAccessTokenOctokit: accessTokenOctokit,
                    succeeded: false
                };
            }
        } else if (statusObj.status == 'duplicate-username') {
            showError(`Repository already exists but somehow belongs to a different student (perhaps you recently changed your username, or you modified the STUDENT_ID repository variable). Instructor intervention is required.`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        } else if (statusObj.status != 'success') {
            showError(`Artifact result archive reported non-success status "${statusObj.status}"`);
            return {
                refreshedAccessToken: accessToken,
                refreshedAccessTokenOctokit: accessTokenOctokit,
                succeeded: false,
                zip: null
            };
        } else {
            succeeded = true;
        }
    }
    
    return {
        refreshedAccessToken: accessToken,
        refreshedAccessTokenOctokit: accessTokenOctokit,
        succeeded: succeeded,
        zip: zip
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
    
    // Get classroom RSA public key
    const classroomRSAPublicKey = await util.getClassroomRSAPublicKey(organizationName, accessTokenOctokit)

    // Dispatch backend workflow to accept assignment.
    const acceptResults = await acceptAssignment(
        organizationName,
        accessToken,
        accessTokenOctokit,
        assignmentName,
        assignmentAcceptKey,
        classroomRSAPublicKey
    );

    accessToken = acceptResults.refreshedAccessToken;
    accessTokenOctokit = acceptResults.refreshedAccessTokenOctokit;

    if (!acceptResults.succeeded) {
        return;
    }

    if (!Object.hasOwn(acceptResults.zip.files, 'result/data.json')) {
        showError("Artifact result archive missing data.json");
        return;
    }

    const responseDataJson = await acceptResults.zip.files['result/data.json'].async('string');
    const responseData = JSON.parse(responseDataJson);

    window.location.replace(responseData.repositoryURL);
});
