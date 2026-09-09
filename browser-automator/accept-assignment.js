import { setTimeout } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';

import puppeteer from 'puppeteer';

const options = {
  organization: { type: 'string', short: 'o' },
  assignment: { type: 'string', short: 'a' },
  key: { type: 'string', short: 'k' },
};

const { values, _ } = parseArgs({ options });

function parseArg(argVal, envVarVal, defaultValue) {
    if (argVal) {
        return argVal;
    } else if (envVarVal) {
        return envVarVal;
    } else if (defaultValue) {
        return defaultValue;
    } else {
        return null;
    }
}

const organizationName = parseArg(values.organization, process.env.FOOBAR_PROJECTS_ORGANIZATION);
if (!organizationName) {
    console.error('Error: Missing organization name. Specify via -o <organization_name> or set FOOBAR_PROJECTS_ORGANIZATION environment variable.');
    process.exit(1);
}

const assignmentName = parseArg(values.assignment, process.env.FOOBAR_PROJECTS_ASSIGNMENT);
if (!assignmentName) {
    console.error('Error: Missing assignment name. Specify via -a <assignment_name> or set FOOBAR_PROJECTS_ASSIGNMENT environment variable.');
    process.exit(1);
}

const credentialHelperCacheTimeout = parseArg(values.gitCredentialHelperCacheTimeout, process.env.FOOBAR_PROJECTS_GIT_CREDENTIAL_HELPER_CACHE_TIMEOUT, 3600 - 60);

const assignmentAcceptKey = parseArg(values.key, process.env.FOOBAR_PROJECTS_ASSIGNMENT_ACCEPT_KEY);

const foobarProjectsHost = process.env.FOOBAR_PROJECTS_HOST || 'https://foobarprojects.org';

let url = `${foobarProjectsHost}?organization-name=${organizationName}&assignment-name=${assignmentName}`;
if (assignmentAcceptKey) {
    url += `&assignment-accept-key=${assignmentAcceptKey}`;
}

const browser = await puppeteer.launch({
    headless: false,
    slowMo: 50,
    // args: [`--app=${url}`]
    defaultViewport: null,
    args: [
      '--kiosk',
      '--no-first-run',
      '--disable-infobars',
    ]
});

// const [page] = await browser.pages();
const page = await browser.newPage();

async function dirExists(path) {
    try {
        const stats = await stat(path);
        return stats.isDirectory();
    } catch (error) {
        if (error.code === 'ENOENT') {
            return false;
        }
        throw error;
    }
}

page.on('console', async (msg) => {
    const args = await Promise.all(msg.args().map(arg => arg.jsonValue()));
    
    const formattedArgs = args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : arg
    );

    formattedArgs.forEach(async (formattedArg) => {
        if (formattedArg.startsWith("repositoryAccessToken")) {
            const repositoryAccessToken = await page.evaluate(() => {
                return window.repositoryAccessToken;
            });
            const repositoryRemoteURL = await page.evaluate(() => {
                return window.repositoryRemoteURL;
            });
            const repositoryRemoteURLWithoutCredentials = 'https://' + repositoryRemoteURL.split('@')[1];
            const repositoryRemoteCredentials = repositoryRemoteURL.split('https://')[1].split('@')[0];
            const repositoryRemoteCredentialsBase64 = Buffer.from(repositoryRemoteCredentials, 'utf8').toString('base64');
            
            if (repositoryAccessToken) {
                const repoDir = repositoryRemoteURL.split('/').at(-1).split('.git')[0];
                if (await dirExists(repoDir)) {
                    console.log(`Repository directory ${repoDir} already exists. Skipping git clone.`)
                } else {
                    await new Promise((resolve, reject) => {
                        console.log('git', 'clone', '-c', `http.extraheader=Authorization: Basic ${repositoryRemoteCredentials}`, repositoryRemoteURLWithoutCredentials, repoDir);
                        const child = spawn('git', ['clone', '-c', `http.extraheader=Authorization: Basic ${repositoryRemoteCredentialsBase64}`, repositoryRemoteURLWithoutCredentials, repoDir]);
                        child.on('close', (code) => {
                            if (code === 0) {
                                resolve();
                            } else {
                                reject(new Error(`Failed to clone repository. git clone exited with status ${code}.`));
                            }
                        });
                        child.on('error', (err) => {
                            reject(`Failed to clone repository. Error: ${err.toString()}`);
                        });
                    });
                    console.log(`Cloned repository into local directory ${repoDir}`)
                }

                process.chdir(repoDir);

                await new Promise((resolve, reject) => {
                    const child = spawn('git', ['config', 'credential.helper', `cache --timeout=${credentialHelperCacheTimeout}`]);
                    child.on('close', (code) => {
                        if (code === 0) {
                            resolve();
                        } else {
                            reject(new Error(`Failed to configure git credential.helper. git config exited with status ${code}.`));
                        }
                    });
                    child.on('error', (err) => {
                        reject(`Failed to configure git credential.helper. Error: ${err.toString()}`);
                    });
                });

                await new Promise((resolve, reject) => {
                    const child = spawn('git', ['credential-cache', 'exit']);
                    child.on('close', (code) => {
                        if (code === 0) {
                            resolve();
                        } else {
                            reject(new Error(`Failed to clear git credential cache. git credential-cache exited with status ${code}.`));
                        }
                    });
                    child.on('error', (err) => {
                        reject(`Failed to clear git credential cache. Error: ${err.toString()}`);
                    });
                });

                await new Promise((resolve, reject) => {
                    const child = spawn('git', ['fetch', repositoryRemoteURL]);
                    child.on('close', (code) => {
                        if (code === 0) {
                            resolve();
                        } else {
                            reject(new Error(`Failed to fetch repository updates. git fetch exited with status ${code}.`));
                        }
                    });
                    child.on('error', (err) => {
                        reject(`Failed to fetch repository updates. Error: ${err.toString()}`);
                    });
                });
                
                await browser.close();
            } else {
                console.error('Error: Failed to retrieve repository access token');
            }
        }
    });
});

await page.goto(url);
