import readline from 'node:readline/promises';
import { setTimeout } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { stat, mkdir } from 'node:fs/promises';
import { stdin as input, stdout as output } from 'node:process';

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
const assignmentName = parseArg(values.assignment, process.env.FOOBAR_PROJECTS_ASSIGNMENT);
const credentialHelperCacheTimeout = parseArg(values.gitCredentialHelperCacheTimeout, process.env.FOOBAR_PROJECTS_GIT_CREDENTIAL_HELPER_CACHE_TIMEOUT, 3600 - 60);
const assignmentAcceptKey = parseArg(values.key, process.env.FOOBAR_PROJECTS_ASSIGNMENT_ACCEPT_KEY);
const foobarProjectsHost = process.env.FOOBAR_PROJECTS_HOST || 'https://foobarprojects.org';

// Disable git terminal prompts (e.g., username / password prompt) so that,
// if cached credentials have expired, git push fails rather than
// prompting for username + password
process.env.GIT_TERMINAL_PROMPT = '0';

try {
    console.log('Staging all changes...')
    await new Promise((resolve, reject) => {
        const child = spawn('git', ['add', '-A']);
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Failed to stage changes. git add exited with status ${code}.`));
            }
        });
        child.on('error', (err) => {
            reject(new Error(`Failed to stage changes. Error: ${err.toString()}`));
        });
    });
} catch (error) {}

try {
    console.log('Committing all changes...')
    await new Promise((resolve, reject) => {
        const child = spawn('git', ['commit', '-m', 'Save work']);
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Failed to commit changes. git commit exited with status ${code}.`));
            }
        });
        child.on('error', (err) => {
            reject(new Error(`Failed to commit changes. Error: ${err.toString()}`));
        });
    });
} catch (error) {}

let success = false;
try {
    console.log('Attempting to push commits...')
    await new Promise((resolve, reject) => {
        const child = spawn('git', ['push']);
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Failed to push changes. git push exited with status ${code}.`));
            }
        });
        child.on('error', (err) => {
            reject(new Error(`Failed to push changes. Error: ${err.toString()}`));
        });
    });
    success = true;
} catch (error) {}

if (success) {
    console.log('Done.');
    process.exit(0);
}

// Git push failed. Re-accept assignment to refresh access token

if (!organizationName || !assignmentName) {
    console.log('Push failed. Access token may be expired. A new access token must be generated. Please re-run this script with -o <organization_name> -a <assignment_name> [-k <assignment_accept_key>]')
    process.exit(1);
}

const rl = readline.createInterface({ input, output });
await rl.question('Push failed. Access token may be expired. Press [ENTER] to re-accept the assignment and generate a new access token: ');
rl.close();

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

// Precondition: working directory must be inside git repository
async function uploadAssignment(
        repositoryRemoteURL,
        credentialHelperCacheTimeout) {
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
        const child = spawn('git', ['push', repositoryRemoteURL, 'main']);
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Failed to push commits. git push exited with status ${code}.`));
            }
        });
        child.on('error', (err) => {
            reject(`Failed to push commits. Error: ${err.toString()}`);
        });
    });
    console.log(`Saved changes to GitHub repository.`)
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
            
            if (repositoryAccessToken) {
                await browser.close();
                
                await uploadAssignment(
                    repositoryRemoteURL,
                    credentialHelperCacheTimeout
                );

                return;
            } else {
                console.error('Error: Failed to retrieve repository access token');
            }
        }
    });
});

await page.goto(url);
