import yaml
import jwt
import shutil
import tempfile
import subprocess
from contextlib import chdir
from pathlib import Path
import json
import sys
import multiprocessing
import typing
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time
import textwrap
import threading
import os
from base64 import b64encode

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from nacl import encoding, public
from rich.console import Console
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
import requests


# Number of consecutive failures for a given API query before raising an
# exception
MAX_API_ATTEMPTS = 3
# Seconds of waiting before re-attempting API query
API_REATTEMPT_WAIT_INTERVAL = 10.0


console = Console()


def rprint(*args: typing.Any, **kwargs: typing.Any) -> None:
    console.print(*args, **kwargs)


def rprint_wrapped(text: str, end: str='\n', **kwargs: typing.Any) -> None:
    lines = text.split('\n')
    for line in lines[:-1]:
        rprint(
            textwrap.fill(
                line,
                width=80,
                replace_whitespace=False,
                drop_whitespace=False
            ),
            **kwargs
        )
    rprint(
        textwrap.fill(
            lines[-1],
            width=80,
            replace_whitespace=False,
            drop_whitespace=False
        ),
        end=end,
        **kwargs
    )


PRESS_ENTER_TO_CONTINUE_MESSAGE = ('[Press enter when you\'re '
    'ready to continue.]')
GREET_MESSAGE = (
    'This tool will guide you through the process of setting up a '
    'classroom so that you can distribute programming assignments '
    'to your students. Most of the work will be automated by this tool, '
    'but some manual intervention will be required. Please do not exit this '
    'tool until setup is complete.\n\n'
    'Note: This tool is NOT designed for modifying an existing classroom '
    'deployment. Refer to guides/configuration.md for more information on '
    'classroom deployment configuration.'
)


def greet() -> None:
    rprint_wrapped(GREET_MESSAGE)
    rprint()


REQUEST_ORGANIZATION_NAME_MESSAGE_1 = (
    'The first step is to create a GitHub Organization that will manage your '
    'classroom. This step cannot be automated and must be done within the '
    'GitHub web UI. You may use an existing GitHub Organization if you\'d '
    'like, but you must be an owner of the chosen Organization. That said, '
    'it\'s strongly recommended that you use a new organization.\n'
    '\n'
    'Follow the below link to create a new GitHub Organization.'
)
REQUEST_ORGANIZATION_NAME_LINK = (
    'https://github.com/account/organizations/new'
)
REQUEST_ORGANIZATION_NAME_PROMPT = (
    'Enter the exact name of your GitHub Organization (case-sensitive): '
)
REQUEST_ORGANIZATION_NAME_REPROMPT = (
    'For confirmation, please enter the organization name again: '
)
REQUEST_ORGANIZATION_NAME_ERROR = (
    'Error: The two organization names you entered did not match. '
    'Please try again.'
)


def request_organization_name() -> str:
    matching = False
    first = True
    while not matching:
        if first:
            rprint_wrapped(REQUEST_ORGANIZATION_NAME_MESSAGE_1)
            rprint()
            rprint(REQUEST_ORGANIZATION_NAME_LINK)
            rprint()
            first = False

        exists = False
        while not exists:
            organization_name_1 = input(REQUEST_ORGANIZATION_NAME_PROMPT)
            rprint()
            
            # Verify organization exists
            headers = {
                'X-GitHub-Api-Version': '2026-03-10',
                'Accept': 'application/vnd.github+json',
            }
            response = requests.get(
                (f'https://api.github.com/orgs/{organization_name_1}'),
                headers=headers
            )
            if response.status_code >= 200 and response.status_code < 300:
                exists = True

            if not exists:
                rprint(
                    (f'Error: GitHub Organization '
                        f'"{organization_name_1}" not found.'),
                    style='bold red'
                )
                rprint()
        organization_name_2 = input(REQUEST_ORGANIZATION_NAME_REPROMPT)
        rprint()

        matching = organization_name_1 == organization_name_2
        if not matching:
            rprint_wrapped(REQUEST_ORGANIZATION_NAME_ERROR, style='bold red')

    return organization_name_1


def generate_and_sign_jwt(client_id: str, private_key: str) -> str:
    payload = {
        'iat': int(time.time()) - 60,
        'exp': int(time.time()) - 60 + 600,
        'iss': client_id
    }
    encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256')
    return encoded_jwt


def get_installation_access_token(
        encoded_jwt: str,
        installation_id: str) -> Json:
    # Exchange JWT for installation access token and
    # repository_selection value
    headers = {
        'X-GitHub-Api-Version': '2026-03-10',
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {encoded_jwt}'
    }
    response = requests.post(
        (f'https://api.github.com/app/installations/'
            f'{installation_id}/access_tokens'),
        headers=headers
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError(f'Got HTTP status code {response.status_code} '
            f'when generating installation access token')

    response_json = response.json()
    return response_json


def uninstall_app(
        encoded_jwt: str,
        installation_id: str) -> None:
    # Use JWT to delete installation
    headers = {
        'X-GitHub-Api-Version': '2026-03-10',
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {encoded_jwt}'
    }
    response = requests.delete(
        (f'https://api.github.com/app/installations/{installation_id}'),
        headers=headers
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError(f'Got HTTP status code {response.status_code} '
            f'when deleting app installation')


class NotifyingServer(ThreadingHTTPServer):
    def __init__(
            self,
            server_address: tuple[str, int],
            RequestHandlerClass: type,
            server_state: ServerState):
        self._server_state = server_state
        super().__init__(server_address, RequestHandlerClass)

    # Notifies main thread that server is up and running via
    # threading.Event
    def server_activate(self) -> None:
        super().server_activate()
        self._server_state.up = True
        self._server_state.ready_event.set()


class AppRegistrationResponse:
    app_id: int
    client_id: str
    client_secret: str
    private_key: str
    installation_url: str

    def __init__(
            self,
            app_id: int,
            client_id: str,
            client_secret: str,
            private_key: str,
            installation_url: str) -> None:
        self.app_id = app_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.installation_url = installation_url


class AppInstallationResponse:
    installation_id: str

    def __init__(self, installation_id: str) -> None:
        self.installation_id = installation_id


class RepositoryCreationData:
    id: int
    html_url: str

    def __init__(self, id: int, html_url: str) -> None:
        self.id = id
        self.html_url = html_url


type Json = typing.Any
type Repository = Json

type InstallationVerifier =\
    typing.Callable[[str, list[Repository] | None], bool]

class AppDetails:
    installation_instructions: str
    installation_configuration_error_message: str
    next_endpoint: str | None
    installation_verifier: InstallationVerifier
    public: bool
    
    def __init__(
            self,
            installation_instructions: str,
            installation_configuration_error_message: str,
            installation_verifier: InstallationVerifier,
            next_endpoint: str | None = None,
            public: bool = False) -> None:
        self.installation_instructions = installation_instructions
        self.installation_configuration_error_message =\
            installation_configuration_error_message
        self.next_endpoint = next_endpoint
        self.installation_verifier = installation_verifier
        self.public = public


class HandlerContext:
    @staticmethod
    def verify_classroom_setup_app_installation(
            repository_selection: str,
            repositories: list[Repository] | None) -> bool:
        return repository_selection == 'all'


    @staticmethod
    def verify_backend_workflow_dispatch_app_installation(
            repository_selection: str,
            repositories: list[Repository] | None) -> bool:
        if repository_selection != 'selected':
            return False

        if repositories is None or len(repositories) != 1:
            return False
        
        if repositories[0]['name'] != 'backend-workflows':
            return False

        return True
        

    @staticmethod
    def verify_classrooms_app_installation(
            repository_selection: str,
            repositories: list[Repository] | None) -> bool:
        if repository_selection != 'selected':
            return False

        if repositories is None or len(repositories) != 1:
            return False
        
        if repositories[0]['name'] != 'classrooms':
            return False

        return True


    @staticmethod
    def verify_assignment_creation_app_installation(
            repository_selection: str,
            repositories: list[Repository] | None) -> bool:
        return repository_selection == 'all'


    # TODO consolidate the various app-specific constants / dicts into
    # APP_DETAILS
    CLASSROOM_SETUP_APP_ENDPOINT = \
        'classroom-setup-app'
    WORKFLOW_DISPATCH_APP_ENDPOINT = \
        'workflow-dispatch-app'
    CLASSROOMS_APP_ENDPOINT = \
        'classrooms-app'
    ASSIGNMENT_CREATION_APP_ENDPOINT = \
        'assignment-creation-app'
    APP_MANIFEST_ENDPOINTS = [
        CLASSROOM_SETUP_APP_ENDPOINT,
        WORKFLOW_DISPATCH_APP_ENDPOINT,
        CLASSROOMS_APP_ENDPOINT,
        ASSIGNMENT_CREATION_APP_ENDPOINT,
    ]
    APP_NAMES = {
        CLASSROOM_SETUP_APP_ENDPOINT: \
            'Classroom Setup',
        WORKFLOW_DISPATCH_APP_ENDPOINT: \
            'Workflow Dispatch',
        CLASSROOMS_APP_ENDPOINT: \
            'Classrooms',
        ASSIGNMENT_CREATION_APP_ENDPOINT: \
            'Assignment Creation'
    }
    APP_DESCRIPTIONS = {
        CLASSROOM_SETUP_APP_ENDPOINT: ('Temporary app used to '
            'automate the setup process for the classroom. '
            'The setup script automatically uninstalls this app (but does not '
            'unregister it) when the setup is complete.'),
        WORKFLOW_DISPATCH_APP_ENDPOINT: ('App embedded in '
            'classroom\'s student-facing web frontend. Used to dispatch '
            'backend workflows (e.g., to authenticate students and accept '
            'assignments).'),
        ASSIGNMENT_CREATION_APP_ENDPOINT: ('App used to '
            'generate, populate, and generate invites for student '
            'assignment repositories.'),
        CLASSROOMS_APP_ENDPOINT: ('App used to '
            'read classrooms repository contents for configuring '
            'and initializing student assignment repositories upon assignment '
            'acceptance.')
    }
    APP_PERMISSIONS = {
        CLASSROOM_SETUP_APP_ENDPOINT: {
            'organization_administration': 'write',
            'administration': 'write',
            'contents': 'write',
            'pages': 'write',
            'secrets': 'write',
            'actions_variables': 'write',
            'workflows': 'write',
            'metadata': 'read'
        },
        WORKFLOW_DISPATCH_APP_ENDPOINT: {
            'actions': 'read',
            'issues': 'write'
        },
        ASSIGNMENT_CREATION_APP_ENDPOINT: {
            'administration': 'write',
            'contents': 'write',
            'actions_variables': 'write',
            'metadata': 'read'
        },
        CLASSROOMS_APP_ENDPOINT: {
            'contents': 'read',
            'metadata': 'read'
        }
    }
    APP_DETAILS = {
        CLASSROOM_SETUP_APP_ENDPOINT: AppDetails(
            installation_instructions=('Install the Classroom Setup app '
                'in your GitHub Organization '
                'on ALL repositories. Note: The setup script will uninstall '
                'this app once the setup is complete.'),
            installation_configuration_error_message=('The Classroom Setup '
                'app must be installed on ALL (not selected) repositories.'),
            next_endpoint=\
                f'{WORKFLOW_DISPATCH_APP_ENDPOINT}/install',
            installation_verifier=\
                verify_classroom_setup_app_installation
        ),
        WORKFLOW_DISPATCH_APP_ENDPOINT: AppDetails(
            installation_instructions=('Install the Workflow Dispatch '
                'app in your GitHub Organization '
                'on the "backend-workflows" repository. CRITICAL: '
                'Install this app ONLY on the "backend-workflows" '
                'repository. Do NOT install it on all repositories.'),
            installation_configuration_error_message=('For security reasons, '
                'the Workflow Dispatch '
                'app must be installed on, and ONLY on, the '
                '"backend-workflows" repository.'),
            next_endpoint=\
                ASSIGNMENT_CREATION_APP_ENDPOINT,
            installation_verifier=\
                verify_backend_workflow_dispatch_app_installation,
            public=True
        ),
        ASSIGNMENT_CREATION_APP_ENDPOINT: AppDetails(
            installation_instructions=(f'Install the Assignment Creation '
                'app in your GitHub '
                'Organization on ALL repositories.'),
            installation_configuration_error_message=('The Assignment Creation '
                'app must be installed on ALL (not selected) '
                'repositories.'),
            next_endpoint=\
                CLASSROOMS_APP_ENDPOINT,
            installation_verifier=\
                verify_assignment_creation_app_installation
        ),
        CLASSROOMS_APP_ENDPOINT: AppDetails(
            installation_instructions=('Install the Classrooms '
                'app in your GitHub Organization '
                'on the "classrooms" repository. CRITICAL: '
                'Install this app ONLY on the "classrooms" '
                'repository. Do NOT install it on all repositories.'),
            installation_configuration_error_message=('For security reasons, '
                'the Classrooms '
                'app must be installed on, and ONLY on, the '
                '"classrooms" repository.'),
            installation_verifier=\
                verify_classrooms_app_installation
        )
    }
    content_events: dict[str, threading.Event]
    organization_name: str
    server_port: int | None
    all_repository_creation_data: dict[str, RepositoryCreationData]
    app_registration_responses: dict[str, AppRegistrationResponse]
    app_installation_responses: dict[str, AppInstallationResponse]
    state_string: str | None
    repositories_created_event: threading.Event
    classroom_setup_token: str | None
    first_visit: bool
    
    def __init__(
            self,
            organization_name: str,
            config: typing.Any) -> None:
        self.organization_name = organization_name
        self.config = config
        self.content_events = {
            endpoint: threading.Event() for endpoint in \
                self.APP_MANIFEST_ENDPOINTS
        }
        self.server_port = None
        self.all_repository_creation_data = {}
        self.app_registration_responses = {}
        self.app_installation_responses = {}
        self.state_string = None
        self.repositories_created_event = threading.Event()
        self.classroom_setup_token = None
        self.first_visit = False


URL_CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_"
def secure_random_url_string(length: int) -> str:
    random_bytes = os.urandom(length)
    random_chars = [URL_CHARS[byte % len(URL_CHARS)] for byte in random_bytes]
    return ''.join(random_chars)

APP_NAME_CHARS="ABC1234567890"
def random_app_name_suffix(length: int) -> str:
    random_bytes = os.urandom(length)
    random_chars = [APP_NAME_CHARS[byte % len(APP_NAME_CHARS)] for byte in random_bytes]
    return ''.join(random_chars)


MAX_APP_NAME_LENGTH = 34


def get_handler_class(context: HandlerContext) -> type:
    class Handler(BaseHTTPRequestHandler):
        def register_app(self, registration_endpoint: str) -> None:
            app_name = context.APP_NAMES[registration_endpoint]
            app_name_suffix = \
                random_app_name_suffix(MAX_APP_NAME_LENGTH - len(app_name) - 1)
            app_default_permissions = \
                json.dumps(context.APP_PERMISSIONS[registration_endpoint])
            state_string = secure_random_url_string(32)
            context.state_string = state_string
            html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Next action item: register the {app_name} app on GitHub.</div><form id="manifest-form" action="https://github.com/organizations/{context.organization_name}/settings/apps/new?state={state_string}" method="post">
<input type="hidden" name="manifest" id="manifest">
<input type="submit" value="Click here to begin action item">
</form></div>

<script>
window.addEventListener('DOMContentLoaded', () => {{
  form = document.getElementById("manifest-form")
  input = document.getElementById("manifest")
  input.value = JSON.stringify({{
    "name": "{app_name} {app_name_suffix}",
    "url": "https://github.com/{context.organization_name}",
    "redirect_url": "http://localhost:{context.server_port}/{registration_endpoint}/install",
    "setup_url": "http://localhost:{context.server_port}/{registration_endpoint}/setup",
    "description": "{context.APP_DESCRIPTIONS[registration_endpoint]}",
    "public": {'true' if context.APP_DETAILS[registration_endpoint].public else 'false'},
    "default_permissions": {app_default_permissions},
    "setup_on_update": true
  }})
}});
</script></body></html>'''

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))


        def register_classroom_setup_app(self) -> None:
            self.register_app(
                context.CLASSROOM_SETUP_APP_ENDPOINT
            )


        def register_backend_workflow_dispatch_app(self) -> None:
            context.repositories_created_event.wait()
            self.register_app(
                context.WORKFLOW_DISPATCH_APP_ENDPOINT
            )


        def register_assignment_creation_app(self) -> None:
            self.register_app(
                context.ASSIGNMENT_CREATION_APP_ENDPOINT
            )


        def register_classrooms_app(self) -> None:
            self.register_app(
                context.CLASSROOMS_APP_ENDPOINT
            )


        def install_app(self, registration_endpoint: str) -> None:
            path_params = self.path.split('?')[1].split('&')
            path_params_tuple_list = [
                tuple(param.split('=')) for param in path_params
            ]
            path_params_dict = {
                name: value for (name, value) in path_params_tuple_list
            }

            state_string = path_params_dict['state']
            code = path_params_dict['code']

            if state_string != context.state_string:
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Error: State string doesn\'t match')
                return
            
            headers = {
                'X-GitHub-Api-Version': '2026-03-10',
                'Accept': 'application/vnd.github+json'
            }
            response = requests.post(
                f'https://api.github.com/app-manifests/{code}/conversions',
                headers=headers
            )

            if response.status_code < 200 or response.status_code >= 300:
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Error: Failed to finalize app registration')
                return

            response_json = response.json()

            app_id = response_json['id']
            client_id = response_json['client_id']
            client_secret = response_json['client_secret']
            private_key = response_json['pem']
            html_url = response_json['html_url']
            installation_url = f'{html_url}/installations/new'
            context.app_registration_responses[
                registration_endpoint
            ] = AppRegistrationResponse(
                app_id,
                client_id,
                client_secret,
                private_key,
                installation_url
            )

            html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Next action item: {context.APP_DETAILS[registration_endpoint].installation_instructions}</div><form id="manifest-form" action="{installation_url}" method="get">
<input type="submit" value="Click here to begin action item">
</form></div></body></html>
'''

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))

        def install_backend_workflow_dispatch_app(self) -> None:
            html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Next action item: {context.APP_DETAILS[context.WORKFLOW_DISPATCH_APP_ENDPOINT].installation_instructions}</div><form id="manifest-form" action="{context.config['workflow_dispatch_app_installation_url']}" method="get">
<input type="submit" value="Click here to begin action item">
</form></div></body></html>
'''

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))


        def install_classroom_setup_app(self) -> None:
            self.install_app(
                context.CLASSROOM_SETUP_APP_ENDPOINT
            )


        def install_assignment_creation_app(self) -> None:
            self.install_app(
                context.ASSIGNMENT_CREATION_APP_ENDPOINT
            )


        def install_classrooms_app(self) -> None:
            self.install_app(
                context.CLASSROOMS_APP_ENDPOINT
            )

        
        def get_installation_repository_access(
                self,
                installation_access_token: str,
                repository_selection: str)\
                -> list[Repository] | None:
            repositories = None
            if repository_selection == 'selected':
                headers = {
                    'X-GitHub-Api-Version': '2026-03-10',
                    'Accept': 'application/vnd.github+json',
                    'Authorization': f'Bearer {installation_access_token}'
                }
                response = requests.get(
                    f'https://api.github.com/installation/repositories',
                    headers=headers
                )

                if response.status_code < 200 or response.status_code >= 300:
                    raise ValueError(f'Got HTTP status code '
                        f'{response.status_code} when retrieving installation '
                        'repository access data')

                response_json = response.json()
                repositories = response_json['repositories']

            return repositories


        def get_installation_account(
                self,
                encoded_jwt: str,
                installation_id: str) -> str:
            headers = {
                'X-GitHub-Api-Version': '2026-03-10',
                'Accept': 'application/vnd.github+json',
                'Authorization': f'Bearer {encoded_jwt}'
            }
            response = requests.get(
                f'https://api.github.com/app/installations/{installation_id}',
                headers=headers
            )

            if response.status_code < 200 or response.status_code >= 300:
                raise ValueError(f'Got HTTP status code '
                    f'{response.status_code} when retrieving app installation '
                    'information')

            response_json = response.json()
            account: str = response_json['account']['login']
            return account


        def setup_app(
                self,
                registration_endpoint: str) -> None:
            path_params = self.path.split('?')[1].split('&')
            path_params_tuple_list = [
                tuple(param.split('=')) for param in path_params
            ]
            path_params_dict = {
                name: value for (name, value) in path_params_tuple_list
            }

            installation_id = str(path_params_dict['installation_id'])

            # Get installation access token and repository selection
            client_id = context.app_registration_responses[
                registration_endpoint
            ].client_id
            private_key = context.app_registration_responses[
                registration_endpoint
            ].private_key

            encoded_jwt = generate_and_sign_jwt(client_id, private_key)
            installation_access_token_data = get_installation_access_token(
                encoded_jwt,
                installation_id
            )
            installation_access_token = installation_access_token_data['token']
            repository_selection = \
                installation_access_token_data['repository_selection']
            
            # Verify that the installation belongs to the correct organization
            installation_account = \
                self.get_installation_account(
                    encoded_jwt,
                    installation_id
                )
            
            if installation_account != context.organization_name:
                # Installed on wrong account. Delete errant installation
                uninstall_app(encoded_jwt, installation_id)
                
                # Present error message and ask them to try again.
                installation_url = \
                    context.app_registration_responses[
                        registration_endpoint
                    ].installation_url
                html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Error: You installed the app on the wrong account. Your installation has been deleted. Please try again.</div><div style="margin-bottom: 1em">{context.APP_DETAILS[registration_endpoint].installation_instructions}</div><form id="manifest-form" action="{installation_url}" method="get">
    <input type="submit" value="Click here to begin action item">
    </form></div></body></html>
    '''

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
                return

            # Verify that the user configured the installation properly,
            # giving it access to the correct repositories
            repositories =\
                self.get_installation_repository_access(
                    installation_access_token,
                    repository_selection
                )
            verified = context.APP_DETAILS[registration_endpoint]\
                .installation_verifier(
                    repository_selection, repositories
                )

            if not verified:
                # Bad config. Tell user to reconfigure. They'll be redirected
                # here for another check when they do.
                html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Error: {context.APP_DETAILS[registration_endpoint].installation_configuration_error_message}</div><form id="manifest-form" action="{context.app_registration_responses[registration_endpoint].installation_url}" method="get">
    <input type="submit" value="Click here to reconfigure app installation">
    </form></div></body></html>
    '''

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
                return

            # Else, installation was configured properly. 
            context.app_installation_responses[
                    registration_endpoint
            ] = AppInstallationResponse(installation_id)

            next_endpoint = \
                context.APP_DETAILS[registration_endpoint]\
                    .next_endpoint
            if next_endpoint is None:
                # No more apps to register. Direct user to
                # close the browser window and return to their terminal.
                html=f'<html><head><meta http-equiv="Cache-Control" content="no-cache"/><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Browser flow complete. Please close this browser tab and return to your terminal.</div></div></body></html>'

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
            else:
                # Redirect user to next app registration endpoint
                self.send_response(302)
                self.send_header(
                    'Location',
                    f'/{next_endpoint}'
                )
                self.end_headers()
                self.wfile.write(b'')

            context.content_events[
                registration_endpoint
            ].set()


        def setup_classroom_setup_app(self) -> None:
            self.setup_app(
                context.CLASSROOM_SETUP_APP_ENDPOINT
            )


        def setup_backend_workflow_dispatch_app(self) -> None:
            path_params = self.path.split('?')[1].split('&')
            path_params_tuple_list = [
                tuple(param.split('=')) for param in path_params
            ]
            path_params_dict = {
                name: value for (name, value) in path_params_tuple_list
            }

            installation_id = str(path_params_dict['installation_id'])

            # Request auth server verify auth app installation
            headers = {
                'Accept': 'application/json',
            }
            response = requests.get(
                f'{context.config['auth_server']}/verify-installation?organization-name={context.organization_name}&installation-id={installation_id}',
                headers=headers
            )
            if response.status_code < 200 or response.status_code >= 300:
                # Bad installation ID or similar (somehow).
                html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">An unexpected error occurred. Please try again.</div><form id="manifest-form" action="{context.config['workflow_dispatch_app_installation_url']}" method="get">
    <input type="submit" value="Click here to install app">
    </form></div></body></html>
    '''

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
                return
            
            response_json = response.json()
            if response_json['status'] == 'bad-account':
                # Installed on wrong account
                html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Error: You installed the app on the wrong account. Please try again.</div><div style="margin-bottom: 1em">{context.APP_DETAILS[context.WORKFLOW_DISPATCH_APP_ENDPOINT].installation_instructions}</div><form id="manifest-form" action="{context.config['workflow_dispatch_app_installation_url']}" method="get">
<input type="submit" value="Click here to begin action item">
</form></div></body></html>
'''
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
                return
            elif response_json['status'] != 'verified':
                # Other configuration error (e.g., installed on wrong repositories)
                html=f'''<html><head><meta http-equiv="Cache-Control" content="no-cache"><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Please do not close this tab</div><div style="margin-bottom: 1em">Error: {context.APP_DETAILS[context.WORKFLOW_DISPATCH_APP_ENDPOINT].installation_configuration_error_message}</div><form id="manifest-form" action="{context.config['workflow_dispatch_app_installation_url']}" method="get">
    <input type="submit" value="Click here to reconfigure app installation">
    </form></div></body></html>
    '''

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
                return
            
            # Verified. Redirect to next app registration.
            next_endpoint = \
                context.APP_DETAILS[context.WORKFLOW_DISPATCH_APP_ENDPOINT]\
                    .next_endpoint
            if next_endpoint is None:
                # No more apps to register. Direct user to
                # close the browser window and return to their terminal.
                html=f'<html><head><meta http-equiv="Cache-Control" content="no-cache"/><meta charset="UTF-8"></head><body><div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center"><div style="margin-bottom: 1em">Browser flow complete. Please close this browser tab and return to your terminal.</div></div></body></html>'

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
            else:
                # Redirect user to next app registration endpoint
                self.send_response(302)
                self.send_header(
                    'Location',
                    f'/{next_endpoint}'
                )
                self.end_headers()
                self.wfile.write(b'')

            context.content_events[
                context.WORKFLOW_DISPATCH_APP_ENDPOINT
            ].set()


        def setup_assignment_creation_app(self) -> None:
            self.setup_app(
                context.ASSIGNMENT_CREATION_APP_ENDPOINT
            )


        def setup_classrooms_app(self) -> None:
            self.setup_app(
                context.CLASSROOMS_APP_ENDPOINT
            )
            

        path_handlers = {
            f'/{context.CLASSROOM_SETUP_APP_ENDPOINT}': \
                register_classroom_setup_app,
            f'/{context.CLASSROOM_SETUP_APP_ENDPOINT}/install': \
                install_classroom_setup_app,
            f'/{context.CLASSROOM_SETUP_APP_ENDPOINT}/setup': \
                setup_classroom_setup_app,
            f'/{context.WORKFLOW_DISPATCH_APP_ENDPOINT}/install': \
                install_backend_workflow_dispatch_app,
            f'/{context.WORKFLOW_DISPATCH_APP_ENDPOINT}/setup': \
                setup_backend_workflow_dispatch_app,
            f'/{context.ASSIGNMENT_CREATION_APP_ENDPOINT}': \
                register_assignment_creation_app,
            f'/{context.ASSIGNMENT_CREATION_APP_ENDPOINT}/install': \
                install_assignment_creation_app,
            f'/{context.ASSIGNMENT_CREATION_APP_ENDPOINT}/setup': \
                setup_assignment_creation_app,
            f'/{context.CLASSROOMS_APP_ENDPOINT}': \
                register_classrooms_app,
            f'/{context.CLASSROOMS_APP_ENDPOINT}/install': \
                install_classrooms_app,
            f'/{context.CLASSROOMS_APP_ENDPOINT}/setup': \
                setup_classrooms_app,
        }


        INITIATED_BROWSER_FLOW_MESSAGE = ('User has initiated browser flow')
        DO_NOT_EXIT_MESSAGE = ('Please do not exit your browser until '
            'the browser flow is completed. If you accidentally exit out of '
            'a page, refer to the bottom-most log message below for the '
            'address of your most recently visited page')


        def do_GET(self) -> None:
            # Remove query parameters and trailing / from path
            paramless_path = self.path.split('?')[0]
            if paramless_path[-1] == '/':
                paramless_path = paramless_path[:-1]

            # Find path handler and execute, else send 404
            if paramless_path in Handler.path_handlers:
                if not context.first_visit:
                    context.first_visit = True
                    console.clear()
                    console.log(Handler.INITIATED_BROWSER_FLOW_MESSAGE)
                    rprint()
                    rprint_wrapped(Handler.DO_NOT_EXIT_MESSAGE)
                    rprint()
                
                console.log(f'User visited localhost address: '
                    f'http://localhost:{context.server_port}{self.path}')
                Handler.path_handlers[paramless_path](self)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'')

        def log_message(self, format: str, *args: typing.Any) -> None:
            pass # Hides default status messages

    return Handler


class ServerState:
    ready_event: threading.Event
    context: HandlerContext
    server: NotifyingServer | None
    up: bool
    
    def __init__(self, context: HandlerContext) -> None:
        self.ready_event = threading.Event()
        self.context = context
        self.server = None
        self.up = False


PORT = 51423


def start_server_thread_entry(server_state: ServerState) -> None:
    served = False
    try:
        server_state.context.server_port = PORT
        server = NotifyingServer(
            ('localhost', PORT),
            get_handler_class(server_state.context),
            server_state
        )
        server_state.server = server
        server.serve_forever()
        served = True
    except OSError:
        server_state.context.server_port = None
        server_state.server = None

    if not served:
        server_state.ready_event.set()


START_SERVER_ERROR_MESSAGE = (
    f'Error: Failed to start server. Make sure there\'s an open '
    f'port in the range [{MIN_PORT}, {MAX_PORT}] that isn\'t blocked by '
    f'firewall rules.'
)


def start_server(server_state: ServerState) -> threading.Thread:
    server_thread = threading.Thread(
        target=start_server_thread_entry,
        args=(server_state,)
    )
    server_thread.start()
    server_state.ready_event.wait()
    return server_thread


BROWSER_FLOW_MESSAGE_1 = (
    'Next, your organization will need three private GitHub Apps '
    'for, respectively:\n'
    '- (temporary) automating most of the operations in this setup tool '
    '(note: this app will uninstall itself once your classroom is fully set '
    'up)\n'
    '- reading configurations and assignment templates\n'
    '- creating and administering student assignment repositories\n\n'
    'These apps will be registered from respective preconfigured manifests, '
    'but the registration and installation requires your approval via '
    'GitHub\'s web UI.\n\n'
    'In addition, the FooBar Projects Backend Workflows app must be '
    'installed in your organization.\n\n'
    'Follow the below link to begin the app registration flow.'
)


def start_browser_flow(
        handler_context: HandlerContext) \
        -> tuple[ServerState, threading.Thread]:
    server_state = ServerState(
        handler_context
    )
    server_thread = start_server(server_state)
    if not server_state.up:
        rprint_wrapped(START_SERVER_ERROR_MESSAGE, style='bold red')
        raise OSError('Failed to start server')

    console.log(
        f'Local webserver for browser operations '
        f'running on port {server_state.context.server_port}'
    )
    rprint()

    rprint_wrapped(BROWSER_FLOW_MESSAGE_1)
    rprint()
    rprint(f'http://localhost:'
        f'{server_state.context.server_port}/'
        f'{server_state.context.CLASSROOM_SETUP_APP_ENDPOINT}')

    return server_state, server_thread

def wait_for_browser_flow_finish(
        server_state: ServerState,
        server_thread: threading.Thread) -> None:
    for _, event in server_state.context.content_events.items():
        event.wait()

    # User has finished browser flow
    
    if server_state.server is not None:
        server_state.server.shutdown() # Tells server loop to stop
        server_state.server.server_close() # Releases network resources
        try:
            # Dummy request to break server loop if necessary
            requests.get(f'http://localhost:{server_state.context.server_port}')
        except Exception:
            pass

    server_thread.join()


class RepositoryInputData:
    description: str
    private: bool
    additional_relative_file_paths: list[str]

    def __init__(
            self,
            description: str,
            private: bool,
            additional_relative_file_paths: list[str] | None = None) -> None:
        if additional_relative_file_paths is None:
            additional_relative_file_paths = []

        self.description = description
        self.private = private
        self.additional_relative_file_paths = additional_relative_file_paths


ALL_REPOSITORY_INPUT_DATA = {
    'backend-workflows': RepositoryInputData(
        description=('This repository strictly '
            'contains backend workflows dispatched by the web frontend '
            '(e.g., to authenticate students, accept assignments, etc).'),
        private=False
    ),
    'classrooms': RepositoryInputData(
        description=('This repository contains '
            'assignment configuration files as well as assignment templates '
            '(starter code) '
            'that are copied into students\' assignment repositories '
            'upon creation (assignment acceptance).'),
        private=True
    ),
}


def create_repository(
        organization_name: str,
        classroom_setup_token: str,
        repository_name: str,
        input_data: RepositoryInputData) -> RepositoryCreationData:
    attempt = 0
    while attempt < MAX_API_ATTEMPTS:
        attempt += 1
        headers = {
            'X-GitHub-Api-Version': '2026-03-10',
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {classroom_setup_token}'
        }
        
        # Check if repo already exists.
        response = requests.get(
            f'https://api.github.com/repos/{organization_name}/{repository_name}',
            headers=headers
        )
        if response.status_code == 200:
            # Repo exists. Return info.
            response_json = response.json()
            return RepositoryCreationData(
                response_json['id'],
                response_json['html_url']
            )

        # Repo doesn't exist. Create it.
        body = {
            'name': repository_name,
            'private': input_data.private,
            'description': input_data.description
        }
        response = requests.post(
            f'https://api.github.com/orgs/{organization_name}/repos',
            headers=headers,
            json=body
        )

        if (response.status_code < 200 or response.status_code >= 300):
            if attempt < MAX_API_ATTEMPTS:
                print(f'Failed to create repository {repository_name}; got '
                    f'HTTP status code {response.status_code}. Trying '
                    f'again in {API_REATTEMPT_WAIT_INTERVAL} seconds...')
            else:
                raise ValueError(f'Failed to create repository '
                    f'{repository_name}; got '
                    f'HTTP status code {response.status_code}')
        else:
            response_json = response.json()
            return RepositoryCreationData(
                response_json['id'],
                response_json['html_url']
            )
        
        time.sleep(API_REATTEMPT_WAIT_INTERVAL)

    raise ValueError(f'Failed to create repository {repository_name}.')


def create_repositories(
        organization_name: str,
        classroom_setup_token: str)\
        -> dict[str, RepositoryCreationData]:
    result = {}
    for repository_name, input_data in ALL_REPOSITORY_INPUT_DATA.items():
        console.log(f'Creating repository "{repository_name}" in organization '
            f'"{organization_name}"...')
        result[repository_name] = create_repository(
            organization_name,
            classroom_setup_token,
            repository_name,
            input_data
        )

    return result


def gen_classroom_keys() -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialize private key in PKCS8 format (DER / binary encoding, then b64
    # encode; basically PEM without the delimiters)
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_b64 = b64encode(private_key_der).decode('utf-8')

    # Serialize public key in SPKI format (DER / binary encoding, then b64
    # encode)
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = b64encode(public_key_der).decode('utf-8')

    return private_key_b64, public_key_b64


def create_repository_variable(
        organization_name: str,
        classroom_setup_token: str,
        repository_name: str,
        variable_name: str,
        variable_value: str) -> None:
    headers = {
        'X-GitHub-Api-Version': '2026-03-10',
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {classroom_setup_token}'
    }
    body = {
        'name': variable_name,
        'value': variable_value
    }
    response = requests.post(
        (f'https://api.github.com/repos/'
            f'{organization_name}/{repository_name}/actions/variables'),
        headers=headers,
        json=body
    )

    if response.status_code == 409:
        # Variable already exists. Update it.
        response = requests.patch(
            (f'https://api.github.com/repos/{organization_name}/'
                f'{repository_name}/actions/variables/{variable_name}'),
            headers=headers,
            json=body
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f'Got HTTP status code {response.status_code} '
                f'when updating repository variable')
    elif response.status_code < 200 or response.status_code >= 300:
        # 201 means created, 409 means already exists (conflict). Anything else
        # is an unexpected error.
        raise ValueError(f'Got HTTP status code {response.status_code} when '
            f'creating repository variable')


def create_repository_variables(
        organization_name: str,
        handler_context: HandlerContext,
        classroom_rsa_public_key: str) -> None:
    all_variables = {
        'backend-workflows': [
            ('STUDENT_ASSIGNMENT_ORGANIZATION', organization_name),
            ('CLASSROOMS_REPO',
                f'github.com/{organization_name}/classrooms.git'),
            ('ASSIGNMENT_CREATION_APP_ID',
                handler_context.app_registration_responses[
                    handler_context.ASSIGNMENT_CREATION_APP_ENDPOINT
                ].client_id),
            ('ASSIGNMENT_CREATION_APP_INSTALLATION_ID',
                handler_context.app_installation_responses[
                    handler_context.ASSIGNMENT_CREATION_APP_ENDPOINT
                ].installation_id),
            ('CLASSROOMS_APP_ID',
                handler_context.app_registration_responses[
                    handler_context.CLASSROOMS_APP_ENDPOINT
                ].client_id),
            ('CLASSROOMS_APP_INSTALLATION_ID',
                handler_context.app_installation_responses[
                    handler_context.CLASSROOMS_APP_ENDPOINT
                ].installation_id),
            ('CLASSROOM_RSA_PUBLIC_KEY', classroom_rsa_public_key),
        ],
    }
    
    assert handler_context.classroom_setup_token is not None
    for repository, variables in all_variables.items():
        for name, value in variables:
            console.log(f'Creating repository variable {name}={value}...')
            create_repository_variable(
                organization_name,
                handler_context.classroom_setup_token,
                repository,
                name,
                value
            )


def get_repository_public_key(
        organization_name: str,
        repository_name: str,
        classroom_setup_token: str)\
        -> tuple[public.PublicKey, str]:
    headers = {
        'X-GitHub-Api-Version': '2026-03-10',
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {classroom_setup_token}'
    }
    response = requests.get(
        (f'https://api.github.com/repos/{organization_name}/'
            f'{repository_name}/actions/secrets/public-key'),
        headers=headers
    )
    
    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError(f'Got HTTP status code {response.status_code} when '
            f'retrieving repository public key')

    response_json = response.json()
    public_key = public.PublicKey(
        response_json['key'].encode("utf-8"),
        encoding.Base64Encoder() # type: ignore
    )
    return public_key, response_json['key_id']


def encrypt(public_key: public.PublicKey, plaintext: str) -> str:
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(plaintext.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def create_repository_secret(
        organization_name: str,
        classroom_setup_token: str,
        repository_name: str,
        secret_name: str,
        secret_value: str,
        public_key: public.PublicKey,
        key_id: str) -> None:
    encrypted_value = encrypt(public_key, secret_value)
    headers = {
        'X-GitHub-Api-Version': '2026-03-10',
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {classroom_setup_token}'
    }
    body = {
        'encrypted_value': encrypted_value,
        'key_id': key_id
    }
    response = requests.put(
        (f'https://api.github.com/repos/{organization_name}/'
            f'{repository_name}/actions/secrets/{secret_name}'),
        headers=headers,
        json=body
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise ValueError(f'Got HTTP status code {response.status_code} when '
            f'creating repository secret')


def create_repository_secrets(
        organization_name: str,
        handler_context: HandlerContext,
        classroom_rsa_private_key: str) -> None:
    all_secrets = {
        'backend-workflows': [
            ('ASSIGNMENT_CREATION_APP_PRIVATE_KEY',
                handler_context.app_registration_responses[
                    handler_context.ASSIGNMENT_CREATION_APP_ENDPOINT
                ].private_key),
            ('CLASSROOMS_APP_PRIVATE_KEY',
                handler_context.app_registration_responses[
                    handler_context.CLASSROOMS_APP_ENDPOINT
                ].private_key),
            ('CLASSROOM_RSA_PRIVATE_KEY', classroom_rsa_private_key),
        ],
    }
    
    assert handler_context.classroom_setup_token is not None
    for repository, secrets in all_secrets.items():
        public_key, key_id = get_repository_public_key(
            organization_name,
            repository,
            handler_context.classroom_setup_token
        )
        for name, value in secrets:
            console.log(f'Creating repository secret {name}...')
            create_repository_secret(
                organization_name,
                handler_context.classroom_setup_token,
                repository,
                name,
                value,
                public_key,
                key_id
            )


def populate_repository(
        organization_name: str,
        classroom_setup_token: str,
        repository_name: str,
        additional_relative_file_paths: list[str]) -> None:
    # Find this repo's root directory (closest ancestor containing .git
    # directory), falling back to this script's grandparent if .git isn't found
    base_src_dir_path = Path(__file__).resolve().parent
    while not (base_src_dir_path / '.git').is_dir():
        abs_path = base_src_dir_path.resolve()
        if abs_path == abs_path.parent:
            # Navigated to root dir. No more ancestors to navigate. Default to
            # this script's grandparent.
            base_src_dir_path = Path(__file__).resolve().parent.parent
            console.log(f'Failed to ascertain this repository\'s root '
                f'directory (perhaps .git folder is missing?). Falling '
                f'back to {base_src_dir_path}')
            break
        
        # More ancestors to navigate. Keep going.
        base_src_dir_path = base_src_dir_path.parent

    # Create temp directory to house local repo contents
    with tempfile.TemporaryDirectory() as base_dst_dir_path_str:
        base_dst_dir_path = Path(base_dst_dir_path_str)
        
        # Set working directory to tmp directory
        with chdir(base_dst_dir_path):
            # Clone git repository
            remote_repo_git_url = (
                f'https://x-access-token:'
                f'{classroom_setup_token}@github.com/'
                f'{organization_name}/{repository_name}.git'
            )
            subprocess.run(
                ['git', 'clone', remote_repo_git_url,
                    str(base_dst_dir_path.resolve())],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Git config
            subprocess.run(
                ['git', 'config', 'user.name', 'Classroom Config'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ['git', 'config', 'user.email', '<>'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Copy primary repo contents into repo, merging with existing
            # contents
            primary_repo_content_dir_path = base_src_dir_path / repository_name
            for complete_src_file_path in \
                    primary_repo_content_dir_path.iterdir():
                # Compute dst file path
                relative_file_path =\
                    complete_src_file_path.relative_to(
                        primary_repo_content_dir_path
                    )
                complete_dst_file_path =\
                        base_dst_dir_path / relative_file_path

                # Copy file / directory
                if complete_src_file_path.is_file():
                    shutil.copy(
                        complete_src_file_path,
                        complete_dst_file_path
                    )
                elif complete_src_file_path.is_dir():
                    shutil.copytree(
                        complete_src_file_path,
                        complete_dst_file_path,
                        dirs_exist_ok=True
                    )
            
            # Copy additional / secondary / shared contents into local repo,
            # merging with existing contents
            for relative_file_path_str in additional_relative_file_paths:
                # Compute complete src and dst file paths
                relative_file_path = Path(relative_file_path_str)
                complete_src_file_path = base_src_dir_path / relative_file_path
                complete_dst_file_path = base_dst_dir_path /\
                    relative_file_path

                # Create parent directory within temp directory to house copy
                complete_dst_file_path.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                # Copy file / directory
                if complete_src_file_path.is_file():
                    shutil.copy(
                        complete_src_file_path,
                        complete_dst_file_path
                    )
                elif complete_src_file_path.is_dir():
                    shutil.copytree(
                        complete_src_file_path,
                        complete_dst_file_path,
                        dirs_exist_ok=True
                    )

            # Stage all updated files
            subprocess.run(
                ['git', 'add', '-A'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Create commit
            subprocess.run(
                ['git', 'commit', '-m', 'Classroom Config: Init'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Push upstream
            subprocess.run(
                ['git', 'push', remote_repo_git_url, 'main'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )


def populate_repositories(
        organization_name: str,
        classroom_setup_token: str) -> None:
    for repository_name, input_data in ALL_REPOSITORY_INPUT_DATA.items():
        console.log(f'Populating GitHub repository '
            f'"{organization_name}/{repository_name}"')
        populate_repository(
            organization_name,
            classroom_setup_token,
            repository_name,
            input_data.additional_relative_file_paths
        )


def harden_organization(
        organization_name: str,
        classroom_setup_token: str) -> None:
    rprint_wrapped('By default, all members of a GitHub organization can '
        'directly create repositories within the organization. In most '
        'cases, this is unnecessary for students since their assignment '
        'repositories are system-generated.')
    rprint()

    valid_input = False
    harden = True
    while not valid_input:
        user_input = input('Would you like to disable the ability for '
            'organization members to create repositories? [Y|n]: ')
        user_input = user_input.strip().lower()

        if user_input == '' or user_input == 'y':
            valid_input = True
            harden = True
        elif user_input == 'n':
            valid_input = True
            harden = False
        else:
            rprint()
            rprint_wrapped('Error: Invalid Input', style='bold red')
            rprint()
    
    if harden:
        headers = {
            'X-GitHub-Api-Version': '2026-03-10',
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {classroom_setup_token}'
        }
        body = {
                'members_can_create_repositories': False,
                'members_can_fork_private_repositories': False,
        }
        response = requests.patch(
            f'https://api.github.com/orgs/{organization_name}',
            headers=headers,
            json=body
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f'Got HTTP status code {response.status_code} '
                f'when hardening organization')
        

def exit_notes(organization_name: str) -> None:
    rprint_wrapped('Automated configuration complete.')
    rprint()
    rprint_wrapped(f'You can now create assignments and configure your '
        f'classroom within your '
        f'organization\'s "classrooms" repository:')
    rprint()
    rprint(f'https://github.com/{organization_name}/classrooms')
    rprint()
    rprint_wrapped(f'See the above repository\'s README.md for more '
        f'information.')

    rprint()

    rprint_wrapped(f'Your classroom is ready to go, but it\'s recommended '
        'that you manually complete some final organization hardening '
        'measures. On the webpage linked below, '
        'set "Projects base permissions" to "No access" and disable app '
        'access requests. If you intend to grant students admin access to '
        'one or more of their assignment repositories, additionally '
        'disable "Allow repository admins to install GitHub apps for their '
        'repositories", and disable all destructive admin repository '
        'permissions (visibility change, deletion and transfer, issue '
        'deletion, and branch renames).')
    rprint()
    rprint(f'https://github.com/organizations/{organization_name}/settings/member_privileges')

def main() -> int:
    with open('create-classroom.conf', 'r') as f:
        config = yaml.safe_load(f)

    console.clear()
    greet()

    organization_name = request_organization_name()

    console.clear()
    handler_context = HandlerContext(
        organization_name,
        config
    )
    server_state, server_thread = start_browser_flow(handler_context)

    handler_context.content_events[
        handler_context.CLASSROOM_SETUP_APP_ENDPOINT
    ].wait()

    encoded_jwt = generate_and_sign_jwt(
        handler_context.app_registration_responses[
            handler_context.CLASSROOM_SETUP_APP_ENDPOINT
        ].client_id,
        handler_context.app_registration_responses[
            handler_context.CLASSROOM_SETUP_APP_ENDPOINT
        ].private_key
    )
    handler_context.classroom_setup_token = \
        get_installation_access_token(
            encoded_jwt,
            handler_context.app_installation_responses[
                handler_context.CLASSROOM_SETUP_APP_ENDPOINT
            ].installation_id
        )['token']

    all_repository_creation_data = create_repositories(
        organization_name,
        handler_context.classroom_setup_token
    )

    handler_context.repositories_created_event.set()

    wait_for_browser_flow_finish(server_state, server_thread)

    console.clear()
    
    classroom_rsa_private_key, classroom_rsa_public_key = gen_classroom_keys()
    create_repository_variables(
        organization_name,
        handler_context,
        classroom_rsa_public_key
    )
    create_repository_secrets(
        organization_name,
        handler_context,
        classroom_rsa_private_key
    )
    populate_repositories(
        organization_name,
        handler_context.classroom_setup_token
    )

    console.clear()

    harden_organization(
        organization_name,
        handler_context.classroom_setup_token
    )
    
    uninstall_app(
        encoded_jwt,
        handler_context.app_installation_responses[
            handler_context.CLASSROOM_SETUP_APP_ENDPOINT
        ].installation_id
    )

    console.clear()

    exit_notes(organization_name)

    return 0

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
