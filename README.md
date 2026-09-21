# Disclaimer

This repository is a WIP. It's not ready for production deployments yet.

# FooBar Projects

FooBar Projects is a free and open-source, lightweight, **self-hosted** (serverless) replacement for GitHub Classroom. It distributes programming assignments to students while keeping all the data under the ownership of the instructor.

All data is stored, and backend operations are performed, within repositories under the classroom's GitHub Organization. The organization does not require a paid plan; an organization on a GitHub Free plan is sufficient. 

## Backends

Currently, the only available backend is the GitHub Actions backend. If using this backend, whenever a student accepts an assignment, a GitHub Actions workflow is dipsatched to generate their assignment repository. This is quite slow and ventures into a gray area of the GitHub Actions service usage limitations.

An alternative Serverless Cloud Function backend is currently under development. When complete, it will be the primary backend of choice. It will require a Google Cloud Platform account and the `gcloud` CLI.

## Setting up a classroom organization

To set up a new classroom organization:

1. Clone this repository onto a system with an internet browser.
2. Install `python` and `pip` on your system (`python` usually ships with `pip`, except in some Linux distributions)
3. (Optional) Create a virtual environment in which to install the configuration tool's dependencies (e.g., `python -m venv classroom-env && source classroom-env/bin/activate`)
4. Navigate to the `config-tools` directory and install the config tool dependencies via `python -m pip install .`
5. Run the classroom setup script via `python create_classroom.py`
6. Follow the on-screen instructions.\
\
   You'll be asked to create a GitHub Organization for your classroom. You'll then be asked to navigate to a webpage hosted locally by the classroom setup tool that will guide you through registering and installing several GitHub Apps in your organization. These operations cannot be fully automated via the GitHub API, hence why they require your manual intervention in a browser.

Once the classroom setup script has finished, your organization should be populated with two repositories:
- `classrooms`: This is where you'll configure your classroom and assignments, including assignment templates (e.g., starter code and instructions documents) that will be instantiated to create students' assignment repositories. `classrooms` is a private repository; students cannot view it.
- `backend-workflows`. This repository hosts GitHub Actions workflows for student-facing operations, such as accepting assignments. In essence, this repository is your classroom's serverless backend. It's a public repository, and students' user access tokens can write issues, read contents, and read workflow run artifacts in this repository to conduct backend operations. You generally shouldn't need to modify anything in this repository.

## Administration (configuring the classroom, creating assignments, etc)

A classroom's configuration, assignment configurations, and assignment templates are all stored in the organization's `classrooms` repository. When your `classrooms` repository is generated (by following the above steps), it ships with a `README.md` file explaining how to administer the classroom (reconfigure the classroom and assignments, create new assignments, etc). It also explains how students accept assignments. [Here's](classrooms/README.md) a copy of that `README.md` file.

## Self-hosted runners

If using the (not-recommended) GitHub Actions backend, which resides in a gray area of the GitHub Actions service usage limitations, it's imperative to at least set up one or more self-hosted runners with the `ubuntu-latest` label. This will offload most of the backend's compute and network resources away from GitHub's cloud-hosted runners and onto your own. It may also reduce workflow pending times and, depending on your self-hosted runners' configuration, execution times (e.g., by pre-installing all necessary packages).

See [the GitHub docs](https://docs.github.com/en/actions/concepts/runners/self-hosted-runners) for more information on how to configure self-hosted runners.

## Comparison with Classroom 50

[Classroom 50](https://classroom50.org/) is another free, open-source replacement for GitHub Classroom. It's an extensive, feature-rich platform with both web UI and CLI frontends. Similar to FooBar Projects, all its major operations are run entirely within GitHub organizations and repositories (e.g., by making calls to the GitHub REST api, or via its `gh` CLI extensions).

However, Classroom 50 and FooBar Projects differ significantly in how they handle "backend" operations, particularly in accepting assignments.

In Classroom 50, students are added to the classroom organization and then assigned to the student team, which is in turn given access to essential classroom resources like private assignment template repositories. All student operations are then authorized directly by the student's user access token acquired via an OAuth flow. The advantage of this design is that it doesn't require a backend for most operations (save a small central proxy server for completing the OAuth flow in the web UI). However, there are also several downsides to this design:

- It reduces the instructor's control over when and how assignment templates are viewed: the moment an assignment is added and its template registered, all students in the classroom's student team are simultaneously granted read access to its template (e.g., in the GitHub web UI), with or without an explicit assignment accept link. This makes it difficult to, say, make a lab exercise available to different students at different times depending on their lab sections. 
- Students must be added to the classroom's GitHub Organization in order to be a part of the student team and accept assignments.
- Students are generally given admin access to their assignment repositories since their user access tokens are used to create them (though, the permissions of a repository admin can be adjusted as a part of organization hardening).
- In general, certain features (e.g., those requiring authorization by protected secrets) are simply impossible to implement without a programmable backend, hence the above limitations.

GitHub Classroom avoided these issues by hiding privileged operations behind a central backend. FooBar Projects's design philosophy is similar to GitHub Classroom's in this regard, but there are [multiple options for backends](#backends), and they're all serverless (e.g., cloud functions or GitHub Actions workflows) and self-hosted. The choice of backend is decided when creating the classroom via `create_classroom.py`, which automates the backend's deployment.

One final difference between Classroom 50 and FooBar Projects is that Classroom 50 requires a GitHub Organization on a Team or Enterprise plan, whereas FooBar Projects works with Free plans as well. However, if you're using an organization with a Free plan, you won't be able to configure branch protection rules or push rulesets in students' assignment repositories, and you'll be restricted to 2,000 Actions minutes per month if using GitHub-hosted runners.

## Auth proxy server

Although FooBar Projects is mostly serverless, there's a small central proxy server that's used to conduct the OAuth flow. This is necessary since GitHub's OAuth web flow does not support public OAuth clients&mdash;only confidential clients&mdash;so a privileged server is required to manage the client secret. The server also verifies the installation of the central workflow dispatch app when setting up a new classroom organization.

The auth proxy server's source code is available [here](auth-server/). It's possible for an instructor to host their own instance of the auth proxy server, but it requires a domain name, SSL certificates, a machine on which to host the server, and additional configuration.

Note that a student's OAuth access tokens, retrieved and cached by the central auth proxy server, only have the necessary and sufficient permissions to write issues, read GitHub Actions resources, and read repository contents, and only within repositories on which the workflow dispatch app is installed (i.e., classrooms' `backend-workflows` repositories). In other words, although students' access tokens are handled centrally, these tokens do not have access to students' personal resources, and they're extremely limited in what they can do.

## Troubleshooting and FAQ

- **Issue**: A student tries to accept an assignment and is met with this error message: `Repository already exists but somehow belongs to a different student [...] Instructor intervention is required.`\
\
**Explanation**: Students' GitHub usernames are used to name and identify their assignment repositories. However, GitHub usernames are mutable. If a student changes their GitHub username, and then another student happens to change their username to the previous username of the first student, the second student should not be given access to the first student's assignment repositories upon attempting to accept assignments. To ensure that's the case, when an assignment repository is first created, it's given a `STUDENT_ID` Actions variable storing the (immutable) GitHub ID of the student who generated it. This variable is used as a second layer of verification in subsequent attempts to accept the assignment (e.g., if the student accidentally lets their first invite expire and must reaccept it). If this second verification fails, either because students' GitHub usernames have changed or because the `STUDENT_ID` repository variable was accidentally modified, then the student will be met with the above error message when attempting to accept the assignment.\
\
**Solution**: Find the assignment repository by searching for it in the GitHub web UI. Its name should follow the pattern `<ASSIGNMENT NAME>-<STUDENT GITHUB USERNAME>`. Communicate with the student and determine whether the repository actually belongs to them. If so, navigate to the repository's settings &rarr; Secrets and variables &rarr; Actions &rarr; Variables tab &rarr; delete the `STUDENT_ID` repository variable; it will be regenerated correctly next time the student tries to accept the assignment. In the unlikely event that the repository *doesn't* belong to this student (but rather to a past student who happened to have the same GitHub username at one point), simply rename the repository to something unique&mdash;that will avoid the naming conflict next time the student tries to accept the assignment.
