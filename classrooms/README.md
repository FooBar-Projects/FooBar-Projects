# Classrooms

This is your classroom's administrative repository. It stores the classroom's configuration, assignment configurations, and assignment templates. To reconfigure the classroom or an assignment, or to create a new assignment, you must modify the contents of this repository accordingly.

## Creating assignments

Assignments are created by manually editing the contents of the `assignments/` directory within this repository. To create an assignment, do one or both of the following:

- In the `assignments/` directory, create a subdirectory for the assignment and populate it with the assignment's template contents (`README.md`, starter code, etc). Note: The name of an assignment's template subdirectory is the name of the assignment itself; assignment names should consist only of alphanumeric characters (`a-z`, `A-Z`, `0-9`), hyphens (`-`), underscores (`_`), and / or periods (`.`).
- In `assignments/assignments.conf`, create a new entry for the assignment. `assignments.conf` is a [YAML](https://yaml.org/) file consisting of a list of assignment objects. Each entry (assignment object) may have the following fields:
  - (Required) `name`: The assignment's name. If the assignment has a template directory (as explained in the previous bullet point), this field's value must **exactly** match the name of the assignment's template directory (case-sensitive match).
  - (Optional) `key`: The secret string of characters required to accept the assignment. Think of it as a password. To generate a link through which students can accept the assignment, the assignment's accept key must be embedded in the link as a query parameter (see below). If this field is omitted, then the assignment will have no accept key, and it can be accepted by anyone who knows (or can guess) the assignment's name.
  - (Optional) `student_role`: The role that the student should be given for their assignment repository when they accept the assignment. Must be one of `push`, `maintain`, `admin`, `pull`, or `triage`. If omitted, defaults to `push`. `push` is recommended for individual assignments; `maintain` is recommend for group assignments so that students can invite each other to their repositories as collaborators. See [here](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization) for an explanation of all repository roles; note that `push` corresponds to "Write", and `pull` corresponds to "Read" in the documentation.

If an assignment has a template directory but no entry in `assignments.conf`, its configuration fields will take on the default values (e.g., it will have no accept key, its `student_role` field will default to `push`, and so on). An assignment with an entry in `assignments.conf` but no template directory will have no starter contents&mdash;when students accept the assignment, their repository will be empty with no commits.

This repository ships with some example assignment configurations.

## Accepting an assignment

Whenever a new commit is pushed to this repository (e.g., to create a new assignment), [the Generate Assignment Links workflow](.github/workflows/gen-assignment-links.yml) will automatically generate a release in this repository with release notes providing the **accept links** of all assignments. You can see the latest release notes at any time by navigating to the latest release page via the navigation bar on the right of this repository's main page.

Alternatively, you can construct an assignment accept link yourself. Each accept link matches the following pattern:

`https://<ORGANIZATION NAME>.github.io/web/?assignment-name=<ASSIGNMENT NAME>&assignment-accept-key=<ASSIGNMENT ACCEPT KEY>`

Replace `<ORGANIZATION NAME>` with the name of the classroom's GitHub Organization, replace `<ASSIGNMENT NAME>` with the (case-sensitive) name of the assignment, and replace `<ASSIGNMENT ACCEPT KEY>` with the assignment's accept key. If the assignment has no accept key, then the `&assignment-accept-key=<ASSIGNMENT ACCEPT KEY>` part of the link can be omitted.

For example: 

`https://example-classroom-organization.github.io/web/?assignment-name=assignment-1-hello-world&assignment-accept-key=secret-assignment-1-password`

When a student navigates to an assignment's accept link (given to them at the instructor's discretion), it 1) asks the student to log into GitHub if they aren't already logged in; 2) asks them to authorize the classroom's Workflow Dispatch App if they haven't already done so (so that it can verify their identity, retrieve their username, and send them invites&mdash;it is **not** granted access to their personal GitHub resources); 3) creates a new repository owned by the classroom organization with the naming scheme `<ASSIGNMENT NAME>-<STUDENT USERNAME>`; 4) populates it with the assignment's template contents, if any; 5) sends the student an invite to the repository with the role specified by the `student_role` field in `assignments/assignments.conf`; and 6) redirects the student to the repository's main page, which will prompt them to accept the aforementioned invite.
