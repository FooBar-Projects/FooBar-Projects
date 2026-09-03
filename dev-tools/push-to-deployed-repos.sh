#!/bin/bash

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "$script_dir/.env"

if [[ "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR" != "" ]]
then
	read -p "About to reset contents of $DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR. Press enter to continue, or CTRL+C to cancel."
	
	mkdir -p "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR"
	tmp_dir="/tmp/classroom-dev-tools/"
	rm -rf "$tmp_dir"
	mkdir -p "$tmp_dir"
	mv "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR/.git" "$tmp_dir"
	mv "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR/CLASSROOM_RSA_PUBLIC_KEY.der" "$tmp_dir"
	find "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR" -mindepth 1 -delete
	mv "$tmp_dir/.git" "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR"
	mv "$tmp_dir/CLASSROOM_RSA_PUBLIC_KEY.der" "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR"

	cp -a "$script_dir/../backend-workflows"/. "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR"
	(
		cd "$DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR"
		git add -A
		git commit -m "Update"
		git push
	)
else
	echo "DEPLOYED_BACKEND_WORKFLOWS_REPO_DIR not defined in .env. Skipping."
fi

if [[ "$DEPLOYED_CLASSROOMS_REPO_DIR" != "" ]]
then
	read -p "About to reset contents of $DEPLOYED_CLASSROOMS_REPO_DIR. Press enter to continue, or CTRL+C to cancel."
	
	mkdir -p "$DEPLOYED_CLASSROOMS_REPO_DIR"
	tmp_dir="/tmp/classroom-dev-tools/"
	rm -rf "$tmp_dir"
	mkdir -p "$tmp_dir"
	mv "$DEPLOYED_CLASSROOMS_REPO_DIR/.git" "$tmp_dir"
	find "$DEPLOYED_CLASSROOMS_REPO_DIR" -mindepth 1 -delete
	mv "$tmp_dir/.git" "$DEPLOYED_CLASSROOMS_REPO_DIR"

	cp -a "$script_dir/../classrooms"/. "$DEPLOYED_CLASSROOMS_REPO_DIR"
	(
		cd "$DEPLOYED_CLASSROOMS_REPO_DIR"
		git add -A
		git commit -m "Update"
		git push
	)
else
	echo "DEPLOYED_CLASSROOMS_REPO_DIR not defined in .env. Skipping."
fi
