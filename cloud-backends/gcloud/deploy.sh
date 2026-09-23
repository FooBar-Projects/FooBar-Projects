#!/bin/bash

if ! command -v gcloud &>/dev/null
then
	echo "Error: Command 'gcloud' not found. Make sure that the Google Cloud CLI is installed on your system." >&2
	exit 1
fi

cur_account=$(gcloud config get-value account 2>/dev/null)
if [[ "$cur_account" == "" ]]
then
	echo "Error: Not logged into gcloud. Login via 'gcloud auth login'"
	exit 1
fi

cur_project=$(gcloud config get-value project 2>/dev/null)
if [[ "$cur_project" == "" ]]
then
	echo "Error: Project not set in gcloud. Set project via 'gcloud config set project <project id>'. You can view your projects via 'gcloud projects list'"
	exit 1
fi

gcloud functions deploy foobar-projects-backend \
  --gen2 \
  --runtime=go127 \
  --region=us-west1 \
  --entry-point=Backend \
  --trigger-http \
  --allow-unauthenticated \
  --env-vars-file=env.yaml \
  --memory=2Gi \
  --cpu=1

res=$?
if [[ "$res" != 0 ]]
then
	exit "$res"
fi
