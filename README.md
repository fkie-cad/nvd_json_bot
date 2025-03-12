# nvd_json_bot

A python bot that uses the NVD [CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) to sync vulnerability data into a git repository. The CVE records remain untouched.

This bot manages the data you can find at [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds).

## How it works

The bot is designed to run as periodic execution service (cron, systemd, ...). Data processing steps are implemented as isolated subcommands that can be executed at different points in time:

1. `sync_nvd`: Pull data changes from the NVD API and write them into a local OpenSearch index. `last_modified` is the CVE timestamp that designates whether or not a CVE is being updated.
2. `update_git_repo`: Write all CVE data cached from the OpenSearch index into a local git repository and push changed objects to remote.
3. `release_git_package`: Write all CVE data cached in the OpenSearch index into the file system, xz-compress the data and create the feeds via a new github release.
4. `rebuild_nvd`: Create a snapshot of the current OpenSearch index. Then flush the index and pull in a fresh copy of all CVEs from the NVD API. (See [here](https://github.com/fkie-cad/nvd-json-data-feeds/issues/16) for an explanation why this is important)

## Current state of documentation & an invitation to contribute

`nvd_json_bot` and the [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) repository are side-projects maintained by René Helmke at the Cyber Analysis & Defense Group from Fraunhofer FKIE.
As [requested by the community](https://github.com/fkie-cad/nvd-json-data-feeds/issues/1)x, I am happy to release the bot's source code to establish more transparency regarding the processing steps applied to the data feeds.

While I am dedicated to keep both the data feeds and this bot alive and well-maintained, please understand that there is currently sparse documentation available.
I hope this changes over the course of time. Of course, together we can do more. Thus, I'd like to invite you to contribute to this project :-).

## Non-Endorsement Clause

This project uses and redistributes data from the NVD API but is not endorsed or certified by the NVD.
