#!/bin/bash

.venv/bin/python main.py sync_nvd
.venv/bin/python main.py update_git_repo

