FROM python:3.11-slim-bullseye

ARG UNAME=<user>
ARG UID=<uid>
ARG GID=<gid>

RUN apt-get update && apt-get install git -y
RUN pip install --no-cache-dir --upgrade pip

RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash -d /nvd $UNAME

USER $UNAME
WORKDIR /nvd

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir packaging
RUN pip install . --force
RUN git config --global user.name "nvd-json-bot"
RUN git config --global user.email "example@example.org"

ENTRYPOINT ["python", "nvd_json_bot/run.py"]
