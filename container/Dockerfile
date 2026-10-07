# Sandbox for ALL untrusted code (npm packages, Remotion, Chrome, FFmpeg, the private bundle). It never receives a
# credential: the workflow runs it with --cap-drop=ALL, --security-opt=no-new-privileges, --read-only, a non-root
# --user and only explicit bind mounts (see bootstrap/run.sh). Base image pinned by digest (Node 20, Debian bookworm).
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates ffmpeg rsync python3 python3-venv \
      libnss3 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libgbm1 libasound2 libxrandr2 libxkbcommon0 libxfixes3 \
      libxcomposite1 libxdamage1 libpango-1.0-0 libcairo2 libcups2 \
      fontconfig fonts-noto-color-emoji fonts-liberation > /dev/null \
 && rm -rf /var/lib/apt/lists/*

USER node
WORKDIR /studio
