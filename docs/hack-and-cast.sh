#!/usr/bin/env bash

#
# Create an asciinema cast of the assistant hacking a target. There will be two panes. The MCP server logs in the top
# pane and the assistant in the bottom pane.
#
# The arguments are:
#   1: The target, such as "Web CTF LFI"
#   2: The prompt, such as "Solve the CTF challenge at 10.10.14.10"
#   3*: Arguments to the assistant, such as
#      -- gemini-model=gemini-2.5-flash
#
# Environment variables are inherited. Models and API keys can be set without being present in the recording:
#   export OPENAI_API_KEY=xxxxx
#   export OPENAI_MODEL=gpt-5-mini

set -euo pipefail

TARGET="$1"
PROMPT="$2"
shift
shift
SESSION="cast$$"

DEMO_DIR="$(pwd)/docs/demos"
mkdir -p -m 0775 "${DEMO_DIR}"
BASENAME="shyhurricane_demo_$(echo -n "${TARGET}" | tr -C '[:alnum:]' '_' | tr -s '_')"
OUTFILE="${DEMO_DIR}/${BASENAME}.json"
CHROMA_DB="${DEMO_DIR}/${BASENAME}.chroma"

TITLE="ShyHurricane demo - ${TARGET}"
IDLE_LIMIT=2            # compress pauses > N sec in final cast
TYPE_CHAR_DELAY=0.01    # seconds between keystrokes
AFTER_ENTER_DELAY=1     # wait after each Enter (per command)
COLS=132
ROWS=40

get_unused_port() {
  while :; do
    port=$(( (RANDOM % 55512) + 10000 ))  # range 10000–65535
    if ! lsof -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
}

cleanup() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  [ -n "${CHROMA_PID}" ] && kill "${CHROMA_PID}"
}
trap cleanup EXIT

type_cmd() {
  local target="$1"
  local cmd="$2"
  local i ch
  for ((i=0; i<${#cmd}; i++)); do
    ch="${cmd:$i:1}"
    tmux send-keys -t "$target" -l "$ch"
    sleep "$TYPE_CHAR_DELAY"
  done
  tmux send-keys -t "$target" C-m
  sleep "$AFTER_ENTER_DELAY"
}

# Disable oh-my-zsh updates
export DISABLE_AUTO_UPDATE=true
# Disable macOS bash warnings
export BASH_SILENCE_DEPRECATION_WARNING=1

source .venv/bin/activate

# start chroma database for this demo
CHROMA_PORT=$(get_unused_port)
chroma run --path "${CHROMA_DB}" --host 127.0.0.1 --port "${CHROMA_PORT}" >/dev/null &
CHROMA_PID=$!
export CHROMA="127.0.0.1:${CHROMA_PORT}"

# create tmux session with two stacked panes (horizontal split line)
#DEMO_SHELL="${SHELL}"
DEMO_SHELL=bash
tmux new-session -d -s "$SESSION" "${DEMO_SHELL}"
tmux set-option  -t "$SESSION" -g status off
tmux set-option  -t "$SESSION" -g mouse off
tmux set-window-option -t "$SESSION" -g remain-on-exit on
tmux split-window -t "$SESSION:0" -v -l '80%' "${DEMO_SHELL}"

PANE_MCP="$SESSION:0.0"
PANE_ASSIST="$SESSION:0.1"

(
  # wait for shell to finish init
  sleep 2
  type_cmd "$PANE_MCP" "source .venv/bin/activate"
  sleep 0.2
  tmux send-keys -t "$PANE_MCP" C-l

  type_cmd "$PANE_MCP" "python3 mcp_service.py"
  tmux wait-for -S done-top
) &

(
  # wait for shell to finish init
  sleep 2
  type_cmd "$PANE_ASSIST" "source .venv/bin/activate"
  sleep 0.2
  tmux send-keys -t "$PANE_ASSIST" C-l

  # wait for MCP port to be ready
  while ! curl -s --fail -X POST -o /dev/null http://127.0.0.1:8000/status; do
    sleep 3s
  done

  if [ -n "${PROMPT}" ]; then
    type_cmd "$PANE_ASSIST" "python3 assistant.py $* --run-and-exit \"${PROMPT}\""
  else
    type_cmd "$PANE_ASSIST" "python3 assistant.py $*"
  fi
  while pgrep -f assistant.py >/dev/null 2>/dev/null; do
    sleep 3s
  done
  # add "end of demo" marker
  tmux send-keys -t "$PANE_ASSIST" -l "## _____ END OF LINE _____"
  tmux send-keys -t "$PANE_ASSIST" C-m
  tmux wait-for -S done-bot
) &

# monitor: when both drivers finish, detach the client (no on-screen message)
(
  tmux wait-for done-top
  tmux wait-for done-bot
  # give tmux a beat to render final output
  sleep 0.2
  tmux detach-client -s "$SESSION" || true
) &

# record by attaching to the tmux session
# asciinema captures both panes as they are displayed in the single window
asciinema rec -t "$TITLE" -i "$IDLE_LIMIT" --cols=${COLS} --rows=${ROWS} -c "tmux attach -t $SESSION" --overwrite "${OUTFILE}.tmp" || true

# cleanup server after recording has ended
tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true

sed -e '/"## ____/q' "${OUTFILE}.tmp" > "${OUTFILE}"
rm "${OUTFILE}.tmp"

echo "Saved to ${OUTFILE}"
echo "Play it with: asciinema play ${OUTFILE}"
echo "Inspect it with: asciinema cat ${OUTFILE}"
echo "Convert to a GIF with: agg --idle-time-limit ${IDLE_LIMIT} --no-loop ${OUTFILE} ${DEMO_DIR}/${BASENAME}.gif"
