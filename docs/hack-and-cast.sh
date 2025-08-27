#!/usr/bin/env bash

#
# Create an asciinema cast of the assistant hacking a target. There will be two panes. The MCP server logs in the top
# pane and the assistant in the bottom pane.
#
# The arguments are:
#   1: The prompt, such as "Solve the CTF challenge at 10.10.14.10"
#   2*: Arguments to the assistant, such as
#      -- gemini-model=gemini-2.5-flash
#
# Environment variables are inherited. Models and API keys can be set without being present in the recording:
#   export OPENAI_API_KEY=xxxxx
#   export OPENAI_MODEL=gpt-5-turbo

set -euo pipefail

TARGET="$1"
shift
SESSION="cast$$"
TITLE="ShyHurricane demo - ${TARGET}"
IDLE_LIMIT=2            # compress pauses > N sec in final cast
TYPE_CHAR_DELAY=0.01    # seconds between keystrokes
AFTER_ENTER_DELAY=1     # wait after each Enter (per command)
OUTFILE="shyhurricane_demo_$(echo -n "${TARGET}" | tr -C '[:alnum:]' '_' | tr -s '_').json"

cleanup() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
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

# create tmux session with two stacked panes (horizontal split line)
tmux new-session -d -s "$SESSION" "${SHELL}"
tmux set-option  -t "$SESSION" -g status off
tmux set-option  -t "$SESSION" -g mouse off
tmux set-window-option -t "$SESSION" -g remain-on-exit on
tmux split-window -t "$SESSION:0" -v

TOP="$SESSION:0.0"
BOT="$SESSION:0.1"

tmux resize-pane -t "$TOP" -y '20%'

(
  sleep 0.2
  type_cmd "$TOP" "source .venv/bin/activate"
  type_cmd "$TOP" "python3 mcp_service.py"
  tmux wait-for -S done-top
) &

(
  # wait for MCP port to be ready
  while ! curl -s --fail -X POST -o /dev/null http://127.0.0.1:8000/status; do
    sleep 3s
  done

  type_cmd "$BOT" "source .venv/bin/activate"
  type_cmd "$BOT" "python3 assistant.py $* --run-and-exit \"${TARGET}\""
  while pgrep -f assistant.py >/dev/null 2>/dev/null; do
    sleep 3s
  done
  # add end of demo marker
  tmux send-keys -t "$BOT" -l "## _____ END OF LINE _____"
  tmux send-keys -t "$BOT" C-m
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
asciinema rec -t "$TITLE" -i "$IDLE_LIMIT" -c "tmux attach -t $SESSION" --overwrite "${OUTFILE}.tmp" || true

# cleanup server after recording has ended
tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true

sed '/_____ END OF LINE _____/q' "${OUTFILE}.tmp" > "${OUTFILE}"
rm "${OUTFILE}.tmp"

echo "Saved to ${OUTFILE}"
echo "Play it with: asciinema play ${OUTFILE}"
