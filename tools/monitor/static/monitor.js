"use strict";

// The monitor is a TV.  This script reads /api/board and paints it; it has no
// other capability.  Every value that came out of a run is written with
// textContent, so evidence text can never become markup.

const BOARD_URL = "/api/board";
const REFRESH_MS = 2000;
const DASH = "—";

const el = (id) => document.getElementById(id);

function text(value) {
  return value === null || value === undefined || value === "" ? DASH : String(value);
}

function flag(value) {
  if (value === true) return "true";
  if (value === false) return "false";
  return DASH;
}

function line(tag, className, value) {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = value;
  return node;
}

function stageBox(stage) {
  const state = stage.state || "queued";
  const box = document.createElement("li");
  box.className = `stage stage--${state}`;

  box.appendChild(line("h2", "stage__id", text(stage.id)));
  box.appendChild(line("p", "stage__role", text(stage.role)));
  box.appendChild(line("p", "stage__state", state));

  const update = line("time", "stage__update", text(stage.lastUpdate));
  if (stage.lastUpdate) update.dateTime = stage.lastUpdate;
  box.appendChild(update);

  // Short error text only; the reader has already reduced any stack dump.
  if (state === "failed" && stage.error) {
    box.appendChild(line("p", "stage__error", stage.error));
  }
  return box;
}

function render(board) {
  const stages = Array.isArray(board.stages) ? board.stages : [];

  el("run-id").textContent = board.runId ? String(board.runId) : "waiting for run";
  el("status").textContent = text(board.status);
  el("live").textContent = flag(board.live);
  el("source-unchanged").textContent = flag(board.sourceUnchanged);
  el("run-directory").textContent = text(board.runDirectory);

  const sheet = el("decision-sheet");
  sheet.hidden = !board.decisionSheetUrl;
  if (board.decisionSheetUrl) sheet.href = board.decisionSheetUrl;

  el("board").replaceChildren(...stages.map(stageBox));

  const empty = el("empty");
  empty.textContent = board.message || "waiting for run";
  empty.hidden = stages.length > 0;

  document.title = board.runId ? `${board.runId} — live stage monitor` : "live stage monitor";
}

async function poll() {
  try {
    const response = await fetch(BOARD_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`board request failed: ${response.status}`);
    render(await response.json());
    document.body.classList.remove("is-stale");
  } catch (error) {
    // Keep the last board on screen and dim it until the next good read.
    document.body.classList.add("is-stale");
  }
}

poll();
// The server re-selects the newest run folder on every request, so the board
// follows a new run within one refresh with no reload and no reconfiguration.
setInterval(poll, REFRESH_MS);
