import { useState } from "react";
import { PauseCircle, Play, Ban } from "lucide-react";
import { useDenyHold, useHolds, useRunHold } from "../api/client";
import type { HoldResponse } from "../types";
import EmptyState from "../components/EmptyState";
import clsx from "clsx";

const STATUS_FILTERS = ["pending", "executing", "executed", "denied", "expired", "failed"] as const;

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "pending"
      ? "bg-[var(--orange-subtle)] text-[var(--orange)]"
      : status === "executing"
        ? "bg-[var(--blue-subtle)] text-[var(--blue)]"
        : status === "executed"
          ? "bg-[var(--green-subtle)] text-[var(--green)]"
          : "bg-[var(--red-subtle)] text-[var(--red)]";
  return (
    <span className={clsx("shrink-0 rounded-full px-2 py-[2px] text-[10px] font-semibold uppercase", cls)}>
      {status}
    </span>
  );
}

function HoldCard({
  hold,
  onRun,
  onDeny,
  busy,
}: {
  hold: HoldResponse;
  onRun: () => void;
  onDeny: (note: string) => void;
  busy: boolean;
}) {
  const [note, setNote] = useState("");
  const [denying, setDenying] = useState(false);
  const pending = hold.status === "pending";

  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-secondary)] p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <StatusBadge status={hold.status} />
            <span className="text-[13px] font-semibold text-[var(--text-primary)]">
              {hold.node_name ?? hold.node_id}
            </span>
            {hold.gate_score !== null && (
              <span
                className="text-[11px] text-[var(--text-quaternary)]"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                score {hold.gate_score.toFixed(3)}
              </span>
            )}
          </div>
          <code
            className="mt-2.5 block overflow-x-auto rounded-lg bg-[var(--bg-elevated)] px-3 py-2 text-[12px] text-[var(--green)]"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            {hold.command}
          </code>
          <p className="mt-2 text-[11px] text-[var(--text-quaternary)]">
            client {hold.client_id ?? "—"} · conversation {hold.conversation_key}
          </p>
        </div>

        {pending && (
          <div className="flex shrink-0 flex-col items-stretch gap-2">
            <button
              onClick={onRun}
              disabled={busy}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--green)] px-3.5 py-2 text-[12px] font-semibold text-black transition-all hover:bg-[var(--green-light)] disabled:opacity-50"
            >
              <Play size={13} strokeWidth={2} />
              Run once
            </button>
            <button
              onClick={() => setDenying((v) => !v)}
              disabled={busy}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-[var(--border-default)] bg-[var(--bg-tertiary)] px-3.5 py-2 text-[12px] font-medium text-[var(--text-secondary)] transition-all hover:bg-[var(--bg-hover)] disabled:opacity-50"
            >
              <Ban size={13} strokeWidth={1.8} />
              Deny
            </button>
          </div>
        )}
      </div>

      {pending && denying && (
        <div className="mt-3 flex items-center gap-2">
          <input
            type="text"
            value={note}
            maxLength={500}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Optional denial note for the agent…"
            className="focus-ring h-9 flex-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] px-3 text-[12px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)]"
          />
          <button
            onClick={() => onDeny(note)}
            disabled={busy}
            className="rounded-lg bg-[var(--red)] px-3.5 py-2 text-[12px] font-semibold text-white transition-all hover:opacity-90 disabled:opacity-50"
          >
            Confirm deny
          </button>
        </div>
      )}

      {hold.denial_note && (
        <p className="mt-2 text-[12px] text-[var(--text-tertiary)]">
          Note to agent: {hold.denial_note}
        </p>
      )}

      {hold.status === "executed" && hold.stdout && (
        <pre
          className="mt-3 max-h-40 overflow-auto rounded-lg bg-[var(--bg-primary)] px-3 py-2 text-[11px] text-[var(--text-secondary)]"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          {hold.stdout}
        </pre>
      )}

      {hold.recent_commands.length > 0 && (
        <div className="mt-3 border-t border-[var(--border-subtle)] pt-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-quaternary)]">
            Recent in this conversation
          </p>
          <ul className="mt-1.5 space-y-1">
            {hold.recent_commands.slice(0, 5).map((log) => (
              <li
                key={log.id}
                className="truncate text-[11px] text-[var(--text-tertiary)]"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {log.command}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function Holds() {
  const [status, setStatus] = useState<string>("pending");
  const { data: holds = [], isLoading } = useHolds(status || undefined);
  const runHold = useRunHold();
  const denyHold = useDenyHold();
  const busy = runHold.isPending || denyHold.isPending;

  return (
    <div className="h-full overflow-y-auto bg-[var(--bg-primary)] p-8">
      <div>
        <h1 className="text-[17px] font-bold tracking-[-0.02em] text-[var(--text-primary)]">
          Holds
        </h1>
        <p className="mt-1 text-[13px] text-[var(--text-tertiary)]">
          Commands in the uncertain band, waiting for your decision. Run once
          returns the output to the requesting agent; deny stops this exact
          command for the rest of the conversation.
        </p>
      </div>

      <div className="mt-5 flex flex-wrap items-center gap-1.5">
        {["", ...STATUS_FILTERS].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setStatus(s)}
            className={clsx(
              "rounded-lg px-3 py-1.5 text-[12px] font-medium capitalize transition-all",
              status === s
                ? "bg-[var(--green-subtle)] text-[var(--green)]"
                : "text-[var(--text-tertiary)] hover:bg-[var(--bg-hover)]",
            )}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      <div className="mt-5 space-y-3">
        {isLoading ? (
          <p className="text-[13px] text-[var(--text-quaternary)]">Loading…</p>
        ) : holds.length === 0 ? (
          <EmptyState
            icon={PauseCircle}
            title="No holds"
            description={
              status === "pending"
                ? "No commands are waiting for a decision."
                : "No holds match this filter."
            }
          />
        ) : (
          holds.map((hold) => (
            <HoldCard
              key={hold.id}
              hold={hold}
              busy={busy}
              onRun={() => runHold.mutate(hold.id)}
              onDeny={(note) =>
                denyHold.mutate({ id: hold.id, body: { note: note || null } })
              }
            />
          ))
        )}
      </div>
    </div>
  );
}
