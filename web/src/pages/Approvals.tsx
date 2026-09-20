import { useEffect, useMemo, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X, CheckCircle2, XCircle, Clock, History } from "lucide-react";
import clsx from "clsx";
import { useApprovals, useApproveApproval, useRejectApproval } from "../api/client";
import type { ApprovalResponse } from "../types";
import EmptyState from "../components/EmptyState";

function Countdown({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(Date.now());
  // Re-render every second while mounted so the countdown ticks.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const remaining = Math.max(0, new Date(expiresAt).getTime() - now);
  const mm = Math.floor(remaining / 60000);
  const ss = Math.floor((remaining % 60000) / 1000);
  const urgent = remaining < 60_000;
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 text-[12px] tabular-nums",
        urgent ? "text-[var(--red)]" : "text-[var(--text-tertiary)]",
      )}
    >
      <Clock size={12} strokeWidth={1.8} />
      {mm}:{String(ss).padStart(2, "0")}
    </span>
  );
}

function CommandBlock({ command }: { command: string }) {
  return (
    <pre
      className="max-h-40 overflow-auto rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-3 text-[12.5px] leading-relaxed text-[var(--text-primary)]"
      style={{ fontFamily: "var(--font-mono)" }}
    >
      {command}
    </pre>
  );
}

function BypassNotice() {
  return (
    <div className="rounded-lg border border-[var(--yellow)]/30 bg-[var(--yellow-subtle)] px-3 py-2 text-[12px] text-[var(--yellow)]">
      ⚡ This call requested a session bypass — approving also unlocks the matched
      pattern for the rest of this session.
    </div>
  );
}

function ApproveDialog({
  approval,
  onOpenChange,
}: {
  approval: ApprovalResponse | null;
  onOpenChange: (open: boolean) => void;
}) {
  const approve = useApproveApproval();
  if (!approval) return null;
  return (
    <Dialog.Root open={!!approval} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/70 backdrop-blur-md data-[state=open]:animate-fade-in" />
        <Dialog.Content className="animate-scale-in fixed left-1/2 top-1/2 w-full max-w-lg rounded-2xl border border-[var(--border-default)] bg-[var(--bg-elevated)] p-6 shadow-2xl focus:outline-none">
          <div className="flex items-start justify-between">
            <Dialog.Title className="text-[15px] font-semibold text-[var(--text-primary)]">
              Approve command?
            </Dialog.Title>
            <Dialog.Close className="rounded-lg p-1.5 text-[var(--text-quaternary)] transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--text-secondary)]">
              <X size={14} />
            </Dialog.Close>
          </div>
          <Dialog.Description className="mt-3 text-[12px] text-[var(--text-tertiary)]">
            Review the full command before approving. It will run on{" "}
            <span className="font-medium text-[var(--text-secondary)]">
              {approval.node_name ?? approval.node_id}
            </span>
            {approval.rule_description
              ? ` — matched rule: ${approval.rule_description}`
              : ""}
            .
          </Dialog.Description>
          <div className="mt-4 space-y-3">
            <CommandBlock command={approval.command} />
            {approval.bypass_scope === "session" && <BypassNotice />}
          </div>
          <div className="mt-6 flex justify-end gap-3">
            <Dialog.Close className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] px-4 py-2 text-[13px] font-medium text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)]">
              Cancel
            </Dialog.Close>
            <button
              onClick={() => {
                approve.mutate(approval.id);
                onOpenChange(false);
              }}
              disabled={approve.isPending}
              className={clsx(
                "inline-flex items-center gap-1.5 rounded-lg bg-[var(--green)] px-4 py-2 text-[13px] font-semibold text-black transition-all duration-200 hover:bg-[var(--green-light)]",
                approve.isPending && "opacity-50",
              )}
            >
              <CheckCircle2 size={14} strokeWidth={2} />
              Approve
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RejectDialog({
  approval,
  onOpenChange,
}: {
  approval: ApprovalResponse | null;
  onOpenChange: (open: boolean) => void;
}) {
  const reject = useRejectApproval();
  const [reason, setReason] = useState("");
  if (!approval) return null;
  return (
    <Dialog.Root
      open={!!approval}
      onOpenChange={(open) => {
        if (!open) setReason("");
        onOpenChange(open);
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/70 backdrop-blur-md data-[state=open]:animate-fade-in" />
        <Dialog.Content className="animate-scale-in fixed left-1/2 top-1/2 w-full max-w-lg rounded-2xl border border-[var(--border-default)] bg-[var(--bg-elevated)] p-6 shadow-2xl focus:outline-none">
          <div className="flex items-start justify-between">
            <Dialog.Title className="text-[15px] font-semibold text-[var(--text-primary)]">
              Reject command?
            </Dialog.Title>
            <Dialog.Close className="rounded-lg p-1.5 text-[var(--text-quaternary)] transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--text-secondary)]">
              <X size={14} />
            </Dialog.Close>
          </div>
          <Dialog.Description className="mt-3 text-[12px] text-[var(--text-tertiary)]">
            The AI will be told the command was rejected.
          </Dialog.Description>
          <div className="mt-4 space-y-3">
            <CommandBlock command={approval.command} />
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={2000}
              rows={3}
              placeholder="Why is this unsafe? The AI will see this reason."
              className="w-full resize-none rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] p-3 text-[12.5px] text-[var(--text-primary)] placeholder:text-[var(--text-quaternary)] focus:outline-none focus:ring-1 focus:ring-[var(--red)]/50"
            />
          </div>
          <div className="mt-6 flex justify-end gap-3">
            <Dialog.Close className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] px-4 py-2 text-[13px] font-medium text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)]">
              Cancel
            </Dialog.Close>
            <button
              onClick={() => {
                reject.mutate({ id: approval.id, reason: reason.trim() || undefined });
                onOpenChange(false);
                setReason("");
              }}
              disabled={reject.isPending}
              className={clsx(
                "inline-flex items-center gap-1.5 rounded-lg bg-[var(--red)] px-4 py-2 text-[13px] font-semibold text-white transition-all duration-200 hover:brightness-110",
                reject.isPending && "opacity-50",
              )}
            >
              <XCircle size={14} strokeWidth={2} />
              Reject
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

const statusStyles: Record<string, string> = {
  pending: "text-[var(--yellow)] border-[var(--yellow)]/30 bg-[var(--yellow-subtle)]",
  approved: "text-[var(--green)] border-[var(--green)]/30 bg-[var(--green-subtle)]",
  executed: "text-[var(--green)] border-[var(--green)]/30 bg-[var(--green-subtle)]",
  rejected: "text-[var(--red)] border-[var(--red)]/30 bg-[var(--red-subtle)]",
  expired: "text-[var(--text-tertiary)] border-[var(--border-default)] bg-[var(--bg-tertiary)]",
};

function HistoryRow({ ap }: { ap: ApprovalResponse }) {
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <pre
            className="overflow-hidden text-ellipsis whitespace-nowrap text-[12.5px] text-[var(--text-primary)]"
            style={{ fontFamily: "var(--font-mono)" }}
            title={ap.command}
          >
            {ap.command}
          </pre>
          <p className="mt-1 text-[11.5px] text-[var(--text-tertiary)]">
            {ap.node_name ?? ap.node_id}
            {ap.rule_description ? ` · ${ap.rule_description}` : ""}
            {ap.decided_at
              ? ` · decided ${new Date(ap.decided_at).toLocaleString()}`
              : ""}
            {ap.exec_exit_code !== null ? ` · exit ${ap.exec_exit_code}` : ""}
          </p>
          {ap.reject_reason && (
            <p className="mt-1 text-[11.5px] text-[var(--red)]">
              Reason: {ap.reject_reason}
            </p>
          )}
        </div>
        <span
          className={clsx(
            "shrink-0 rounded-full border px-2 py-0.5 text-[10.5px] font-medium capitalize",
            statusStyles[ap.status] ?? statusStyles.expired,
          )}
        >
          {ap.status}
        </span>
      </div>
    </div>
  );
}

export default function Approvals() {
  const [tab, setTab] = useState<"pending" | "history">("pending");
  const [toApprove, setToApprove] = useState<ApprovalResponse | null>(null);
  const [toReject, setToReject] = useState<ApprovalResponse | null>(null);

  const pending = useApprovals("pending");
  const history = useApprovals();

  const historyRows = useMemo(
    () => (history.data ?? []).filter((a) => a.status !== "pending"),
    [history.data],
  );

  return (
    <div className="mx-auto w-full max-w-4xl px-8 py-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold tracking-[-0.02em] text-[var(--text-primary)]">
            Approvals
          </h1>
          <p className="mt-1 text-[12.5px] text-[var(--text-tertiary)]">
            Commands that need a human decision before they can run.
          </p>
        </div>
        <div className="flex rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] p-0.5">
          {(
            [
              ["pending", "Pending", pending.data?.length ?? 0],
              ["history", "History", null],
            ] as const
          ).map(([key, label, count]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={clsx(
                "rounded-md px-3 py-1.5 text-[12px] font-medium transition-all",
                tab === key
                  ? "bg-[var(--bg-elevated)] text-[var(--text-primary)] shadow-sm"
                  : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]",
              )}
            >
              {label}
              {count !== null && count > 0 && (
                <span className="ml-1.5 rounded-full bg-[var(--yellow-subtle)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--yellow)]">
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {tab === "pending" ? (
        <div className="mt-6 space-y-3">
          {pending.isLoading ? (
            <p className="text-[13px] text-[var(--text-tertiary)]">Loading…</p>
          ) : (pending.data ?? []).length === 0 ? (
            <EmptyState
              icon={CheckCircle2}
              title="Nothing waiting"
              description="Commands matching a CONFIRM rule will appear here for approval."
            />
          ) : (
            pending.data!.map((ap) => (
              <div
                key={ap.id}
                className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-4"
              >
                <CommandBlock command={ap.command} />
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-[var(--text-tertiary)]">
                    <span className="font-medium text-[var(--text-secondary)]">
                      {ap.node_name ?? ap.node_id}
                    </span>
                    {ap.rule_description && (
                      <span>Rule: {ap.rule_description}</span>
                    )}
                    <span>
                      requested {new Date(ap.requested_at).toLocaleTimeString()}
                    </span>
                    <Countdown expiresAt={ap.expires_at} />
                    {ap.bypass_scope === "session" && (
                      <span className="text-[var(--yellow)]">
                        ⚡ session bypass requested
                      </span>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setToReject(ap)}
                      className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-tertiary)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)]"
                    >
                      Reject
                    </button>
                    <button
                      onClick={() => setToApprove(ap)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--green)] px-3 py-1.5 text-[12px] font-semibold text-black transition-all hover:bg-[var(--green-light)]"
                    >
                      <CheckCircle2 size={13} strokeWidth={2} />
                      Approve
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {historyRows.length === 0 ? (
            <EmptyState
              icon={History}
              title="No history yet"
              description="Decided, executed and expired approvals will show up here."
            />
          ) : (
            historyRows.map((ap) => <HistoryRow key={ap.id} ap={ap} />)
          )}
        </div>
      )}

      <ApproveDialog approval={toApprove} onOpenChange={(o) => !o && setToApprove(null)} />
      <RejectDialog approval={toReject} onOpenChange={(o) => !o && setToReject(null)} />
    </div>
  );
}
