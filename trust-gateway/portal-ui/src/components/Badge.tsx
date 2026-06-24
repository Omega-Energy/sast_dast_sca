export function Badge({ severity }: { severity: string }) {
  const s = severity?.toUpperCase() ?? "UNKNOWN";
  return (
    <span className={`badge-${s} inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide`}>
      {s}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending: "bg-slate-700 text-slate-300",
    running: "bg-blue-900 text-blue-300 animate-pulse",
    done:    "bg-green-900 text-green-300",
    failed:  "bg-red-900 text-red-300",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold capitalize ${map[status] ?? map.pending}`}>
      {status}
    </span>
  );
}
