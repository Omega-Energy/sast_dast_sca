import { LucideIcon } from "lucide-react";

interface Props {
  label: string;
  value: number | string;
  icon: LucideIcon;
  color?: "red" | "orange" | "blue" | "green" | "purple" | "slate";
  sub?: string;
}

const colorMap = {
  red:    "text-red-400 bg-red-950/40 border-red-800/40",
  orange: "text-orange-400 bg-orange-950/40 border-orange-800/40",
  blue:   "text-blue-400 bg-blue-950/40 border-blue-800/40",
  green:  "text-green-400 bg-green-950/40 border-green-800/40",
  purple: "text-purple-400 bg-purple-950/40 border-purple-800/40",
  slate:  "text-slate-300 bg-slate-800/40 border-slate-700/40",
};

export function StatCard({ label, value, icon: Icon, color = "slate", sub }: Props) {
  const cls = colorMap[color];
  return (
    <div className={`rounded-xl border p-5 flex items-start gap-4 ${cls}`}>
      <div className="mt-0.5 p-2 rounded-lg bg-black/20">
        <Icon size={20} />
      </div>
      <div>
        <div className="text-3xl font-bold">{value}</div>
        <div className="text-sm font-medium mt-0.5">{label}</div>
        {sub && <div className="text-xs opacity-60 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}
