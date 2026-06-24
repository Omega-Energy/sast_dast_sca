import { Routes, Route, NavLink } from "react-router-dom";
import { LayoutDashboard, ScanSearch, History, GitCompare } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";
import CompareScans from "./pages/CompareScans";
import HistoryPage from "./pages/HistoryPage";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan", icon: ScanSearch, label: "New Scan" },
  { to: "/history", icon: History, label: "History" },
  { to: "/compare", icon: GitCompare, label: "Compare" },
];

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-surface border-r border-border flex flex-col">
        <div className="px-5 py-5 border-b border-border">
          <span className="text-xl font-bold tracking-tight">🔐 AppSec</span>
          <span className="ml-1 text-slate-400 text-sm">Pipeline</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? "bg-indigo-600/20 text-indigo-300 font-medium"
                    : "text-slate-400 hover:text-slate-200 hover:bg-surface2"
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-5 py-3 border-t border-border text-xs text-slate-600">
          Bandit · Semgrep · pip-audit · Gitleaks
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-bg">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/scan/:id" element={<ScanDetail />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/compare" element={<CompareScans />} />
        </Routes>
      </main>
    </div>
  );
}
