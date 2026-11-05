import { useMemo, useState } from "react";
import { useLocation } from "wouter";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bell,
  BookOpen,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  Database,
  FileSearch,
  Filter,
  FlaskConical,
  LogIn,
  LogOut,
  Menu,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  User,
  X,
} from "lucide-react";
import { toast } from "sonner";

import {
  activity,
  coverage,
  dashboardMetrics,
  detections,
  hunts,
  incidents,
  playbooks,
  type DetectionRule,
  type Hunt,
  type Incident,
  type Playbook,
  type Severity,
} from "@/lib/cyberionData";

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    critical: "border-red-400/20 bg-red-400/10 text-red-300",
    high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
    medium: "border-yellow-400/20 bg-yellow-400/10 text-yellow-300",
    low: "border-cyan-400/20 bg-cyan-400/10 text-cyan-300",
  };

  return (
    <span
      className={cx(
        "inline-flex rounded-md border px-2 py-1 text-[9px] font-bold uppercase tracking-[0.12em]",
        styles[severity],
      )}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-400">
      <CircleDot size={9} />
      {status}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Login                                                                      */
/* -------------------------------------------------------------------------- */

function LoginScreen({
  onLogin,
}: {
  onLogin: (name: string, role: string) => void;
}) {
  const [name, setName] = useState("");
  const [role, setRole] = useState("Detection Engineer");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleLogin = () => {
    const cleanName = name.trim();
    const cleanRole = role.trim();

    if (!cleanName) {
      toast.error("Enter your analyst name.");
      return;
    }

    if (!cleanRole) {
      toast.error("Enter your analyst role.");
      return;
    }

    if (!password) {
      toast.error("Enter a password.");
      return;
    }

    /*
     * Demo authentication.
     *
     * This is intentionally local-only.
     * It does NOT validate against a real server.
     */
    localStorage.setItem("cyberion_logged_in", "true");
    localStorage.setItem("cyberion_analyst_name", cleanName);
    localStorage.setItem("cyberion_analyst_role", cleanRole);

    onLogin(cleanName, cleanRole);

    toast.success(`Welcome, ${cleanName}.`);
  };

  return (
    <div className="min-h-screen bg-[#070b10] text-slate-200">
      <div className="flex min-h-screen items-center justify-center px-5 py-10">
        <div className="w-full max-w-md">
          {/* Logo */}
          <div className="mb-8 text-center">
            <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 shadow-[0_0_50px_rgba(34,211,238,0.08)]">
              <ShieldCheck size={30} className="text-cyan-300" />
            </div>

            <h1 className="text-2xl font-bold tracking-tight text-white">
              Cyberion ThreatShield
            </h1>

            <p className="mt-2 text-xs text-slate-500">
              Security Operations Center
            </p>
          </div>

          {/* Login Card */}
          <div className="rounded-3xl border border-white/[0.08] bg-[#0d131b] p-6 shadow-2xl">
            <div className="mb-6">
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-300">
                Analyst Authentication
              </p>

              <h2 className="mt-2 text-lg font-semibold text-white">
                Sign in to ThreatShield
              </h2>

              <p className="mt-1 text-xs leading-5 text-slate-500">
                Enter your analyst details to access the SOC workspace.
              </p>
            </div>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Analyst name
                </label>

                <div className="relative">
                  <User
                    size={15}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600"
                  />

                  <input
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        handleLogin();
                      }
                    }}
                    placeholder="Enter your name"
                    className="w-full rounded-xl border border-white/[0.08] bg-[#080d13] py-3 pl-10 pr-3 text-xs text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-300/30"
                  />
                </div>
              </div>

              {/* Role */}
              <div>
                <label className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Analyst role
                </label>

                <select
                  value={role}
                  onChange={(event) => setRole(event.target.value)}
                  className="w-full rounded-xl border border-white/[0.08] bg-[#080d13] px-3 py-3 text-xs text-slate-200 outline-none focus:border-cyan-300/30"
                >
                  <option>Detection Engineer</option>
                  <option>SOC Analyst</option>
                  <option>Threat Hunter</option>
                  <option>Incident Responder</option>
                  <option>Security Engineer</option>
                  <option>SOC Manager</option>
                </select>
              </div>

              {/* Password */}
              <div>
                <label className="mb-2 block text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Password
                </label>

                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        handleLogin();
                      }
                    }}
                    placeholder="Enter password"
                    className="w-full rounded-xl border border-white/[0.08] bg-[#080d13] px-3 py-3 pr-20 text-xs text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-300/30"
                  />

                  <button
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-600 hover:text-slate-300"
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </div>

              {/* Login */}
              <button
                type="button"
                onClick={handleLogin}
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-[10px] font-bold uppercase tracking-[0.14em] text-cyan-200 transition hover:bg-cyan-300/15"
              >
                <LogIn size={14} />
                Sign in
              </button>
            </div>

            {/* Demo notice */}
            <div className="mt-6 rounded-xl border border-yellow-400/10 bg-yellow-400/[0.03] p-3">
              <p className="text-[9px] leading-4 text-yellow-200/60">
                Demo authentication: credentials are stored locally in this
                browser. No real server-side authentication is configured yet.
              </p>
            </div>
          </div>

          <p className="mt-6 text-center text-[9px] uppercase tracking-[0.14em] text-slate-700">
            CYBERION THREATSHIELD · LOCAL SOC ENVIRONMENT
          </p>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Metric Card                                                                */
/* -------------------------------------------------------------------------- */

function MetricCard({
  label,
  value,
  icon: Icon,
  detail,
}: {
  label: string;
  value: string | number;
  icon: typeof Activity;
  detail?: string;
}) {
  return (
    <div className="group rounded-2xl border border-white/[0.07] bg-white/[0.02] p-4 transition duration-200 hover:border-cyan-300/15 hover:bg-white/[0.035]">
      <div className="flex items-start justify-between gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-300/10 bg-cyan-300/[0.05]">
          <Icon size={16} className="text-cyan-300" />
        </div>

        {detail && (
          <span className="rounded-md border border-emerald-400/10 bg-emerald-400/[0.03] px-2 py-1 text-[9px] font-semibold text-emerald-300/80">
            {detail}
          </span>
        )}
      </div>

      <p className="mt-5 text-3xl font-bold tracking-tight text-white">
        {value}
      </p>

      <p className="mt-1 text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500">
        {label}
      </p>

      <div className="mt-4 h-1 overflow-hidden rounded-full bg-white/[0.05]">
        <div className="h-full w-2/3 rounded-full bg-cyan-300/60 transition-all duration-500 group-hover:w-4/5" />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Panel                                                                      */
/* -------------------------------------------------------------------------- */

function Panel({
  title,
  subtitle,
  children,
  action,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02]">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">{title}</h3>

          {subtitle && (
            <p className="mt-1 text-[9px] text-slate-600">{subtitle}</p>
          )}
        </div>

        {action}
      </div>

      <div className="p-4">{children}</div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* App Shell                                                                  */
/* -------------------------------------------------------------------------- */

function AppShell({
  children,
  path,
  setPath,
  onLogout,
  analyst,
  role,
}: {
  children: React.ReactNode;
  path: string;
  setPath: (path: string) => void;
  onLogout: () => void;
  analyst: string;
  role: string;
}) {
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const initials =
    analyst
      .split(" ")
      .filter(Boolean)
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "AN";

  const navItems = [
    {
      path: "/",
      label: "Command Center",
      icon: Activity,
    },
    {
      path: "/detections",
      label: "Detection Library",
      icon: ShieldAlert,
      count: "128",
    },
    {
      path: "/hunts",
      label: "Threat Hunts",
      icon: Target,
      count: "12",
    },
    {
      path: "/incidents",
      label: "Incident Investigations",
      icon: AlertTriangle,
      count: "07",
    },
    {
      path: "/playbooks",
      label: "Response Playbooks",
      icon: BookOpen,
    },
    {
      path: "/coverage",
      label: "Coverage Matrix",
      icon: BarChart3,
    },
  ];

  return (
    <div className="min-h-screen bg-[#070b10] text-slate-200">
      {/* Sidebar */}
      <aside
        className={cx(
          "fixed inset-y-0 left-0 z-50 w-64 border-r border-white/[0.06] bg-[#0a0f15] transition-transform",
          mobileOpen
            ? "translate-x-0"
            : "-translate-x-full lg:translate-x-0",
        )}
      >
        <div className="flex h-full flex-col">
          {/* Logo */}
          <div className="flex h-16 items-center gap-3 border-b border-white/[0.06] px-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-300/10">
              <ShieldCheck size={18} className="text-cyan-300" />
            </div>

            <div>
              <p className="text-sm font-bold text-white">Cyberion</p>
              <p className="text-[8px] uppercase tracking-[0.18em] text-slate-600">
                ThreatShield
              </p>
            </div>
          </div>

          {/* Navigation */}
          <div className="flex-1 overflow-y-auto p-3">
            <p className="mb-3 px-3 text-[8px] font-bold uppercase tracking-[0.18em] text-slate-700">
              SOC Workspace
            </p>

            <nav className="space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = path === item.path;

                return (
                  <button
                    key={item.path}
                    type="button"
                    onClick={() => {
                      setPath(item.path);
                      setMobileOpen(false);
                    }}
                    className={cx(
                      "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition",
                      active
                        ? "border border-cyan-300/10 bg-cyan-300/[0.06] text-cyan-200"
                        : "text-slate-500 hover:bg-white/[0.03] hover:text-slate-300",
                    )}
                  >
                    <Icon size={15} />

                    <span className="flex-1 text-[10px] font-semibold">
                      {item.label}
                    </span>

                    {item.count && (
                      <span className="rounded-md bg-white/[0.04] px-1.5 py-0.5 text-[8px] text-slate-600">
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Environment */}
          <div className="border-t border-white/[0.06] p-4">
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-emerald-400" />

                <span className="text-[9px] font-semibold text-slate-400">
                  SOC environment online
                </span>
              </div>

              <p className="mt-2 text-[8px] text-slate-700">
                ENV / DEMO-SOC-01
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
        />
      )}

      {/* Main */}
      <div className="lg:pl-64">
        {/* Header */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-white/[0.06] bg-[#070b10]/95 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="rounded-lg p-2 text-slate-500 hover:bg-white/[0.04] lg:hidden"
            >
              <Menu size={18} />
            </button>

            <div className="hidden sm:block">
              <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-slate-600">
                Telemetry stream
              </p>

              <div className="mt-0.5 flex items-center gap-2">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />

                <span className="text-[10px] text-slate-400">
                  Nominal
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Notification */}
            <button
              type="button"
              onClick={() =>
                toast.info("No new priority notifications.")
              }
              className="relative rounded-lg p-2 text-slate-500 hover:bg-white/[0.04] hover:text-slate-300"
            >
              <Bell size={16} />

              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-orange-400" />
            </button>

            {/* Profile */}
            <div className="relative">
              <button
                type="button"
                onClick={() =>
                  setProfileOpen((open) => !open)
                }
                className="flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] p-1.5 pr-3 transition hover:border-cyan-300/20 hover:bg-white/[0.06]"
              >
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet-400/15 text-[10px] font-bold text-violet-200">
                  {initials}
                </div>

                <div className="hidden text-left sm:block">
                  <p className="text-xs font-medium text-slate-300">
                    {analyst}
                  </p>

                  <p className="text-[9px] text-slate-600">
                    {role}
                  </p>
                </div>

                <ChevronDown
                  size={14}
                  className="text-slate-600"
                />
              </button>

              {profileOpen && (
                <div className="absolute right-0 top-12 z-50 w-64 overflow-hidden rounded-2xl border border-white/[0.08] bg-[#111720] shadow-2xl">
                  <div className="border-b border-white/[0.06] p-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-400/15 text-xs font-bold text-violet-200">
                        {initials}
                      </div>

                      <div>
                        <p className="text-xs font-semibold text-slate-200">
                          {analyst}
                        </p>

                        <p className="mt-1 text-[9px] text-slate-600">
                          {role}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="p-2">
                    <button
                      type="button"
                      onClick={() => {
                        setProfileOpen(false);

                        toast.info(
                          "Profile editing is available from the login identity in this local build.",
                        );
                      }}
                      className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[10px] text-slate-400 transition hover:bg-white/[0.04] hover:text-slate-200"
                    >
                      <User size={14} />
                      Account information
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setProfileOpen(false);
                        onLogout();
                      }}
                      className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[10px] text-red-300 transition hover:bg-red-400/[0.06]"
                    >
                      <LogOut size={14} />
                      Log out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="min-h-[calc(100vh-4rem)] px-4 py-5 sm:px-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Page Header                                                                 */
/* -------------------------------------------------------------------------- */

function PageHeader({
  title,
  description,
  onRefresh,
}: {
  title: string;
  description: string;
  onRefresh: () => void;
}) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-[9px] font-bold uppercase tracking-[0.18em] text-cyan-300">
          Cyberion ThreatShield
        </p>

        <h1 className="mt-2 text-xl font-bold tracking-tight text-white sm:text-2xl">
          {title}
        </h1>

        <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-500">
          {description}
        </p>
      </div>

      <button
        type="button"
        onClick={onRefresh}
        className="flex items-center gap-2 self-start rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-400 transition hover:bg-white/[0.06]"
      >
        <RefreshCw size={12} />
        Sync telemetry
      </button>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Overview                                                                    */
/* -------------------------------------------------------------------------- */

function Overview({
  onIncident,
  onDetection,
}: {
  onIncident: (incident: Incident) => void;
  onDetection: (detection: DetectionRule) => void;
}) {
  return (
    <div className="space-y-5">
      {/* Metrics */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label={dashboardMetrics.incidents.label}
          value={dashboardMetrics.incidents.value}
          icon={AlertTriangle}
          detail={dashboardMetrics.incidents.delta}
        />

        <MetricCard
          label={dashboardMetrics.detections.label}
          value={dashboardMetrics.detections.value}
          icon={ShieldAlert}
          detail={dashboardMetrics.detections.delta}
        />

        <MetricCard
          label={dashboardMetrics.hunts.label}
          value={dashboardMetrics.hunts.value}
          icon={Target}
          detail={dashboardMetrics.hunts.delta}
        />

        <MetricCard
          label={dashboardMetrics.coverage.label}
          value={dashboardMetrics.coverage.value}
          icon={BarChart3}
          detail={dashboardMetrics.coverage.delta}
        />
      </div>

      {/* Priority Incidents + Recent Detections */}
      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Priority incidents"
          subtitle="Highest-priority investigations"
        >
          <div className="space-y-2">
            {incidents.slice(0, 5).map((incident) => (
              <button
                key={incident.id}
                type="button"
                onClick={() => onIncident(incident)}
                className="flex w-full items-center gap-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3 text-left transition hover:border-cyan-300/10 hover:bg-white/[0.03]"
              >
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[10px] font-semibold text-slate-300">
                      {incident.id}
                    </span>

                    <SeverityBadge severity={incident.severity} />
                  </div>

                  <p className="mt-1 text-[10px] text-slate-500">
                    {incident.title}
                  </p>
                </div>

                <ArrowRight
                  size={13}
                  className="text-slate-700"
                />
              </button>
            ))}
          </div>
        </Panel>

        <Panel
          title="Recent detections"
          subtitle="Latest detection engineering activity"
        >
          <div className="space-y-2">
            {detections.slice(0, 5).map((detection) => (
              <button
                key={detection.id}
                type="button"
                onClick={() => onDetection(detection)}
                className="flex w-full items-center gap-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3 text-left transition hover:border-cyan-300/10 hover:bg-white/[0.03]"
              >
                <Shield
                  size={14}
                  className="text-cyan-300"
                />

                <div className="flex-1">
                  <p className="text-[10px] font-semibold text-slate-300">
                    {detection.title}
                  </p>

                  <p className="mt-1 text-[9px] text-slate-600">
                    {detection.id} · {detection.technique}
                  </p>
                </div>

                <SeverityBadge
                  severity={detection.severity}
                />
              </button>
            ))}
          </div>
        </Panel>
      </div>

      {/* SOC Activity */}
      <Panel
        title="SOC activity"
        subtitle="Recent analyst and detection activity"
      >
        <div className="space-y-3">
          {activity.slice(0, 8).map((item, index) => (
            <div
              key={`${item.title}-${item.time}-${index}`}
              className="flex items-start gap-3"
            >
              <div className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-300" />

              <div className="min-w-0 flex-1">
                <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
                  <p className="text-[10px] font-semibold leading-5 text-slate-300">
                    {item.title}
                  </p>

                  <span className="shrink-0 text-[9px] text-slate-600">
                    {item.time}
                  </span>
                </div>

                <p className="text-[10px] leading-5 text-slate-500">
                  {item.detail}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Detection Library                                                           */
/* -------------------------------------------------------------------------- */

function DetectionLibrary({
  onSelect,
}: {
  onSelect: (detection: DetectionRule) => void;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");

  const filtered = useMemo(() => {
    return detections.filter((detection) => {
      const search = query.toLowerCase();

      const matchesQuery =
        !query ||
        detection.title.toLowerCase().includes(search) ||
        detection.id.toLowerCase().includes(search) ||
        detection.technique.toLowerCase().includes(search);

      const matchesSeverity =
        severity === "all" ||
        detection.severity === severity;

      return matchesQuery && matchesSeverity;
    });
  }, [query, severity]);

  return (
    <Panel
      title="Detection Library"
      subtitle={`${filtered.length} detection rules`}
      action={
        <button
          type="button"
          onClick={() =>
            toast.success(
              "New detection rule workflow opened.",
            )
          }
          className="flex items-center gap-1.5 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.05] px-2.5 py-1.5 text-[9px] font-semibold text-cyan-200"
        >
          <Plus size={11} />
          New rule
        </button>
      }
    >
      <div className="mb-4 flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <Search
            size={13}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-700"
          />

          <input
            value={query}
            onChange={(event) =>
              setQuery(event.target.value)
            }
            placeholder="Search detection rules..."
            className="w-full rounded-xl border border-white/[0.07] bg-white/[0.02] py-2.5 pl-9 pr-3 text-[10px] text-slate-300 outline-none focus:border-cyan-300/20"
          />
        </div>

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(event.target.value)
          }
          className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-3 py-2 text-[10px] text-slate-400 outline-none"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="space-y-2">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/[0.07] p-8 text-center">
            <FileSearch
              size={20}
              className="mx-auto text-slate-700"
            />

            <p className="mt-3 text-xs font-semibold text-slate-400">
              No detection rules found
            </p>

            <p className="mt-1 text-[9px] text-slate-700">
              Try another search term or severity filter.
            </p>
          </div>
        ) : (
          filtered.map((detection) => (
            <button
              key={detection.id}
              type="button"
              onClick={() => onSelect(detection)}
              className="flex w-full flex-col gap-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3 text-left transition hover:border-cyan-300/10 hover:bg-white/[0.03] sm:flex-row sm:items-center"
            >
              <div className="flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[9px] font-bold text-cyan-300">
                    {detection.id}
                  </span>

                  <SeverityBadge
                    severity={detection.severity}
                  />

                  <StatusBadge status={detection.status} />
                </div>

                <p className="mt-2 text-xs font-semibold text-slate-300">
                  {detection.title}
                </p>

                <p className="mt-1 text-[9px] text-slate-600">
                  MITRE ATT&CK · {detection.technique}
                </p>
              </div>

              <ArrowRight
                size={13}
                className="text-slate-700"
              />
            </button>
          ))
        )}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/* Hunts                                                                       */
/* -------------------------------------------------------------------------- */

function HuntBoard() {
  return (
    <Panel
      title="Threat Hunts"
      subtitle={`${hunts.length} active hypotheses`}
      action={
        <button
          type="button"
          onClick={() =>
            toast.success(
              "New threat hunting hypothesis created.",
            )
          }
          className="flex items-center gap-1.5 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.05] px-2.5 py-1.5 text-[9px] font-semibold text-cyan-200"
        >
          <Plus size={11} />
          New hypothesis
        </button>
      }
    >
      <div className="grid gap-3 md:grid-cols-2">
        {hunts.map((hunt: Hunt) => (
          <div
            key={hunt.id}
            className="rounded-xl border border-white/[0.05] bg-white/[0.015] p-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-bold text-cyan-300">
                {hunt.id}
              </span>

              <StatusBadge status={hunt.status} />
            </div>

            <h3 className="mt-3 text-xs font-semibold text-slate-300">
              {hunt.title}
            </h3>

            <p className="mt-2 text-[9px] leading-5 text-slate-600">
              {hunt.hypothesis}
            </p>

            <div className="mt-4 flex items-center justify-between border-t border-white/[0.05] pt-3">
              <span className="text-[8px] uppercase tracking-[0.1em] text-slate-700">
                ATT&CK
              </span>

              <span className="text-[9px] text-slate-500">
                {hunt.techniques}
              </span>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/* Incidents                                                                   */
/* -------------------------------------------------------------------------- */

function IncidentQueue({
  onSelect,
}: {
  onSelect: (incident: Incident) => void;
}) {
  return (
    <Panel
      title="Incident Investigations"
      subtitle={`${incidents.length} investigations in queue`}
    >
      <div className="space-y-2">
        {incidents.map((incident) => (
          <button
            key={incident.id}
            type="button"
            onClick={() => onSelect(incident)}
            className="flex w-full items-center gap-3 rounded-xl border border-white/[0.05] bg-white/[0.015] p-3 text-left transition hover:border-cyan-300/10 hover:bg-white/[0.03]"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-400/[0.06]">
              <AlertTriangle
                size={14}
                className="text-red-300"
              />
            </div>

            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[9px] font-bold text-slate-300">
                  {incident.id}
                </span>

                <SeverityBadge
                  severity={incident.severity}
                />
              </div>

              <p className="mt-1 text-[10px] text-slate-500">
                {incident.title}
              </p>
            </div>

            <span className="text-[9px] text-slate-700">
              {incident.assignee}
            </span>

            <ArrowRight
              size={13}
              className="text-slate-700"
            />
          </button>
        ))}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/* Playbooks                                                                   */
/* -------------------------------------------------------------------------- */

function PlaybookCatalog() {
  return (
    <Panel
      title="Response Playbooks"
      subtitle={`${playbooks.length} response workflows`}
      action={
        <button
          type="button"
          onClick={() =>
            toast.success("New response playbook created.")
          }
          className="flex items-center gap-1.5 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.05] px-2.5 py-1.5 text-[9px] font-semibold text-cyan-200"
        >
          <Plus size={11} />
          New playbook
        </button>
      }
    >
      <div className="grid gap-3 md:grid-cols-2">
        {playbooks.map((playbook: Playbook) => (
          <div
            key={playbook.id}
            className="rounded-xl border border-white/[0.05] bg-white/[0.015] p-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-bold text-cyan-300">
                {playbook.id}
              </span>

              <BookOpen
                size={14}
                className="text-slate-700"
              />
            </div>

            <h3 className="mt-3 text-xs font-semibold text-slate-300">
              {playbook.title}
            </h3>

            <p className="mt-2 text-[9px] leading-5 text-slate-600">
              {playbook.trigger}
            </p>

            <button
              type="button"
              onClick={() =>
                toast.info(
                  `${playbook.title} workflow selected.`,
                )
              }
              className="mt-4 flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-cyan-300"
            >
              <Play size={10} />
              Open workflow
            </button>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/* Coverage                                                                    */
/* -------------------------------------------------------------------------- */

function CoverageMatrix() {
  return (
    <Panel
      title="Coverage Matrix"
      subtitle="MITRE ATT&CK detection coverage"
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[600px] text-left">
          <thead>
            <tr className="border-b border-white/[0.06]">
              <th className="px-3 py-3 text-[8px] uppercase tracking-[0.12em] text-slate-700">
                Technique
              </th>

              <th className="px-3 py-3 text-[8px] uppercase tracking-[0.12em] text-slate-700">
                Tactic
              </th>

              <th className="px-3 py-3 text-[8px] uppercase tracking-[0.12em] text-slate-700">
                Coverage
              </th>
            </tr>
          </thead>

          <tbody>
            {coverage.map((item, index) => (
              <tr
                key={`${item.tactic}-${index}`}
                className="border-b border-white/[0.04]"
              >
                <td className="px-3 py-3 text-[10px] font-semibold text-slate-300">
                  {item.techniques.map((technique) => technique.name).join(", ")}
                </td>

                <td className="px-3 py-3 text-[9px] text-slate-600">
                  {item.tactic}
                </td>

                <td className="px-3 py-3">
                  <div className="flex items-center gap-3">
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/[0.06]">
                      <div
                        className="h-full rounded-full bg-cyan-300"
                        style={{
  width: `${
    (item.techniques.filter((technique) => technique.state === "covered").length /
      item.techniques.length) *
    100
  }%`,
}}
                      />
                    </div>

                    <span className="text-[9px] text-slate-500">
                      {Math.round(
  (item.techniques.filter((technique) => technique.state === "covered").length /
    item.techniques.length) *
    100
)}%
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/* Detection Drawer                                                            */
/* -------------------------------------------------------------------------- */

function DetectionDrawer({
  detection,
  onClose,
}: {
  detection: DetectionRule | null;
  onClose: () => void;
}) {
  if (!detection) return null;

  return (
    <div className="fixed inset-0 z-[60] flex justify-end bg-black/60">
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0"
      />

      <div className="relative z-10 h-full w-full max-w-lg overflow-y-auto border-l border-white/[0.08] bg-[#0b1118] p-5 shadow-2xl">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[9px] font-bold text-cyan-300">
              {detection.id}
            </span>

            <h2 className="mt-2 text-lg font-bold text-white">
              {detection.title}
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-slate-600 hover:bg-white/[0.04] hover:text-slate-300"
          >
            <X size={16} />
          </button>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          <SeverityBadge severity={detection.severity} />
          <StatusBadge status={detection.status} />
        </div>

        <div className="mt-6 space-y-4">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <p className="text-[8px] font-bold uppercase tracking-[0.14em] text-slate-700">
              MITRE ATT&CK
            </p>

            <p className="mt-2 text-xs text-slate-400">
              {detection.technique}
            </p>
          </div>

          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <p className="text-[8px] font-bold uppercase tracking-[0.14em] text-slate-700">
              Detection description
            </p>

            <p className="mt-2 text-[10px] leading-5 text-slate-500">
              {detection.description}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Incident Drawer                                                             */
/* -------------------------------------------------------------------------- */

function IncidentDrawer({
  incident,
  onClose,
}: {
  incident: Incident | null;
  onClose: () => void;
}) {
  if (!incident) return null;

  return (
    <div className="fixed inset-0 z-[60] flex justify-end bg-black/60">
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0"
      />

      <div className="relative z-10 h-full w-full max-w-lg overflow-y-auto border-l border-white/[0.08] bg-[#0b1118] p-5 shadow-2xl">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[9px] font-bold text-red-300">
              {incident.id}
            </span>

            <h2 className="mt-2 text-lg font-bold text-white">
              {incident.title}
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-slate-600 hover:bg-white/[0.04] hover:text-slate-300"
          >
            <X size={16} />
          </button>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
            <p className="text-[8px] uppercase tracking-[0.12em] text-slate-700">
              Assignee
            </p>

            <p className="mt-2 text-[10px] text-slate-400">
              {incident.assignee}
            </p>
          </div>

          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
            <p className="text-[8px] uppercase tracking-[0.12em] text-slate-700">
              Detection Rule
            </p>

            <p className="mt-2 text-[10px] text-slate-400">
              {incident.rule}
            </p>
          </div>
        </div>

        <div className="mt-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <p className="text-[8px] font-bold uppercase tracking-[0.14em] text-slate-700">
            Investigation
          </p>

          <p className="mt-2 text-[10px] leading-5 text-slate-500">
            {incident.summary}
          </p>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Home                                                                        */
/* -------------------------------------------------------------------------- */

export default function Home() {
  const [location, setLocation] = useLocation();

  const [loggedIn, setLoggedIn] = useState(
    () => localStorage.getItem("cyberion_logged_in") === "true",
  );

  const [analyst, setAnalyst] = useState(
    () =>
      localStorage.getItem("cyberion_analyst_name") ||
      "",
  );

  const [role, setRole] = useState(
    () =>
      localStorage.getItem("cyberion_analyst_role") ||
      "Detection Engineer",
  );

  const [selectedIncident, setSelectedIncident] =
    useState<Incident | null>(null);

  const [selectedDetection, setSelectedDetection] =
    useState<DetectionRule | null>(null);

  const path =
    location === "/"
      ? "/"
      : `/${location.split("/")[1]}`;

  const handleLogin = (name: string, userRole: string) => {
    setAnalyst(name);
    setRole(userRole);
    setLoggedIn(true);
    setLocation("/");
  };

  const handleLogout = () => {
    localStorage.removeItem("cyberion_logged_in");
    localStorage.removeItem("cyberion_analyst_name");
    localStorage.removeItem("cyberion_analyst_role");

    setLoggedIn(false);
    setAnalyst("");
    setRole("Detection Engineer");

    toast.success("You have been logged out.");
  };

  if (!loggedIn) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  const page = (() => {
    switch (path) {
      case "/detections":
        return (
          <DetectionLibrary
            onSelect={setSelectedDetection}
          />
        );

      case "/hunts":
        return <HuntBoard />;

      case "/incidents":
        return (
          <IncidentQueue
            onSelect={setSelectedIncident}
          />
        );

      case "/playbooks":
        return <PlaybookCatalog />;

      case "/coverage":
        return <CoverageMatrix />;

      default:
        return (
          <>
            <PageHeader
              title="Command Center"
              description="Detection engineering, threat hunting, incident investigation and ATT&CK coverage."
              onRefresh={() =>
                toast.success(
                  "Telemetry sync complete · demo dataset current.",
                )
              }
            />

            <Overview
              onIncident={setSelectedIncident}
              onDetection={setSelectedDetection}
            />
          </>
        );
    }
  })();

  return (
    <AppShell
      path={path}
      setPath={setLocation}
      onLogout={handleLogout}
      analyst={analyst}
      role={role}
    >
      {path !== "/" && (
        <PageHeader
          title={
            path === "/detections"
              ? "Detection Library"
              : path === "/hunts"
                ? "Threat Hunts"
                : path === "/incidents"
                  ? "Incident Investigations"
                  : path === "/playbooks"
                    ? "Response Playbooks"
                    : "Coverage Matrix"
          }
          description="Cyberion ThreatShield SOC workspace."
          onRefresh={() =>
            toast.success(
              "Telemetry sync complete · demo dataset current.",
            )
          }
        />
      )}

      {page}

      <DetectionDrawer
        detection={selectedDetection}
        onClose={() => setSelectedDetection(null)}
      />

      <IncidentDrawer
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </AppShell>
  );
}