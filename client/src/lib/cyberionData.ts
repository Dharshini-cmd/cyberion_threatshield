export type Severity = "critical" | "high" | "medium" | "low";
export type Status = "active" | "investigating" | "contained" | "planned" | "completed" | "validated" | "draft";

export type DetectionRule = {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: "validated" | "draft" | "testing";
  tactic: string;
  technique: string;
  techniqueName: string;
  dataSources: string[];
  author: string;
  version: string;
  lastTested: string;
  hitRate: string;
  sigma: string;
};

export type Hunt = {
  id: string;
  title: string;
  hypothesis: string;
  status: "active" | "planned" | "completed";
  priority: "P1" | "P2" | "P3";
  analyst: string;
  techniques: string[];
  evidence: number;
  updated: string;
  scope: string;
};

export type Incident = {
  id: string;
  title: string;
  severity: Severity;
  status: "investigating" | "contained" | "monitoring";
  confidence: number;
  assignee: string;
  entity: string;
  rule: string;
  opened: string;
  summary: string;
  timeline: { time: string; title: string; source: string; detail: string; kind: "alert" | "process" | "network" | "note" }[];
};

export type Playbook = {
  id: string;
  title: string;
  trigger: string;
  owner: string;
  duration: string;
  progress: number;
  phases: { title: string; steps: string[] }[];
};

export const dashboardMetrics = {
  detections: { value: "128", delta: "+14.2%", label: "Active detections", tone: "cyan" },
  incidents: { value: "07", delta: "−02", label: "Open investigations", tone: "amber" },
  coverage: { value: "68%", delta: "+8.6%", label: "ATT&CK coverage", tone: "violet" },
  hunts: { value: "12", delta: "+04", label: "Hunts this quarter", tone: "green" },
};

export const detections: DetectionRule[] = [
  {
    id: "CYB-PS-042",
    title: "PowerShell encoded command execution",
    description: "Detects suspicious PowerShell invocation using encoded commands and hidden window flags.",
    severity: "high",
    status: "validated",
    tactic: "Execution",
    technique: "T1059.001",
    techniqueName: "PowerShell",
    dataSources: ["Windows Process", "PowerShell Script Block"],
    author: "A. Prakash",
    version: "v1.4",
    lastTested: "Today, 09:14",
    hitRate: "98.4%",
    sigma: `title: PowerShell Encoded Command Execution\nid: 7f29b21d-7b2c-4a7f-a9a2-cyb042\nstatus: stable\ndescription: Detect encoded PowerShell payloads\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \\"\\\\powershell.exe\\"\n    CommandLine|contains:\n      - \\"-enc\\"\n      - \\"-encodedcommand\\"\n  condition: selection\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001`,
  },
  {
    id: "CYB-AD-017",
    title: "Member added to privileged group",
    description: "Flags membership changes to domain administrator and local administrator groups.",
    severity: "critical",
    status: "validated",
    tactic: "Privilege Escalation",
    technique: "T1098",
    techniqueName: "Account Manipulation",
    dataSources: ["Windows Security Event"],
    author: "R. Menon",
    version: "v2.1",
    lastTested: "Yesterday, 16:40",
    hitRate: "94.8%",
    sigma: `title: Member Added To Privileged Group\nstatus: stable\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4732\n    TargetUserName|contains:\n      - Administrators\n      - Domain Admins\n  condition: selection\nlevel: critical\ntags:\n  - attack.persistence\n  - attack.t1098`,
  },
  {
    id: "CYB-RDP-031",
    title: "RDP connection from unusual geography",
    description: "Detects successful remote desktop connections that fall outside the approved analyst geofence.",
    severity: "medium",
    status: "testing",
    tactic: "Initial Access",
    technique: "T1021.001",
    techniqueName: "Remote Services: RDP",
    dataSources: ["Windows Logon", "VPN Gateway"],
    author: "S. Kulkarni",
    version: "v0.9",
    lastTested: "12 Sep, 14:08",
    hitRate: "86.2%",
    sigma: `title: RDP Connection From Unusual Geography\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4624\n    LogonType: 10\n  filter_known:\n    SourceNetworkAddress|cidr: 10.10.0.0/16\n  condition: selection and not filter_known\nlevel: medium\ntags:\n  - attack.lateral-movement\n  - attack.t1021.001`,
  },
  {
    id: "CYB-LOLS-008",
    title: "Regsvr32 remote script execution",
    description: "Identifies signed binary proxy execution through regsvr32 and remote scrobj payloads.",
    severity: "high",
    status: "validated",
    tactic: "Defense Evasion",
    technique: "T1218.010",
    techniqueName: "Regsvr32",
    dataSources: ["Windows Process", "DNS Query"],
    author: "N. Shah",
    version: "v1.1",
    lastTested: "11 Sep, 11:23",
    hitRate: "91.7%",
    sigma: `title: Regsvr32 Remote Script Execution\nstatus: stable\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \\"\\\\regsvr32.exe\\"\n    CommandLine|contains: \\"scrobj.dll\\"\n  condition: selection\nlevel: high\ntags:\n  - attack.defense-evasion\n  - attack.t1218.010`,
  },
  {
    id: "CYB-SCH-054",
    title: "Scheduled task created via command shell",
    description: "Detects scheduled task creation launched from cmd.exe or a script interpreter.",
    severity: "high",
    status: "validated",
    tactic: "Persistence",
    technique: "T1053.005",
    techniqueName: "Scheduled Task/Job",
    dataSources: ["Windows Process", "Windows Task Scheduler"],
    author: "A. Prakash",
    version: "v1.0",
    lastTested: "10 Sep, 18:55",
    hitRate: "89.3%",
    sigma: `title: Scheduled Task Created Via Command Shell\nstatus: stable\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \\"\\\\schtasks.exe\\"\n    CommandLine|contains: \\"/create\\"\n  condition: selection\nlevel: high\ntags:\n  - attack.persistence\n  - attack.t1053.005`,
  },
];

export const hunts: Hunt[] = [
  { id: "HUNT-2026-019", title: "Silent admin creation on tier-0 assets", hypothesis: "An operator may be creating dormant privileged accounts to preserve access after containment.", status: "active", priority: "P1", analyst: "A. Prakash", techniques: ["T1098", "T1136"], evidence: 18, updated: "14 min ago", scope: "Domain Controllers · 30 days" },
  { id: "HUNT-2026-017", title: "RDP spray from edge infrastructure", hypothesis: "Repeated low-volume RDP failures may be hiding a password spray against service accounts.", status: "active", priority: "P2", analyst: "S. Kulkarni", techniques: ["T1110.001", "T1021.001"], evidence: 11, updated: "42 min ago", scope: "VPN + RDP gateway · 7 days" },
  { id: "HUNT-2026-011", title: "Living-off-the-land proxy execution", hypothesis: "Signed binaries are being used to proxy unsigned payloads from user-writable locations.", status: "completed", priority: "P2", analyst: "N. Shah", techniques: ["T1218", "T1059"], evidence: 26, updated: "2 days ago", scope: "Workstations · 14 days" },
  { id: "HUNT-2026-006", title: "Cloud mailbox forwarding rules", hypothesis: "Compromised identities may be establishing forwarding rules to exfiltrate high-value mail.", status: "planned", priority: "P3", analyst: "R. Menon", techniques: ["T1114.003"], evidence: 0, updated: "5 days ago", scope: "Microsoft 365 · 90 days" },
];

export const incidents: Incident[] = [
  {
    id: "INC-0428",
    title: "Encoded PowerShell on FIN-WS-042",
    severity: "critical",
    status: "investigating",
    confidence: 94,
    assignee: "A. Prakash",
    entity: "FIN-WS-042",
    rule: "CYB-PS-042",
    opened: "Today, 09:14",
    summary: "A finance workstation launched a base64-encoded PowerShell command shortly after a suspicious document was opened.",
    timeline: [
      { time: "09:14:22", title: "Detection fired", source: "CYB-PS-042", detail: "powershell.exe launched with -enc and hidden window flags.", kind: "alert" },
      { time: "09:13:58", title: "Office child process", source: "Sysmon", detail: "WINWORD.EXE spawned powershell.exe from a temporary user path.", kind: "process" },
      { time: "09:13:41", title: "Outbound DNS lookup", source: "DNS sensor", detail: "Query for cdn-sync[.]net from FIN-WS-042.", kind: "network" },
      { time: "09:19:05", title: "Analyst note", source: "A. Prakash", detail: "Host isolated via EDR. Collecting memory capture and browser history.", kind: "note" },
    ],
  },
  {
    id: "INC-0426",
    title: "Privileged group membership change",
    severity: "high",
    status: "contained",
    confidence: 88,
    assignee: "R. Menon",
    entity: "DC-01",
    rule: "CYB-AD-017",
    opened: "Today, 07:42",
    summary: "A new account was added to the Domain Admins group outside the approved change window.",
    timeline: [
      { time: "07:42:06", title: "Detection fired", source: "CYB-AD-017", detail: "Account svc-backup2 added to Domain Admins.", kind: "alert" },
      { time: "07:47:19", title: "Account disabled", source: "Identity team", detail: "Account disabled pending identity verification.", kind: "process" },
    ],
  },
  {
    id: "INC-0421",
    title: "Unusual RDP session from Singapore",
    severity: "medium",
    status: "monitoring",
    confidence: 71,
    assignee: "S. Kulkarni",
    entity: "ENG-VDI-18",
    rule: "CYB-RDP-031",
    opened: "Yesterday, 18:03",
    summary: "A valid user session originated from an unapproved geography and accessed an engineering VDI.",
    timeline: [
      { time: "18:03:51", title: "Detection fired", source: "CYB-RDP-031", detail: "Successful RDP logon from 103.12.44.19.", kind: "alert" },
      { time: "18:30:00", title: "User verified", source: "SOC", detail: "User confirmed travel; session remains under observation.", kind: "note" },
    ],
  },
];

export const playbooks: Playbook[] = [
  { id: "PB-001", title: "Malicious PowerShell execution", trigger: "Encoded PowerShell / suspicious script block", owner: "Detection Engineering", duration: "25 min", progress: 72, phases: [{ title: "Triage", steps: ["Validate command lineage", "Identify initial access document", "Check prevalence across fleet"] }, { title: "Containment", steps: ["Isolate affected host", "Disable compromised identity", "Block known indicators"] }, { title: "Recovery", steps: ["Collect memory and disk evidence", "Reimage or restore host", "Document lessons learned"] }] },
  { id: "PB-004", title: "Privileged account change", trigger: "Unexpected admin group membership", owner: "Identity Response", duration: "18 min", progress: 38, phases: [{ title: "Validate", steps: ["Confirm approved change ticket", "Review actor and source host"] }, { title: "Contain", steps: ["Disable account", "Revert group membership", "Rotate exposed credentials"] }] },
  { id: "PB-007", title: "Suspicious remote access", trigger: "Unusual RDP / VPN session", owner: "SOC Operations", duration: "32 min", progress: 100, phases: [{ title: "Triage", steps: ["Validate user travel and device", "Review session commands"] }, { title: "Close", steps: ["Document disposition", "Tune geofence exception"] }] },
];

export const coverage = [
  { tactic: "Initial Access", techniques: [{ id: "T1078", name: "Valid Accounts", state: "partial", rules: 4, hunts: 2 }, { id: "T1021.001", name: "Remote Services: RDP", state: "covered", rules: 7, hunts: 3 }, { id: "T1190", name: "Exploit Public-Facing App", state: "gap", rules: 0, hunts: 0 }] },
  { tactic: "Execution", techniques: [{ id: "T1059.001", name: "PowerShell", state: "covered", rules: 12, hunts: 4 }, { id: "T1218.010", name: "Regsvr32", state: "covered", rules: 5, hunts: 2 }, { id: "T1047", name: "Windows Management Instrumentation", state: "partial", rules: 2, hunts: 1 }] },
  { tactic: "Persistence", techniques: [{ id: "T1053.005", name: "Scheduled Task/Job", state: "covered", rules: 8, hunts: 2 }, { id: "T1098", name: "Account Manipulation", state: "partial", rules: 3, hunts: 3 }, { id: "T1547.001", name: "Registry Run Keys / Startup Folder", state: "gap", rules: 0, hunts: 0 }] },
  { tactic: "Privilege Escalation", techniques: [{ id: "T1068", name: "Exploitation for Privilege Escalation", state: "gap", rules: 0, hunts: 0 }, { id: "T1098", name: "Account Manipulation", state: "partial", rules: 3, hunts: 3 }] },
  { tactic: "Defense Evasion", techniques: [{ id: "T1562.001", name: "Impair Defenses", state: "partial", rules: 2, hunts: 1 }, { id: "T1218", name: "System Binary Proxy Execution", state: "covered", rules: 9, hunts: 4 }] },
];

export const activity = [
  { time: "09:19", icon: "shield", tone: "red", title: "Critical incident escalated", detail: "INC-0428 · Encoded PowerShell on FIN-WS-042" },
  { time: "09:14", icon: "zap", tone: "cyan", title: "Detection rule fired", detail: "CYB-PS-042 · confidence 94%" },
  { time: "08:56", icon: "search", tone: "violet", title: "Threat hunt evidence added", detail: "HUNT-2026-019 · 4 new artifacts" },
  { time: "08:42", icon: "check", tone: "green", title: "Rule validation completed", detail: "CYB-AD-017 · 24/24 test cases passed" },
  { time: "08:17", icon: "radar", tone: "amber", title: "Coverage gap identified", detail: "T1190 · Exploit Public-Facing App" },
];

export const isLocalApi = () => Boolean(import.meta.env.VITE_API_BASE);
