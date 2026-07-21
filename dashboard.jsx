import { useState, useRef, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, RotateCcw, FileJson, ChevronDown, ChevronUp } from "lucide-react";

// ── Sample data ───────────────────────────────────────────────────────────────
const SAMPLE = {
  generated_at: "2026-07-21T14:32:18.000Z",
  account_id: "123456789012",
  grade: "D",
  score: 55,
  summary: { total: 12, high: 2, medium: 5, low: 5 },
  findings: [
    {
      check: "mfa_enforcement", severity: "HIGH",
      resource_type: "User", resource_name: "deploy-admin",
      resource_arn: "arn:aws:iam::123456789012:user/deploy-admin",
      issues: ["User has console (password) access but NO MFA device enrolled"],
      description: "User 'deploy-admin' can log into the AWS console with just a password. A single phished or leaked password grants full console access.",
      remediation: "In IAM → user → Security credentials → Assign MFA device. Enforce via a policy that denies all actions unless aws:MultiFactorAuthPresent is true.",
    },
    {
      check: "wildcard_policy", severity: "HIGH",
      resource_type: "ManagedPolicy", resource_name: "DevFullAccess",
      resource_arn: "arn:aws:iam::123456789012:policy/DevFullAccess",
      issues: ["Action '*' on Resource '*' — full administrator access"],
      description: "Managed policy 'DevFullAccess' grants full administrator access to all AWS services and resources.",
      remediation: "Replace wildcard actions with only the specific permissions needed. Use IAM Access Analyzer to generate a least-privilege policy from CloudTrail activity.",
    },
    {
      check: "unused_keys", severity: "MEDIUM",
      resource_type: "AccessKey", resource_name: "ci-runner → key_1",
      resource_arn: "arn:aws:iam::user/ci-runner/key_1",
      issues: ["Key not rotated in 127 days (threshold: 90)"],
      description: "Access key 1 for user 'ci-runner' has not been rotated in 127 days, exceeding the 90-day threshold.",
      remediation: "Rotate the key if still needed, or deactivate and delete it. Prefer short-lived credentials (IAM roles, STS AssumeRole) over long-lived access keys.",
    },
    {
      check: "unused_keys", severity: "MEDIUM",
      resource_type: "AccessKey", resource_name: "deploy-user → key_2",
      resource_arn: "arn:aws:iam::user/deploy-user/key_2",
      issues: ["Key is active but has NEVER been used (45 days old)"],
      description: "Access key 2 for user 'deploy-user' is active but has never been used in its 45-day lifetime.",
      remediation: "Deactivate and delete this key immediately. A key that has never been used represents unnecessary standing access.",
    },
    {
      check: "direct_attachment", severity: "MEDIUM",
      resource_type: "User", resource_name: "analyst-jane",
      resource_arn: "arn:aws:iam::123456789012:user/analyst-jane",
      issues: ["Has 2 managed policies attached directly: S3ReadOnlyAccess, CloudWatchReadOnlyAccess"],
      description: "User 'analyst-jane' has managed policies attached directly rather than via a group, making access harder to audit.",
      remediation: "Create an IAM group with these policies, add the user to the group, then detach the policies from the user directly.",
    },
    {
      check: "direct_attachment", severity: "MEDIUM",
      resource_type: "User", resource_name: "developer-bob",
      resource_arn: "arn:aws:iam::123456789012:user/developer-bob",
      issues: ["Has 1 inline policy: DeveloperOverrides"],
      description: "User 'developer-bob' has an inline policy which is invisible in the IAM policy list and harder to audit or reuse.",
      remediation: "Convert this inline policy to a managed policy and attach via a group.",
    },
    {
      check: "s3_public_access", severity: "MEDIUM",
      resource_type: "S3/Bucket", resource_name: "my-app-assets-staging",
      resource_arn: "arn:aws:s3:::my-app-assets-staging",
      issues: ["Block public ACLs is disabled", "Ignore public ACLs is disabled"],
      description: "Bucket 'my-app-assets-staging' has two Block Public Access settings disabled, leaving it vulnerable to accidental public exposure.",
      remediation: "Enable all four Block Public Access settings on this bucket unless it intentionally serves public content.",
    },
    {
      check: "mfa_enforcement", severity: "LOW",
      resource_type: "User", resource_name: "ci-runner",
      resource_arn: "arn:aws:iam::123456789012:user/ci-runner",
      issues: ["User has no MFA device enrolled (programmatic-only access)"],
      description: "User 'ci-runner' has no MFA enrolled. While currently programmatic-only, adding a login profile later would be critical without MFA.",
      remediation: "Prefer IAM roles over long-lived IAM users for programmatic access.",
    },
    {
      check: "unused_role", severity: "LOW",
      resource_type: "Role", resource_name: "LegacyLambdaRole",
      resource_arn: "arn:aws:iam::123456789012:role/LegacyLambdaRole",
      issues: ["Role not assumed in 142 days (threshold: 90)"],
      description: "Role 'LegacyLambdaRole' has not been assumed in 142 days and may no longer be needed.",
      remediation: "Confirm this role is still needed. If inactive, delete it to reduce your attack surface.",
    },
    {
      check: "unused_role", severity: "LOW",
      resource_type: "Role", resource_name: "OldCodeBuildRole",
      resource_arn: "arn:aws:iam::123456789012:role/OldCodeBuildRole",
      issues: ["Role has NEVER been assumed (67 days since creation)"],
      description: "Role 'OldCodeBuildRole' has existed for 67 days but has never been assumed.",
      remediation: "Verify this role is still needed. If not, delete it.",
    },
    {
      check: "unused_role", severity: "LOW",
      resource_type: "Role", resource_name: "DataPipelineRole",
      resource_arn: "arn:aws:iam::123456789012:role/DataPipelineRole",
      issues: ["Role not assumed in 203 days (threshold: 90)"],
      description: "Role 'DataPipelineRole' has not been assumed in 203 days.",
      remediation: "Confirm this role is still needed. If inactive, consider deleting it.",
    },
    {
      check: "unused_role", severity: "LOW",
      resource_type: "Role", resource_name: "BackupAutomationRole",
      resource_arn: "arn:aws:iam::123456789012:role/BackupAutomationRole",
      issues: ["Role not assumed in 118 days (threshold: 90)"],
      description: "Role 'BackupAutomationRole' has not been assumed in 118 days.",
      remediation: "Confirm this role is still needed. If inactive, consider deleting it.",
    },
  ],
};

// ── Tokens ────────────────────────────────────────────────────────────────────
const C = {
  bg:     "#F1F2F4",
  white:  "#FFFFFF",
  border: "#E2E3E8",
  text:   "#111218",
  sub:    "#4B5063",
  muted:  "#9EA3B5",
  amber:  "#D97706",
};

const GRADE = {
  A: { hex: "#16A34A", soft: "#F0FDF4", label: "Clean"            },
  B: { hex: "#65A30D", soft: "#F7FEE7", label: "Good"             },
  C: { hex: "#CA8A04", soft: "#FEFCE8", label: "Moderate risk"    },
  D: { hex: "#EA580C", soft: "#FFF7ED", label: "Significant risk" },
  F: { hex: "#DC2626", soft: "#FEF2F2", label: "Critical"         },
};

const SEV = {
  HIGH:   { fg: "#B91C1C", bg: "#FEE2E2", border: "#FECACA" },
  MEDIUM: { fg: "#B45309", bg: "#FEF3C7", border: "#FDE68A" },
  LOW:    { fg: "#1D4ED8", bg: "#DBEAFE", border: "#BFDBFE" },
};

const CHECK_LABELS = {
  wildcard_policy:   "Wildcard Policy",
  unused_keys:       "Stale Keys",
  direct_attachment: "Direct Attachment",
  trust_policy:      "Trust Policy",
  unused_role:       "Unused Role",
  mfa_enforcement:   "MFA Enforcement",
  s3_public_access:  "S3 Public Access",
};

const card = {
  background: "#FFFFFF",
  border: "1px solid #E2E3E8",
  borderRadius: 14,
  boxShadow: "0 1px 4px rgba(0,0,0,0.06), 0 0 0 1px rgba(0,0,0,0.02)",
};

// ── Severity tag ──────────────────────────────────────────────────────────────
function SevTag({ s }) {
  const sv = SEV[s];
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 8px", borderRadius: 6,
      background: sv.bg, color: sv.fg,
      border: `1px solid ${sv.border}`,
      fontSize: 10, fontWeight: 700, letterSpacing: "0.07em",
      fontFamily: "ui-monospace, monospace",
    }}>
      <span style={{ width: 5, height: 5, borderRadius: 1, background: sv.fg, flexShrink: 0 }} />
      {s}
    </span>
  );
}

// ── Grade panel ───────────────────────────────────────────────────────────────
function GradePanel({ grade, score, generated_at, summary }) {
  const g = GRADE[grade] || GRADE.F;
  const ts = new Date(generated_at).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });

  return (
    <div style={{
      ...card,
      minWidth: 220, flexShrink: 0,
      background: `linear-gradient(145deg, ${g.soft} 0%, #ffffff 55%)`,
      border: `1px solid ${g.hex}28`,
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      padding: "36px 28px",
      position: "relative", overflow: "hidden",
      userSelect: "none",
    }}>
      {/* Background letter ghost */}
      <span style={{
        position: "absolute",
        fontSize: 220, fontWeight: 900,
        color: g.hex, opacity: 0.06,
        lineHeight: 1,
        fontFamily: "system-ui, -apple-system, sans-serif",
        letterSpacing: "-0.05em",
        top: "50%", left: "50%",
        transform: "translate(-44%, -52%)",
        pointerEvents: "none",
        userSelect: "none",
      }}>
        {grade}
      </span>

      {/* Foreground letter */}
      <span style={{
        fontSize: 108, fontWeight: 900, lineHeight: 0.9,
        color: g.hex,
        fontFamily: "system-ui, -apple-system, sans-serif",
        letterSpacing: "-0.04em",
        position: "relative", zIndex: 1,
      }}>
        {grade}
      </span>

      <span style={{
        color: g.hex, fontSize: 11, fontWeight: 600,
        letterSpacing: "0.08em", textTransform: "uppercase",
        marginTop: 14, position: "relative", zIndex: 1,
        background: `${g.hex}15`,
        padding: "3px 10px", borderRadius: 99,
        border: `1px solid ${g.hex}25`,
      }}>
        {g.label}
      </span>

      <span style={{
        color: C.muted, fontSize: 10,
        fontFamily: "ui-monospace, monospace",
        marginTop: 10, position: "relative", zIndex: 1,
      }}>
        score {score}
      </span>

      <div style={{ width: "100%", height: 1, background: `${g.hex}20`, margin: "16px 0" }} />

      <span style={{ color: C.muted, fontSize: 10, textAlign: "center", zIndex: 1, position: "relative" }}>
        {ts}
      </span>
    </div>
  );
}

// ── Stat cards ────────────────────────────────────────────────────────────────
function StatCards({ summary }) {
  const items = [
    { k: "HIGH",   n: summary.high,   note: "Immediate action required", icon: "⚠" },
    { k: "MEDIUM", n: summary.medium, note: "Should be addressed soon",  icon: "●" },
    { k: "LOW",    n: summary.low,    note: "Best-practice gaps",        icon: "○" },
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, flex: 1, minWidth: 240 }}>
      {items.map(({ k, n, note, icon }) => {
        const sv = SEV[k];
        return (
          <div key={k} style={{
            ...card,
            padding: "16px 20px",
            display: "flex", alignItems: "center", gap: 16,
            background: n > 0 ? `linear-gradient(to right, ${sv.bg}, #ffffff 50%)` : C.white,
            border: n > 0 ? `1px solid ${sv.border}` : `1px solid ${C.border}`,
          }}>
            <span style={{
              fontSize: 44, fontWeight: 900,
              color: n > 0 ? sv.fg : C.muted,
              fontFamily: "ui-monospace, monospace",
              lineHeight: 1, minWidth: 56, textAlign: "right",
            }}>
              {n}
            </span>
            <div style={{ borderLeft: `2px solid ${n > 0 ? sv.border : C.border}`, paddingLeft: 14 }}>
              <p style={{ color: n > 0 ? sv.fg : C.muted, fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", margin: 0 }}>
                {k}
              </p>
              <p style={{ color: C.muted, fontSize: 11, margin: "2px 0 0" }}>{note}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Breakdown chart ───────────────────────────────────────────────────────────
function Breakdown({ findings }) {
  const map = {};
  findings.forEach(f => {
    const name = CHECK_LABELS[f.check] || f.check;
    if (!map[name]) map[name] = { name, HIGH: 0, MEDIUM: 0, LOW: 0 };
    map[name][f.severity]++;
  });
  const data = Object.values(map).sort(
    (a, b) => (b.HIGH * 10 + b.MEDIUM * 5 + b.LOW) - (a.HIGH * 10 + a.MEDIUM * 5 + a.LOW)
  );

  const Tip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ ...card, padding: "10px 14px" }}>
        <p style={{ color: C.text, fontSize: 12, fontWeight: 600, marginBottom: 6 }}>{label}</p>
        {payload.filter(p => p.value > 0).map(p => (
          <p key={p.dataKey} style={{ color: SEV[p.dataKey]?.fg, fontSize: 11, fontFamily: "monospace", margin: "2px 0" }}>
            {p.dataKey}: {p.value}
          </p>
        ))}
      </div>
    );
  };

  return (
    <div style={{ ...card, padding: "22px 24px" }}>
      <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 18 }}>
        Findings by check
      </p>
      <ResponsiveContainer width="100%" height={Math.max(data.length * 36 + 12, 80)}>
        <BarChart layout="vertical" data={data} margin={{ top: 0, right: 4, left: 0, bottom: 0 }}>
          <XAxis type="number" allowDecimals={false}
            tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }}
            axisLine={{ stroke: C.border }} tickLine={false}
          />
          <YAxis type="category" dataKey="name" width={132}
            tick={{ fill: C.sub, fontSize: 11 }}
            axisLine={false} tickLine={false}
          />
          <Tooltip content={<Tip />} cursor={{ fill: "rgba(0,0,0,0.025)" }} />
          <Bar dataKey="HIGH"   stackId="s" fill="#FCA5A5" barSize={11} />
          <Bar dataKey="MEDIUM" stackId="s" fill="#FCD34D" barSize={11} />
          <Bar dataKey="LOW"    stackId="s" fill="#93C5FD" barSize={11} radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
      {/* Legend */}
      <div style={{ display: "flex", gap: 16, marginTop: 14 }}>
        {[["HIGH", "#FCA5A5", "#B91C1C"], ["MEDIUM", "#FCD34D", "#B45309"], ["LOW", "#93C5FD", "#1D4ED8"]].map(([label, bg, fg]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: bg, display: "inline-block" }} />
            <span style={{ fontSize: 10, color: C.muted, fontFamily: "monospace" }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Finding row ───────────────────────────────────────────────────────────────
function Row({ f, i }) {
  const [open, setOpen] = useState(false);
  const sv = SEV[f.severity];
  return (
    <>
      <tr
        onClick={() => setOpen(o => !o)}
        style={{
          background: open ? sv.bg : i % 2 ? "#FAFAFA" : C.white,
          cursor: "pointer",
          transition: "background 0.12s",
        }}
      >
        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
          <SevTag s={f.severity} />
        </td>
        <td style={{ padding: "10px 8px", color: C.sub, fontSize: 11, whiteSpace: "nowrap" }}>
          {CHECK_LABELS[f.check] || f.check}
        </td>
        <td style={{ padding: "10px 8px", color: C.text, fontSize: 12, fontFamily: "ui-monospace, monospace", whiteSpace: "nowrap" }}>
          {f.resource_name}
        </td>
        <td style={{ padding: "10px 8px 10px 0", color: C.sub, fontSize: 12, maxWidth: 320 }}>
          <span style={{ display: "-webkit-box", WebkitLineClamp: 1, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
            {f.issues[0]}
          </span>
        </td>
        <td style={{ padding: "10px 16px", textAlign: "right", color: C.muted }}>
          {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5} style={{ padding: 0 }}>
            <div style={{
              padding: "18px 20px 20px 20px",
              background: sv.bg,
              borderTop: `1px solid ${sv.border}`,
              borderBottom: `1px solid ${sv.border}`,
              display: "grid", gridTemplateColumns: "1fr 1fr",
              gap: "16px 32px",
            }}>
              <div>
                <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>
                  What's wrong
                </p>
                <p style={{ color: C.text, fontSize: 12, lineHeight: 1.7 }}>{f.description}</p>
              </div>
              <div>
                <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>
                  How to fix it
                </p>
                <p style={{ color: "#1D4ED8", fontSize: 12, lineHeight: 1.7 }}>{f.remediation}</p>
              </div>
              <div style={{ gridColumn: "1 / -1" }}>
                <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 4 }}>ARN</p>
                <code style={{ color: C.sub, fontSize: 10, fontFamily: "ui-monospace, monospace" }}>{f.resource_arn}</code>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Findings table ────────────────────────────────────────────────────────────
function Table({ findings }) {
  const [filter, setFilter] = useState("ALL");
  const counts = { ALL: findings.length, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => counts[f.severity]++);

  const ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const visible = [...(filter === "ALL" ? findings : findings.filter(f => f.severity === filter))]
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

  return (
    <div style={{ ...card, overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center",
        borderBottom: `1px solid ${C.border}`,
        background: "#FAFAFA",
        padding: "0 6px",
      }}>
        <span style={{ color: C.muted, fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase", padding: "0 12px" }}>
          Findings
        </span>
        <div style={{ display: "flex", marginLeft: "auto" }}>
          {["ALL", "HIGH", "MEDIUM", "LOW"].map(tab => {
            const active = filter === tab;
            const sv = SEV[tab];
            const col = tab === "ALL" ? C.amber : sv?.fg;
            const bg  = tab === "ALL" ? "#FEF3C7" : sv?.bg;
            return (
              <button key={tab} onClick={() => setFilter(tab)} style={{
                background: "transparent", border: "none",
                borderBottom: active ? `2px solid ${col}` : "2px solid transparent",
                color: active ? col : C.muted,
                padding: "10px 14px",
                cursor: "pointer",
                fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                display: "flex", alignItems: "center", gap: 6,
                fontFamily: "ui-monospace, monospace",
                transition: "color 0.12s",
              }}>
                {tab}
                <span style={{
                  background: active ? bg : C.bg,
                  color: active ? col : C.muted,
                  border: `1px solid ${active ? (col + "40") : C.border}`,
                  borderRadius: 999, padding: "0 6px", fontSize: 9,
                }}>
                  {counts[tab]}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#FAFAFA", borderBottom: `1px solid ${C.border}` }}>
              {["Severity", "Check", "Resource", "Issue", ""].map((h, idx) => (
                <th key={idx} style={{
                  padding: "8px 16px", textAlign: "left",
                  color: C.muted, fontSize: 9,
                  fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase",
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0
              ? <tr><td colSpan={5} style={{ padding: 40, textAlign: "center", color: C.muted, fontSize: 13 }}>No findings for this filter.</td></tr>
              : visible.map((f, i) => <Row key={`${f.resource_arn}-${i}`} f={f} i={i} />)
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function Dashboard({ report, onReset, isSample }) {
  const { grade, score, account_id, generated_at, summary, findings } = report;
  const g = GRADE[grade] || GRADE.F;

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "system-ui, -apple-system, sans-serif" }}>

      {/* Accent stripe */}
      <div style={{ height: 3, background: `linear-gradient(to right, ${g.hex}, ${C.amber})` }} />

      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 28px",
        background: C.white,
        borderBottom: `1px solid ${C.border}`,
        position: "sticky", top: 0, zIndex: 10,
        boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <Shield size={15} color={C.amber} />
          <span style={{ fontWeight: 700, fontSize: 13, color: C.text, letterSpacing: "-0.01em" }}>
            IAM Scanner
          </span>
          {isSample && (
            <span style={{
              background: "#FEF3C7", color: C.amber,
              border: "1px solid #FDE68A",
              borderRadius: 5, padding: "2px 7px",
              fontSize: 8, fontWeight: 700, letterSpacing: "0.12em",
            }}>
              DEMO
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "ui-monospace, monospace" }}>
            {account_id}
          </span>
          <button onClick={onReset} style={{
            display: "flex", alignItems: "center", gap: 5,
            background: C.bg, border: `1px solid ${C.border}`,
            color: C.sub, borderRadius: 7, padding: "5px 12px",
            cursor: "pointer", fontSize: 11,
          }}>
            <RotateCcw size={10} /> New scan
          </button>
        </div>
      </div>

      {/* Body */}
      <div style={{ maxWidth: 1060, margin: "0 auto", padding: "28px 20px", display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", gap: 16, alignItems: "stretch", flexWrap: "wrap" }}>
          <GradePanel grade={grade} score={score} generated_at={generated_at} summary={summary} />
          <StatCards summary={summary} />
        </div>
        <Breakdown findings={findings} />
        <Table findings={findings} />
      </div>
    </div>
  );
}

// ── Upload ────────────────────────────────────────────────────────────────────
function Upload({ onLoad }) {
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState(null);
  const ref = useRef();

  const handle = useCallback(file => {
    if (!file) return;
    const r = new FileReader();
    r.onload = e => {
      try {
        const json = JSON.parse(e.target.result);
        if (!json.findings || !json.grade) throw new Error();
        onLoad({ report: json, isSample: false });
      } catch {
        setErr("Invalid file — upload the iam_scan_report.json from the scanner CLI.");
      }
    };
    r.readAsText(file);
  }, [onLoad]);

  return (
    <div style={{
      minHeight: "100vh", background: C.bg, color: C.text,
      fontFamily: "system-ui, -apple-system, sans-serif",
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      padding: 24,
    }}>
      {/* Top amber line */}
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, height: 3, background: C.amber }} />

      <Shield size={22} color={C.amber} style={{ marginBottom: 12 }} />
      <h1 style={{ fontSize: 20, fontWeight: 800, letterSpacing: "-0.02em", margin: 0, color: C.text }}>
        AWS IAM Scanner
      </h1>
      <p style={{ color: C.muted, fontSize: 12, margin: "6px 0 32px" }}>
        Upload a scan report to see your security findings
      </p>

      <div
        onDragOver={e => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={e => { e.preventDefault(); setDrag(false); handle(e.dataTransfer.files[0]); }}
        onClick={() => ref.current?.click()}
        style={{
          width: "100%", maxWidth: 400,
          border: `1.5px dashed ${drag ? C.amber : C.border}`,
          borderRadius: 14,
          background: drag ? "#FFFBEB" : C.white,
          padding: "40px 28px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 10,
          cursor: "pointer", transition: "all 0.15s",
          boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
        }}
      >
        <FileJson size={24} color={drag ? C.amber : C.muted} />
        <p style={{ fontWeight: 600, fontSize: 13, margin: 0, textAlign: "center", color: C.text }}>
          Drop{" "}
          <code style={{ fontFamily: "monospace", color: C.amber, fontSize: 12 }}>
            iam_scan_report.json
          </code>
        </p>
        <p style={{ color: C.muted, fontSize: 11, margin: 0 }}>or click to browse</p>
        <input ref={ref} type="file" accept=".json" style={{ display: "none" }}
          onChange={e => handle(e.target.files[0])} />
      </div>

      {err && <p style={{ color: "#B91C1C", fontSize: 11, marginTop: 10 }}>{err}</p>}

      <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "22px 0" }}>
        <div style={{ height: 1, width: 56, background: C.border }} />
        <span style={{ color: C.muted, fontSize: 10 }}>or</span>
        <div style={{ height: 1, width: 56, background: C.border }} />
      </div>

      <button
        onClick={() => onLoad({ report: SAMPLE, isSample: true })}
        style={{
          background: C.amber, color: "#fff",
          border: "none", borderRadius: 8,
          padding: "9px 26px", fontSize: 13, fontWeight: 700,
          cursor: "pointer", letterSpacing: "-0.01em",
          boxShadow: "0 1px 3px rgba(0,0,0,0.15)",
        }}
      >
        Try it with demo data
      </button>
      <p style={{ color: C.muted, fontSize: 10, marginTop: 8, textAlign: "center", maxWidth: 280, lineHeight: 1.5 }}>
        Loads a pre-built example report so you can explore the dashboard without running the scanner
      </p>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [s, setS] = useState(null);
  if (!s) return <Upload onLoad={setS} />;
  return <Dashboard report={s.report} isSample={s.isSample} onReset={() => setS(null)} />;
}
