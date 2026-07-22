"use client";

import { useState, useRef, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, RotateCcw, FileJson, ChevronDown, ChevronUp, Copy, Check, BookOpen, Upload as UploadIcon } from "lucide-react";

// ── Demo scenarios ────────────────────────────────────────────────────────────
const SCENARIOS = [
  {
    id: "clean_a",
    label: "Security best-in-class",
    description: "A perfectly maintained account — zero findings across all 7 checks",
    grade: "A", score: 0,
    summary: { total: 0, high: 0, medium: 0, low: 0 },
    generated_at: "2026-07-21T06:00:00.000Z",
    account_id: "112233445566",
    findings: [],
  },
  {
    id: "clean_b",
    label: "Security-mature team",
    description: "Well-maintained with only minor housekeeping items remaining",
    grade: "B", score: 11,
    summary: { total: 5, high: 0, medium: 1, low: 4 },
    generated_at: "2026-07-21T08:00:44.000Z",
    account_id: "502918374651",
    findings: [
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "legacy-script → key_1", resource_arn: "arn:aws:iam::user/legacy-script/key_1", issues: ["Key not rotated in 94 days (threshold: 90)"], description: "Access key 1 for legacy-script is 4 days past the rotation threshold.", remediation: "Rotate as part of your regular 90-day rotation schedule." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "OldMigrationRole", resource_arn: "arn:aws:iam::502918374651:role/OldMigrationRole", issues: ["Role not assumed in 96 days (threshold: 90)"], description: "Used for a one-time database migration and not needed since.", remediation: "Confirm migration is complete and delete this role." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "StagingTestRole", resource_arn: "arn:aws:iam::502918374651:role/StagingTestRole", issues: ["Role not assumed in 112 days (threshold: 90)"], description: "Staging test role not used since last quarter.", remediation: "Check if staging tests are still active. Delete if not." },
      { check: "mfa_enforcement", severity: "LOW", resource_type: "User", resource_name: "vendor-api-user", resource_arn: "arn:aws:iam::502918374651:user/vendor-api-user", issues: ["User has no MFA device enrolled (programmatic-only access)"], description: "External vendor API user has no MFA. Consider migrating to cross-account role assumption.", remediation: "Work with the vendor to migrate from long-lived keys to cross-account role assumption." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "TempAnalyticsRole", resource_arn: "arn:aws:iam::502918374651:role/TempAnalyticsRole", issues: ["Role has NEVER been assumed (91 days since creation)"], description: "Created for an analytics project that was deprioritized before launch.", remediation: "Delete this role since the project was cancelled." },
    ],
  },
  {
    id: "typical",
    label: "Growing company",
    description: "A real-world mid-stage account with common misconfigurations",
    grade: "C", score: 37,
    summary: { total: 11, high: 1, medium: 5, low: 5 },
    generated_at: "2026-07-21T14:32:18.000Z",
    account_id: "391024857364",
    findings: [
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "User", resource_name: "deploy-admin", resource_arn: "arn:aws:iam::391024857364:user/deploy-admin", issues: ["User has console (password) access but NO MFA device enrolled"], description: "User 'deploy-admin' can log into the AWS console with just a password. A single phished or leaked password grants full console access.", remediation: "In IAM → user → Security credentials → Assign MFA device." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "ci-runner → key_1", resource_arn: "arn:aws:iam::user/ci-runner/key_1", issues: ["Key not rotated in 127 days (threshold: 90)"], description: "Access key 1 for user 'ci-runner' has not been rotated in 127 days.", remediation: "Rotate the key or switch to IAM roles for CI/CD access." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "deploy-user → key_2", resource_arn: "arn:aws:iam::user/deploy-user/key_2", issues: ["Key is active but has NEVER been used (45 days old)"], description: "This access key has been active for 45 days and has never been used.", remediation: "Deactivate and delete this key immediately." },
      { check: "direct_attachment", severity: "MEDIUM", resource_type: "User", resource_name: "analyst-jane", resource_arn: "arn:aws:iam::391024857364:user/analyst-jane", issues: ["Has 2 managed policies attached directly: S3ReadOnlyAccess, CloudWatchReadOnlyAccess"], description: "User 'analyst-jane' has policies attached directly rather than via a group.", remediation: "Create a group, attach policies there, add the user, remove direct attachments." },
      { check: "direct_attachment", severity: "MEDIUM", resource_type: "User", resource_name: "developer-bob", resource_arn: "arn:aws:iam::391024857364:user/developer-bob", issues: ["Has 1 inline policy: DeveloperOverrides"], description: "User 'developer-bob' has an inline policy that is harder to audit.", remediation: "Convert to a managed policy and attach via a group." },
      { check: "s3_public_access", severity: "MEDIUM", resource_type: "S3/Bucket", resource_name: "my-app-assets-staging", resource_arn: "arn:aws:s3:::my-app-assets-staging", issues: ["Block public ACLs is disabled", "Ignore public ACLs is disabled"], description: "Staging assets bucket has Block Public Access settings disabled.", remediation: "Enable all four Block Public Access settings unless intentionally public." },
      { check: "mfa_enforcement", severity: "LOW", resource_type: "User", resource_name: "ci-runner", resource_arn: "arn:aws:iam::391024857364:user/ci-runner", issues: ["User has no MFA device enrolled (programmatic-only access)"], description: "Programmatic user with no MFA enrolled.", remediation: "Prefer IAM roles over long-lived IAM users for programmatic access." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "LegacyLambdaRole", resource_arn: "arn:aws:iam::391024857364:role/LegacyLambdaRole", issues: ["Role not assumed in 142 days (threshold: 90)"], description: "Role not used in 142 days.", remediation: "Confirm still needed. If not, delete it." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "OldCodeBuildRole", resource_arn: "arn:aws:iam::391024857364:role/OldCodeBuildRole", issues: ["Role has NEVER been assumed (67 days since creation)"], description: "This role has never been assumed in 67 days.", remediation: "Verify still needed. If not, delete it." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "DataPipelineRole", resource_arn: "arn:aws:iam::391024857364:role/DataPipelineRole", issues: ["Role not assumed in 203 days (threshold: 90)"], description: "Role not used in over 6 months.", remediation: "Delete if no longer in use." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "BackupAutomationRole", resource_arn: "arn:aws:iam::391024857364:role/BackupAutomationRole", issues: ["Role not assumed in 118 days (threshold: 90)"], description: "Role not used in 118 days.", remediation: "Confirm still needed. If inactive, delete it." },
    ],
  },
  {
    id: "legacy",
    label: "Legacy enterprise",
    description: "Years of technical debt — significant risk across multiple categories",
    grade: "D", score: 71,
    summary: { total: 12, high: 4, medium: 5, low: 3 },
    generated_at: "2026-07-21T11:45:22.000Z",
    account_id: "774401928350",
    findings: [
      { check: "wildcard_policy", severity: "HIGH", resource_type: "ManagedPolicy", resource_name: "DevTeamAccess", resource_arn: "arn:aws:iam::774401928350:policy/DevTeamAccess", issues: ["Action '*' on Resource '*' — full administrator access"], description: "Policy 'DevTeamAccess' grants full admin and is attached to the entire dev team.", remediation: "Scope down to specific services each team member actually needs." },
      { check: "wildcard_policy", severity: "HIGH", resource_type: "ManagedPolicy", resource_name: "LegacyAutomationPolicy", resource_arn: "arn:aws:iam::774401928350:policy/LegacyAutomationPolicy", issues: ["Service wildcard(s) ['s3:*', 'ec2:*', 'iam:*'] on Resource '*'"], description: "A legacy automation policy grants full S3, EC2, and IAM control to a service account.", remediation: "Replace with specific actions required by the automation scripts." },
      { check: "trust_policy", severity: "HIGH", resource_type: "Role", resource_name: "VendorIntegrationRole", resource_arn: "arn:aws:iam::774401928350:role/VendorIntegrationRole", issues: ["Cross-account trust to arn:aws:iam::399012847650:root with no ExternalId condition (confused deputy vulnerability)"], description: "This cross-account role has no ExternalId condition, making it vulnerable to confused deputy attacks.", remediation: "Add an ExternalId condition to the trust policy and share the ID privately with the vendor." },
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "User", resource_name: "ops-manager", resource_arn: "arn:aws:iam::774401928350:user/ops-manager", issues: ["User has console (password) access but NO MFA device enrolled"], description: "The ops manager has console access with no MFA — a high-value target for attackers.", remediation: "Assign MFA immediately and enforce it via IAM policy." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "automation-svc → key_1", resource_arn: "arn:aws:iam::user/automation-svc/key_1", issues: ["Key not rotated in 445 days (threshold: 90)"], description: "This service account key hasn't been rotated in over a year.", remediation: "Rotate immediately and set up automated rotation." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "backup-svc → key_1", resource_arn: "arn:aws:iam::user/backup-svc/key_1", issues: ["Key not rotated in 312 days (threshold: 90)"], description: "The backup service key is over 10 months old.", remediation: "Rotate and consider switching to IAM roles." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "monitoring → key_2", resource_arn: "arn:aws:iam::user/monitoring/key_2", issues: ["Key is active but has NEVER been used (67 days old)"], description: "A monitoring key that was created but never used.", remediation: "Delete this key. It was likely created by mistake." },
      { check: "direct_attachment", severity: "MEDIUM", resource_type: "User", resource_name: "contractor-alex", resource_arn: "arn:aws:iam::774401928350:user/contractor-alex", issues: ["Has 4 managed policies attached directly: EC2FullAccess, S3FullAccess, RDSFullAccess, LambdaFullAccess"], description: "A contractor has four full-access policies attached directly — massively over-provisioned.", remediation: "Scope down to exactly what the contractor needs. Set an expiry date on the access." },
      { check: "s3_public_access", severity: "MEDIUM", resource_type: "S3/AccountBPA", resource_name: "Account-level Block Public Access", resource_arn: "arn:aws:s3:::*", issues: ["Block public bucket policies is disabled", "Restrict public buckets is disabled"], description: "Two of the four account-level Block Public Access settings are disabled.", remediation: "Enable all four settings in S3 → Block Public Access (account settings)." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "DecommissionedAppRole", resource_arn: "arn:aws:iam::774401928350:role/DecommissionedAppRole", issues: ["Role not assumed in 380 days (threshold: 90)"], description: "This role belongs to an application that was decommissioned over a year ago.", remediation: "Delete immediately. This role has no business purpose." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "TestEnvironmentRole", resource_arn: "arn:aws:iam::774401928350:role/TestEnvironmentRole", issues: ["Role not assumed in 215 days (threshold: 90)"], description: "Test environment role that hasn't been touched since Q4 last year.", remediation: "Check if the test environment still exists. Delete if not." },
      { check: "mfa_enforcement", severity: "LOW", resource_type: "User", resource_name: "automation-svc", resource_arn: "arn:aws:iam::774401928350:user/automation-svc", issues: ["User has no MFA device enrolled (programmatic-only access)"], description: "Programmatic service account with no MFA.", remediation: "Migrate to IAM roles for service-to-service authentication." },
    ],
  },
  {
    id: "critical",
    label: "Startup chaos",
    description: "What a freshly-created, poorly-configured account looks like",
    grade: "F", score: 138,
    summary: { total: 18, high: 9, medium: 5, low: 4 },
    generated_at: "2026-07-21T09:14:03.000Z",
    account_id: "847392015648",
    findings: [
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "Root", resource_name: "root", resource_arn: "arn:aws:iam::root", issues: ["Root account has an active access key"], description: "The root account has an active access key. Root keys should never exist.", remediation: "Delete root access keys immediately. Use IAM users or assume-role for all programmatic access." },
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "Root", resource_name: "root", resource_arn: "arn:aws:iam::root", issues: ["Root account does not have MFA enabled"], description: "The AWS root account has no MFA. Root account compromise is catastrophic.", remediation: "Enable MFA on the root account immediately using a hardware key or virtual MFA device." },
      { check: "wildcard_policy", severity: "HIGH", resource_type: "User", resource_name: "founders → AdministratorAccess", resource_arn: "arn:aws:iam::847392015648:user/founders", issues: ["Has AWS managed policy AdministratorAccess directly attached — full admin access"], description: "User 'founders' has AdministratorAccess attached directly, granting full control over every AWS service.", remediation: "Remove AdministratorAccess. Create a least-privilege policy covering only what this user actually needs." },
      { check: "wildcard_policy", severity: "HIGH", resource_type: "ManagedPolicy", resource_name: "EveryonePolicy", resource_arn: "arn:aws:iam::847392015648:policy/EveryonePolicy", issues: ["Action '*' on Resource '*' — full administrator access"], description: "Managed policy 'EveryonePolicy' grants full administrator access and is attached to every developer.", remediation: "Delete this policy immediately and replace with per-role least-privilege policies." },
      { check: "s3_public_access", severity: "HIGH", resource_type: "S3/Bucket", resource_name: "startup-user-uploads-prod", resource_arn: "arn:aws:s3:::startup-user-uploads-prod", issues: ["ACL grants FULL_CONTROL to AllUsers (public internet)"], description: "The production user uploads bucket is fully public — anyone can read, write, and delete files.", remediation: "Remove the public ACL grant immediately, enable Block Public Access, and audit what data was exposed." },
      { check: "s3_public_access", severity: "HIGH", resource_type: "S3/Bucket", resource_name: "startup-db-backups", resource_arn: "arn:aws:s3:::startup-db-backups", issues: ["Bucket policy is flagged as public by AWS"], description: "The database backups bucket is publicly accessible.", remediation: "Remove the public bucket policy immediately. Database backups must never be publicly accessible." },
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "User", resource_name: "alice", resource_arn: "arn:aws:iam::847392015648:user/alice", issues: ["User has console (password) access but NO MFA device enrolled"], description: "User 'alice' can log into the AWS console with just a password.", remediation: "Assign an MFA device immediately via IAM → user → Security credentials." },
      { check: "mfa_enforcement", severity: "HIGH", resource_type: "User", resource_name: "bob", resource_arn: "arn:aws:iam::847392015648:user/bob", issues: ["User has console (password) access but NO MFA device enrolled"], description: "User 'bob' can log into the AWS console with just a password.", remediation: "Assign an MFA device immediately via IAM → user → Security credentials." },
      { check: "trust_policy", severity: "HIGH", resource_type: "Role", resource_name: "CrossAccountDataRole", resource_arn: "arn:aws:iam::847392015648:role/CrossAccountDataRole", issues: ["Principal: '*' — ANY entity globally can assume this role"], description: "Role 'CrossAccountDataRole' can be assumed by any entity in the world.", remediation: "Restrict the Principal to specific account IDs and add an ExternalId condition immediately." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "alice → key_1", resource_arn: "arn:aws:iam::user/alice/key_1", issues: ["Key not rotated in 312 days (threshold: 90)"], description: "Alice's access key hasn't been rotated in over 10 months.", remediation: "Rotate immediately. Set a calendar reminder to rotate every 90 days." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "deploy-bot → key_1", resource_arn: "arn:aws:iam::user/deploy-bot/key_1", issues: ["Key not rotated in 287 days (threshold: 90)"], description: "The deploy bot key hasn't been rotated in nearly a year.", remediation: "Rotate and consider switching to short-lived credentials via IAM roles." },
      { check: "unused_keys", severity: "MEDIUM", resource_type: "AccessKey", resource_name: "ci-bot → key_2", resource_arn: "arn:aws:iam::user/ci-bot/key_2", issues: ["Key is active but has NEVER been used (134 days old)"], description: "This key was created 134 days ago and has never been used.", remediation: "Delete this key immediately." },
      { check: "direct_attachment", severity: "MEDIUM", resource_type: "User", resource_name: "charlie", resource_arn: "arn:aws:iam::847392015648:user/charlie", issues: ["Has 3 managed policies attached directly: S3FullAccess, RDSFullAccess, EC2FullAccess"], description: "User 'charlie' has three full-access policies attached directly.", remediation: "Scope down to read-only where possible. Attach via groups." },
      { check: "direct_attachment", severity: "MEDIUM", resource_type: "User", resource_name: "dana", resource_arn: "arn:aws:iam::847392015648:user/dana", issues: ["Has 1 inline policy: InternalToolsAccess"], description: "User 'dana' has an inline policy that is invisible in the IAM policy list.", remediation: "Convert to a managed policy and attach via a group." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "OldLambdaRole", resource_arn: "arn:aws:iam::847392015648:role/OldLambdaRole", issues: ["Role not assumed in 198 days (threshold: 90)"], description: "This Lambda role has not been used in 198 days.", remediation: "Delete if no longer needed." },
      { check: "unused_role", severity: "LOW", resource_type: "Role", resource_name: "DeprecatedPipelineRole", resource_arn: "arn:aws:iam::847392015648:role/DeprecatedPipelineRole", issues: ["Role has NEVER been assumed (88 days since creation)"], description: "Created 88 days ago and never used.", remediation: "Delete this role to reduce your attack surface." },
      { check: "mfa_enforcement", severity: "LOW", resource_type: "User", resource_name: "deploy-bot", resource_arn: "arn:aws:iam::847392015648:user/deploy-bot", issues: ["User has no MFA device enrolled (programmatic-only access)"], description: "Programmatic user with no MFA enrolled.", remediation: "Prefer IAM roles with short-lived credentials over long-lived IAM users." },
      { check: "mfa_enforcement", severity: "LOW", resource_type: "User", resource_name: "ci-bot", resource_arn: "arn:aws:iam::847392015648:user/ci-bot", issues: ["User has no MFA device enrolled (programmatic-only access)"], description: "Programmatic user with no MFA enrolled.", remediation: "Prefer IAM roles with short-lived credentials over long-lived IAM users." },
    ],
  },
];

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

// ── Code block with copy button ───────────────────────────────────────────────
function Code({ children, lang = "bash" }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(children.trim());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div style={{ position: "relative", margin: "10px 0" }}>
      <pre style={{
        background: "#1E1E2E",
        color: "#CDD6F4",
        borderRadius: 10,
        padding: "14px 48px 14px 18px",
        fontSize: 13,
        fontFamily: "ui-monospace, monospace",
        lineHeight: 1.7,
        margin: 0,
        overflowX: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
      }}>
        {children.trim()}
      </pre>
      <button onClick={copy} style={{
        position: "absolute", top: 10, right: 10,
        background: copied ? "#22C55E22" : "#ffffff18",
        border: "none", borderRadius: 6,
        color: copied ? "#22C55E" : "#9CA3AF",
        padding: "4px 8px", cursor: "pointer",
        fontSize: 11, display: "flex", alignItems: "center", gap: 4,
        transition: "all 0.15s",
      }}>
        {copied ? <Check size={12} /> : <Copy size={12} />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

// ── Step container ────────────────────────────────────────────────────────────
function Step({ number, title, children }) {
  return (
    <div style={{
      display: "flex", gap: 20,
      padding: "28px 0",
      borderBottom: `1px solid ${C.border}`,
    }}>
      <div style={{ flexShrink: 0 }}>
        <div style={{
          width: 36, height: 36, borderRadius: "50%",
          background: C.amber, color: "#fff",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontWeight: 800, fontSize: 15, fontFamily: "ui-monospace, monospace",
        }}>
          {number}
        </div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <h3 style={{ margin: "4px 0 12px", fontSize: 16, fontWeight: 700, color: C.text }}>
          {title}
        </h3>
        {children}
      </div>
    </div>
  );
}

// ── Callout box ───────────────────────────────────────────────────────────────
function Note({ children, type = "info" }) {
  const styles = {
    info:    { bg: "#EFF6FF", border: "#BFDBFE", color: "#1D4ED8", icon: "ℹ️" },
    warning: { bg: "#FFFBEB", border: "#FDE68A", color: "#B45309", icon: "⚠️" },
    tip:     { bg: "#F0FDF4", border: "#BBF7D0", color: "#15803D", icon: "💡" },
  };
  const s = styles[type];
  return (
    <div style={{
      background: s.bg, border: `1px solid ${s.border}`,
      borderRadius: 8, padding: "10px 14px",
      fontSize: 13, color: s.color, lineHeight: 1.6,
      margin: "10px 0",
      display: "flex", gap: 8,
    }}>
      <span>{s.icon}</span>
      <span>{children}</span>
    </div>
  );
}

// ── Platform toggle ───────────────────────────────────────────────────────────
function PlatformToggle({ value, onChange }) {
  return (
    <div style={{ display: "flex", gap: 4, margin: "10px 0 4px" }}>
      {["Mac / Linux", "Windows"].map(p => (
        <button key={p} onClick={() => onChange(p)} style={{
          background: value === p ? C.amber : C.bg,
          color: value === p ? "#fff" : C.sub,
          border: `1px solid ${value === p ? C.amber : C.border}`,
          borderRadius: 6, padding: "4px 12px",
          cursor: "pointer", fontSize: 12, fontWeight: 600,
          transition: "all 0.12s",
        }}>
          {p}
        </button>
      ))}
    </div>
  );
}

// ── Guide ─────────────────────────────────────────────────────────────────────
function Guide({ onUpload }) {
  const [platform, setPlatform] = useState("Mac / Linux");
  const isMac = platform === "Mac / Linux";

  return (
    <div style={{ minHeight: "100vh", background: C.bg, fontFamily: "system-ui, -apple-system, sans-serif" }}>
      {/* Header */}
      <div style={{
        background: C.white, borderBottom: `1px solid ${C.border}`,
        padding: "13px 28px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        position: "sticky", top: 0, zIndex: 10,
        boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <Shield size={15} color={C.amber} />
          <span style={{ fontWeight: 700, fontSize: 13, color: C.text }}>IAM Scanner</span>
        </div>
        <button onClick={onUpload} style={{
          display: "flex", alignItems: "center", gap: 6,
          background: C.amber, color: "#fff",
          border: "none", borderRadius: 7, padding: "6px 14px",
          cursor: "pointer", fontSize: 12, fontWeight: 600,
        }}>
          <UploadIcon size={12} /> Upload report
        </button>
      </div>

      <div style={{ maxWidth: 740, margin: "0 auto", padding: "40px 24px 80px" }}>
        {/* Intro */}
        <div style={{ marginBottom: 8 }}>
          <h1 style={{ fontSize: 28, fontWeight: 800, color: C.text, margin: "0 0 12px", letterSpacing: "-0.02em" }}>
            How to scan your AWS account
          </h1>
          <p style={{ color: C.sub, fontSize: 15, lineHeight: 1.7, margin: 0 }}>
            This guide walks you through scanning your AWS account for security issues — step by step, from scratch.
            You don't need to be a developer, but you'll need access to a terminal and an AWS account.
            The whole process takes about 10 minutes.
          </p>
        </div>

        {/* What it does */}
        <div style={{ ...card, padding: "18px 22px", margin: "24px 0 0" }}>
          <p style={{ color: C.muted, fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase", margin: "0 0 10px" }}>What the scanner checks</p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 24px" }}>
            {[
              "Overly permissive IAM policies",
              "Users without MFA enabled",
              "Stale or unused access keys",
              "Publicly exposed S3 buckets",
              "Misconfigured trust policies",
              "Inactive roles that should be deleted",
            ].map(item => (
              <div key={item} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: C.sub }}>
                <span style={{ color: "#22C55E", fontWeight: 700 }}>✓</span> {item}
              </div>
            ))}
          </div>
        </div>

        {/* Steps */}
        <div style={{ marginTop: 32 }}>

          <Step number={1} title="Open your terminal">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 10px" }}>
              The terminal (also called the command line) is a text-based way to control your computer.
              Don't let it intimidate you — you'll just be copying and pasting commands into it.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              {[
                { os: "Mac", how: "Press ⌘ + Space, type Terminal, press Enter" },
                { os: "Windows", how: "Press the Windows key, type PowerShell, press Enter" },
              ].map(({ os, how }) => (
                <div key={os} style={{ background: C.bg, borderRadius: 8, padding: "12px 14px", border: `1px solid ${C.border}` }}>
                  <p style={{ fontWeight: 700, fontSize: 13, color: C.text, margin: "0 0 4px" }}>{os}</p>
                  <p style={{ color: C.sub, fontSize: 12, margin: 0 }}>{how}</p>
                </div>
              ))}
            </div>
          </Step>

          <Step number={2} title="Check that Python is installed">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 10px" }}>
              The scanner is written in Python. Paste this into your terminal and hit Enter:
            </p>
            <Code>python3 --version</Code>
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "10px 0" }}>
              You should see something like <code style={{ background: C.bg, padding: "1px 6px", borderRadius: 4, fontFamily: "monospace", fontSize: 13 }}>Python 3.11.0</code>.
              If you get "command not found", download Python from{" "}
              <a href="https://python.org" target="_blank" rel="noopener noreferrer" style={{ color: C.amber }}>python.org</a>{" "}
              — grab the latest version and install it.
            </p>
            <Note type="tip">
              Python 3.9 or newer will work. Anything older than that, install the latest version.
            </Note>
          </Step>

          <Step number={3} title="Download the scanner">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 10px" }}>
              If you have Git installed, run this command to download the scanner:
            </p>
            <Code>git clone https://github.com/agandbhir123/aws-iam-scanner.git
cd aws-iam-scanner</Code>
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "12px 0 10px" }}>
              No Git? That's fine —{" "}
              <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ color: C.amber }}>
                go to the GitHub page
              </a>
              , click the green <strong>Code</strong> button, then click <strong>Download ZIP</strong>.
              Extract it, then navigate to the folder in your terminal:
            </p>
            <PlatformToggle value={platform} onChange={setPlatform} />
            <Code>{isMac
              ? "cd ~/Downloads/aws-iam-scanner"
              : "cd C:\\Users\\YourName\\Downloads\\aws-iam-scanner"
            }</Code>
          </Step>

          <Step number={4} title="Install dependencies">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 6px" }}>
              The scanner relies on a few helper packages. Think of this like installing apps —
              you only need to do it once. Run these three commands in order:
            </p>
            <PlatformToggle value={platform} onChange={setPlatform} />
            <Code>{isMac
              ? `python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt`
              : `python3 -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt`
            }</Code>
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "10px 0 0" }}>
              You'll see a bunch of text scroll past — that's normal. Wait until it says <code style={{ background: C.bg, padding: "1px 6px", borderRadius: 4, fontFamily: "monospace", fontSize: 13 }}>Successfully installed</code>.
            </p>
            <Note type="info">
              The first command creates an isolated Python environment just for this project. The second activates it. The third installs the packages. You need to run the second command again every time you open a new terminal window.
            </Note>
          </Step>

          <Step number={5} title="Get your AWS credentials">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 12px" }}>
              AWS credentials are like a special API key that lets programs read your account.
              The scanner only needs <strong>read access</strong> — it can't change or delete anything.
              Here's how to create a dedicated user for it:
            </p>

            {[
              { n: "1", t: "Log into AWS", d: "Go to console.aws.amazon.com and sign in." },
              { n: "2", t: "Go to IAM", d: 'Search for "IAM" in the top search bar and open it.' },
              { n: "3", t: "Create a user", d: 'Click Users → Create user. Name it "scanner-user".' },
              { n: "4", t: "Attach a policy", d: 'Choose "Attach policies directly". Search for "ReadOnlyAccess" and check the one that says exactly ReadOnlyAccess (type: AWS managed - job function). Hit Next → Create user.' },
              { n: "5", t: "Create an access key", d: 'Click on scanner-user → Security credentials tab → Create access key → choose "Command Line Interface (CLI)" → Create.' },
              { n: "6", t: "Copy your credentials", d: "You'll see an Access key ID and a Secret access key. Copy both — you won't be able to see the secret again after you close this page." },
            ].map(({ n, t, d }) => (
              <div key={n} style={{ display: "flex", gap: 12, marginBottom: 10 }}>
                <span style={{
                  width: 22, height: 22, borderRadius: "50%",
                  background: C.bg, border: `1px solid ${C.border}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: C.sub, flexShrink: 0, marginTop: 1,
                }}>{n}</span>
                <div>
                  <span style={{ fontWeight: 600, fontSize: 13, color: C.text }}>{t} — </span>
                  <span style={{ fontSize: 13, color: C.sub }}>{d}</span>
                </div>
              </div>
            ))}

            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "14px 0 8px" }}>
              Now paste your credentials into the terminal. Replace the values with your actual keys:
            </p>
            <Code>{isMac
              ? `export AWS_ACCESS_KEY_ID=AKIA...your key here...
export AWS_SECRET_ACCESS_KEY=...your secret here...
export AWS_DEFAULT_REGION=us-east-1`
              : `$env:AWS_ACCESS_KEY_ID="AKIA...your key here..."
$env:AWS_SECRET_ACCESS_KEY="...your secret here..."
$env:AWS_DEFAULT_REGION="us-east-1"`
            }</Code>
            <Note type="warning">
              Never share your credentials with anyone. Don't paste them into chat apps, emails, or websites (including this one — credentials should only go in your terminal).
            </Note>
          </Step>

          <Step number={6} title="Run the scanner">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 10px" }}>
              You're ready. Run this command:
            </p>
            <Code>python -m scanner</Code>
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "10px 0" }}>
              The scanner will connect to your AWS account and check it across 7 security categories.
              This takes about 1–2 minutes. When it's done, you'll see a report in your terminal
              and a file called <code style={{ background: C.bg, padding: "1px 6px", borderRadius: 4, fontFamily: "monospace", fontSize: 13 }}>iam_scan_report.json</code> will
              appear in the same folder as the scanner.
            </p>
            <Note type="tip">
              Add --verbose to see remediation steps right in the terminal: <code style={{ fontFamily: "monospace" }}>python -m scanner --verbose</code>
            </Note>
          </Step>

          <Step number={7} title="Upload your results here">
            <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.7, margin: "0 0 14px" }}>
              Come back to this page and upload the <code style={{ background: C.bg, padding: "1px 6px", borderRadius: 4, fontFamily: "monospace", fontSize: 13 }}>iam_scan_report.json</code> file.
              You'll see your findings laid out with a security grade, severity breakdown, and step-by-step fix instructions for each issue.
            </p>
            <button onClick={onUpload} style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              background: C.amber, color: "#fff",
              border: "none", borderRadius: 8,
              padding: "10px 22px", fontSize: 14, fontWeight: 700,
              cursor: "pointer",
              boxShadow: "0 1px 3px rgba(0,0,0,0.15)",
            }}>
              <UploadIcon size={14} /> Upload report
            </button>
          </Step>

        </div>

        {/* Footer */}
        <div style={{ textAlign: "center", marginTop: 40 }}>
          <p style={{ color: C.muted, fontSize: 12 }}>
            Questions? Open an issue on{" "}
            <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ color: C.amber }}>
              GitHub
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

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
function GradePanel({ grade, score, generated_at }) {
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
      <span style={{
        position: "absolute", fontSize: 220, fontWeight: 900,
        color: g.hex, opacity: 0.06, lineHeight: 1,
        fontFamily: "system-ui, -apple-system, sans-serif",
        letterSpacing: "-0.05em",
        top: "50%", left: "50%",
        transform: "translate(-44%, -52%)",
        pointerEvents: "none", userSelect: "none",
      }}>{grade}</span>
      <span style={{
        fontSize: 108, fontWeight: 900, lineHeight: 0.9,
        color: g.hex, fontFamily: "system-ui, -apple-system, sans-serif",
        letterSpacing: "-0.04em", position: "relative", zIndex: 1,
      }}>{grade}</span>
      <span style={{
        color: g.hex, fontSize: 11, fontWeight: 600,
        letterSpacing: "0.08em", textTransform: "uppercase",
        marginTop: 14, position: "relative", zIndex: 1,
        background: `${g.hex}15`, padding: "3px 10px", borderRadius: 99,
        border: `1px solid ${g.hex}25`,
      }}>{g.label}</span>
      <span style={{ color: C.muted, fontSize: 10, fontFamily: "ui-monospace, monospace", marginTop: 10, position: "relative", zIndex: 1 }}>
        score {score}
      </span>
      <div style={{ width: "100%", height: 1, background: `${g.hex}20`, margin: "16px 0" }} />
      <span style={{ color: C.muted, fontSize: 10, textAlign: "center", zIndex: 1, position: "relative" }}>{ts}</span>
    </div>
  );
}

// ── Stat cards ────────────────────────────────────────────────────────────────
function StatCards({ summary }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, flex: 1, minWidth: 240 }}>
      {[
        { k: "HIGH",   n: summary.high,   note: "Immediate action required" },
        { k: "MEDIUM", n: summary.medium, note: "Should be addressed soon"  },
        { k: "LOW",    n: summary.low,    note: "Best-practice gaps"        },
      ].map(({ k, n, note }) => {
        const sv = SEV[k];
        return (
          <div key={k} style={{
            ...card, padding: "16px 20px",
            display: "flex", alignItems: "center", gap: 16,
            background: n > 0 ? `linear-gradient(to right, ${sv.bg}, #ffffff 50%)` : C.white,
            border: n > 0 ? `1px solid ${sv.border}` : `1px solid ${C.border}`,
          }}>
            <span style={{ fontSize: 44, fontWeight: 900, color: n > 0 ? sv.fg : C.muted, fontFamily: "ui-monospace, monospace", lineHeight: 1, minWidth: 56, textAlign: "right" }}>{n}</span>
            <div style={{ borderLeft: `2px solid ${n > 0 ? sv.border : C.border}`, paddingLeft: 14 }}>
              <p style={{ color: n > 0 ? sv.fg : C.muted, fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", margin: 0 }}>{k}</p>
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
  const data = Object.values(map).sort((a, b) => (b.HIGH * 10 + b.MEDIUM * 5 + b.LOW) - (a.HIGH * 10 + a.MEDIUM * 5 + a.LOW));
  const Tip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ ...card, padding: "10px 14px" }}>
        <p style={{ color: C.text, fontSize: 12, fontWeight: 600, marginBottom: 6 }}>{label}</p>
        {payload.filter(p => p.value > 0).map(p => (
          <p key={p.dataKey} style={{ color: SEV[p.dataKey]?.fg, fontSize: 11, fontFamily: "monospace", margin: "2px 0" }}>{p.dataKey}: {p.value}</p>
        ))}
      </div>
    );
  };
  return (
    <div style={{ ...card, padding: "22px 24px" }}>
      <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 18 }}>Findings by check</p>
      <ResponsiveContainer width="100%" height={Math.max(data.length * 36 + 12, 80)}>
        <BarChart layout="vertical" data={data} margin={{ top: 0, right: 4, left: 0, bottom: 0 }}>
          <XAxis type="number" allowDecimals={false} tick={{ fill: C.muted, fontSize: 10, fontFamily: "monospace" }} axisLine={{ stroke: C.border }} tickLine={false} />
          <YAxis type="category" dataKey="name" width={132} tick={{ fill: C.sub, fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip content={<Tip />} cursor={{ fill: "rgba(0,0,0,0.025)" }} />
          <Bar dataKey="HIGH"   stackId="s" fill="#FCA5A5" barSize={11} />
          <Bar dataKey="MEDIUM" stackId="s" fill="#FCD34D" barSize={11} />
          <Bar dataKey="LOW"    stackId="s" fill="#93C5FD" barSize={11} radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
      <div style={{ display: "flex", gap: 16, marginTop: 14 }}>
        {[["HIGH", "#FCA5A5"], ["MEDIUM", "#FCD34D"], ["LOW", "#93C5FD"]].map(([label, bg]) => (
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
      <tr onClick={() => setOpen(o => !o)} style={{ background: open ? sv.bg : i % 2 ? "#FAFAFA" : C.white, cursor: "pointer", transition: "background 0.12s" }}>
        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}><SevTag s={f.severity} /></td>
        <td style={{ padding: "10px 8px", color: C.sub, fontSize: 11, whiteSpace: "nowrap" }}>{CHECK_LABELS[f.check] || f.check}</td>
        <td style={{ padding: "10px 8px", color: C.text, fontSize: 12, fontFamily: "ui-monospace, monospace", whiteSpace: "nowrap" }}>{f.resource_name}</td>
        <td style={{ padding: "10px 8px 10px 0", color: C.sub, fontSize: 12, maxWidth: 320 }}>
          <span style={{ display: "-webkit-box", WebkitLineClamp: 1, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{f.issues[0]}</span>
        </td>
        <td style={{ padding: "10px 16px", textAlign: "right", color: C.muted }}>{open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}</td>
      </tr>
      {open && (
        <tr><td colSpan={5} style={{ padding: 0 }}>
          <div style={{ padding: "18px 20px 20px 20px", background: sv.bg, borderTop: `1px solid ${sv.border}`, borderBottom: `1px solid ${sv.border}`, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px 32px" }}>
            <div>
              <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>What's wrong</p>
              <p style={{ color: C.text, fontSize: 12, lineHeight: 1.7 }}>{f.description}</p>
            </div>
            <div>
              <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>How to fix it</p>
              <p style={{ color: "#1D4ED8", fontSize: 12, lineHeight: 1.7 }}>{f.remediation}</p>
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <p style={{ color: C.muted, fontSize: 9, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 4 }}>ARN</p>
              <code style={{ color: C.sub, fontSize: 10, fontFamily: "ui-monospace, monospace" }}>{f.resource_arn}</code>
            </div>
          </div>
        </td></tr>
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
  const visible = [...(filter === "ALL" ? findings : findings.filter(f => f.severity === filter))].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  return (
    <div style={{ ...card, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", borderBottom: `1px solid ${C.border}`, background: "#FAFAFA", padding: "0 6px" }}>
        <span style={{ color: C.muted, fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase", padding: "0 12px" }}>Findings</span>
        <div style={{ display: "flex", marginLeft: "auto" }}>
          {["ALL", "HIGH", "MEDIUM", "LOW"].map(tab => {
            const active = filter === tab;
            const sv = SEV[tab];
            const col = tab === "ALL" ? C.amber : sv?.fg;
            const bg  = tab === "ALL" ? "#FEF3C7" : sv?.bg;
            return (
              <button key={tab} onClick={() => setFilter(tab)} style={{ background: "transparent", border: "none", borderBottom: active ? `2px solid ${col}` : "2px solid transparent", color: active ? col : C.muted, padding: "10px 14px", cursor: "pointer", fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6, fontFamily: "ui-monospace, monospace", transition: "color 0.12s" }}>
                {tab}
                <span style={{ background: active ? bg : C.bg, color: active ? col : C.muted, border: `1px solid ${active ? (col + "40") : C.border}`, borderRadius: 999, padding: "0 6px", fontSize: 9 }}>{counts[tab]}</span>
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
                <th key={idx} style={{ padding: "8px 16px", textAlign: "left", color: C.muted, fontSize: 9, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase" }}>{h}</th>
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
      <div style={{ height: 3, background: `linear-gradient(to right, ${g.hex}, ${C.amber})` }} />
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 28px", background: C.white, borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, zIndex: 10, boxShadow: "0 1px 3px rgba(0,0,0,0.06)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <Shield size={15} color={C.amber} />
          <span style={{ fontWeight: 700, fontSize: 13, color: C.text, letterSpacing: "-0.01em" }}>IAM Scanner</span>
          {isSample && <span style={{ background: "#FEF3C7", color: C.amber, border: "1px solid #FDE68A", borderRadius: 5, padding: "2px 7px", fontSize: 8, fontWeight: 700, letterSpacing: "0.12em" }}>DEMO</span>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "ui-monospace, monospace" }}>{account_id}</span>
          <button onClick={onReset} style={{ display: "flex", alignItems: "center", gap: 5, background: C.bg, border: `1px solid ${C.border}`, color: C.sub, borderRadius: 7, padding: "5px 12px", cursor: "pointer", fontSize: 11 }}>
            <RotateCcw size={10} /> New scan
          </button>
        </div>
      </div>
      <div style={{ maxWidth: 1060, margin: "0 auto", padding: "28px 20px", display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", gap: 16, alignItems: "stretch", flexWrap: "wrap" }}>
          <GradePanel grade={grade} score={score} generated_at={generated_at} />
          <StatCards summary={summary} />
        </div>
        <Breakdown findings={findings} />
        <Table findings={findings} />
      </div>
    </div>
  );
}

// ── Upload screen ─────────────────────────────────────────────────────────────
function Upload({ onLoad }) {
  const [tab, setTab] = useState("upload");
  const [drag, setDrag] = useState(false);
  const [err, setErr]   = useState(null);
  const [leftPct, setLeftPct] = useState(34);
  const isDragging = useRef(false);
  const containerRef = useRef();
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

  const onDividerMouseDown = useCallback(e => {
    isDragging.current = true;
    e.preventDefault();
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMouseMove = e => {
      if (!isDragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((e.clientX - rect.left) / rect.width) * 100;
      setLeftPct(Math.min(Math.max(pct, 22), 52));
    };
    const onMouseUp = () => {
      isDragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }, []);

  if (tab === "guide") return <Guide onUpload={() => setTab("upload")} />;

  const checks = [
    "Overly permissive IAM policies",
    "Users without MFA enabled",
    "Stale or unused access keys",
    "Publicly exposed S3 buckets",
    "Misconfigured trust policies",
    "Roles that should be deleted",
    "Least-privilege policy generator",
  ];

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "system-ui, -apple-system, sans-serif", display: "flex", flexDirection: "column" }}>
      <div style={{ height: 3, background: C.amber, flexShrink: 0 }} />

      {/* Header */}
      <div style={{ background: C.white, borderBottom: `1px solid ${C.border}`, padding: "13px 40px", display: "flex", alignItems: "center", gap: 9, flexShrink: 0 }}>
        <Shield size={15} color={C.amber} />
        <span style={{ fontWeight: 700, fontSize: 13, color: C.text }}>AWS IAM Scanner</span>
      </div>

      {/* Two-column body */}
      <div ref={containerRef} style={{ flex: 1, display: "flex", minHeight: 0 }}>

        {/* Left — branding + what it checks */}
        <div style={{ flex: `0 0 ${leftPct}%`, background: C.white, overflow: "auto", padding: "60px 40px", display: "flex", flexDirection: "column", justifyContent: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
            <Shield size={32} color={C.amber} />
            <div>
              <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: "-0.02em", margin: 0, color: C.text, lineHeight: 1.1 }}>
                AWS IAM Scanner
              </h1>
              <p style={{ color: C.muted, fontSize: 13, margin: "4px 0 0" }}>Security audit for your AWS account</p>
            </div>
          </div>

          <p style={{ color: C.sub, fontSize: 14, lineHeight: 1.75, margin: "0 0 32px", maxWidth: 380 }}>
            Run the scanner locally against your AWS account, then upload the report here to see your security grade, a breakdown of every finding, and step-by-step fix instructions.
          </p>

          <div style={{ marginBottom: 32 }}>
            <p style={{ color: C.muted, fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase", margin: "0 0 14px", fontWeight: 700 }}>
              What gets checked
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {checks.map(item => (
                <div key={item} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ width: 18, height: 18, borderRadius: "50%", background: "#F0FDF4", border: "1px solid #BBF7D0", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, fontSize: 10, color: "#16A34A", fontWeight: 700 }}>✓</span>
                  <span style={{ fontSize: 13, color: C.sub }}>{item}</span>
                </div>
              ))}
            </div>
          </div>

          <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ display: "inline-flex", alignItems: "center", gap: 6, color: C.muted, fontSize: 12, textDecoration: "none" }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            View on GitHub
          </a>
        </div>

        {/* Draggable divider */}
        <div
          onMouseDown={onDividerMouseDown}
          style={{
            width: 5, flexShrink: 0,
            background: C.border,
            cursor: "col-resize",
            display: "flex", alignItems: "center", justifyContent: "center",
            transition: "background 0.15s",
            position: "relative",
            zIndex: 1,
          }}
          onMouseEnter={e => e.currentTarget.style.background = C.amber}
          onMouseLeave={e => e.currentTarget.style.background = C.border}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 3, pointerEvents: "none" }}>
            {[0,1,2].map(i => <div key={i} style={{ width: 3, height: 3, borderRadius: "50%", background: C.muted }} />)}
          </div>
        </div>

        {/* Right — upload zone */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "48px 40px", overflow: "auto" }}>

          {/* Tab bar */}
          <div style={{ display: "flex", background: C.white, border: `1px solid ${C.border}`, borderRadius: 10, padding: 4, gap: 4, marginBottom: 28, boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
            {[
              { key: "upload", label: "Upload report", Icon: UploadIcon },
              { key: "guide",  label: "How to use",    Icon: BookOpen   },
            ].map(({ key, label, Icon }) => (
              <button key={key} onClick={() => setTab(key)} style={{
                display: "flex", alignItems: "center", gap: 6,
                background: tab === key ? C.amber : "transparent",
                color: tab === key ? "#fff" : C.muted,
                border: "none", borderRadius: 7,
                padding: "8px 18px", cursor: "pointer",
                fontSize: 13, fontWeight: 600,
                transition: "all 0.15s",
              }}>
                <Icon size={13} /> {label}
              </button>
            ))}
          </div>

          {/* Drop zone */}
          <div
            onDragOver={e => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={e => { e.preventDefault(); setDrag(false); handle(e.dataTransfer.files[0]); }}
            onClick={() => ref.current?.click()}
            style={{
              width: "100%", maxWidth: 440,
              border: `2px dashed ${drag ? C.amber : C.border}`,
              borderRadius: 16,
              background: drag ? "#FFFBEB" : C.white,
              padding: "52px 32px",
              display: "flex", flexDirection: "column", alignItems: "center", gap: 12,
              cursor: "pointer", transition: "all 0.15s",
              boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
            }}
          >
            <div style={{ width: 52, height: 52, borderRadius: 12, background: drag ? "#FEF3C7" : C.bg, display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}>
              <FileJson size={26} color={drag ? C.amber : C.muted} />
            </div>
            <div style={{ textAlign: "center" }}>
              <p style={{ fontWeight: 700, fontSize: 15, margin: "0 0 6px", color: C.text }}>
                Drop your scan report here
              </p>
              <p style={{ color: C.muted, fontSize: 13, margin: 0 }}>
                Upload <code style={{ fontFamily: "monospace", color: C.amber, fontSize: 12, background: "#FEF3C7", padding: "1px 5px", borderRadius: 4 }}>iam_scan_report.json</code>
              </p>
            </div>
            <span style={{ color: C.muted, fontSize: 12, marginTop: 4 }}>or click to browse files</span>
            <input ref={ref} type="file" accept=".json" style={{ display: "none" }} onChange={e => handle(e.target.files[0])} />
          </div>

          {err && <p style={{ color: "#B91C1C", fontSize: 12, marginTop: 12 }}>{err}</p>}

          <div style={{ display: "flex", alignItems: "center", gap: 16, margin: "24px 0", width: "100%", maxWidth: 440 }}>
            <div style={{ flex: 1, height: 1, background: C.border }} />
            <span style={{ color: C.muted, fontSize: 11 }}>or explore a demo</span>
            <div style={{ flex: 1, height: 1, background: C.border }} />
          </div>

          <div style={{ width: "100%", maxWidth: 440, display: "flex", flexDirection: "column", gap: 8 }}>
            <p style={{ color: C.muted, fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", margin: "0 0 4px", fontWeight: 700 }}>
              Pick a scenario
            </p>
            {SCENARIOS.map(s => {
              const g = GRADE[s.grade] || GRADE.F;
              return (
                <button
                  key={s.id}
                  onClick={() => onLoad({ report: s, isSample: true })}
                  style={{
                    display: "flex", alignItems: "center", gap: 14,
                    background: C.white,
                    border: `1px solid ${C.border}`,
                    borderRadius: 12,
                    padding: "12px 16px",
                    cursor: "pointer",
                    textAlign: "left",
                    transition: "border-color 0.15s, box-shadow 0.15s",
                    boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = g.hex; e.currentTarget.style.boxShadow = `0 0 0 3px ${g.hex}15`; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.boxShadow = "0 1px 3px rgba(0,0,0,0.05)"; }}
                >
                  {/* Grade badge */}
                  <div style={{
                    width: 44, height: 44, borderRadius: 10, flexShrink: 0,
                    background: `linear-gradient(135deg, ${g.soft}, ${g.hex}22)`,
                    border: `1px solid ${g.hex}30`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <span style={{ fontSize: 22, fontWeight: 900, color: g.hex, fontFamily: "system-ui", letterSpacing: "-0.03em" }}>
                      {s.grade}
                    </span>
                  </div>
                  {/* Text */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ margin: 0, fontWeight: 700, fontSize: 13, color: C.text }}>{s.label}</p>
                    <p style={{ margin: "2px 0 0", fontSize: 11, color: C.muted }}>{s.description}</p>
                  </div>
                  {/* Stats */}
                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      {s.summary.high > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: SEV.HIGH.fg, background: SEV.HIGH.bg, border: `1px solid ${SEV.HIGH.border}`, borderRadius: 4, padding: "1px 6px", fontFamily: "monospace" }}>{s.summary.high} HIGH</span>}
                      {s.summary.medium > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: SEV.MEDIUM.fg, background: SEV.MEDIUM.bg, border: `1px solid ${SEV.MEDIUM.border}`, borderRadius: 4, padding: "1px 6px", fontFamily: "monospace" }}>{s.summary.medium} MED</span>}
                    </div>
                    <p style={{ margin: "4px 0 0", fontSize: 10, color: C.muted }}>{s.summary.total} findings</p>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [s, setS] = useState(null);
  if (!s) return <Upload onLoad={setS} />;
  return <Dashboard report={s.report} isSample={s.isSample} onReset={() => setS(null)} />;
}