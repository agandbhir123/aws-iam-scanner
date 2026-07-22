"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, FileJson, ChevronDown, ChevronUp, Copy, Check, BookOpen, Upload as UploadIcon, ArrowLeft, RefreshCw } from "lucide-react";

// ── Tokens ────────────────────────────────────────────────────────────────────
const C = {
  bg: "#EEEEF2", white: "#FFFFFF", border: "#E0E1E8",
  text: "#0F1017", sub: "#4A4F65", muted: "#9599B0", amber: "#C96800",
};
const GRADE = {
  A: { hex:"#16A34A", soft:"#F0FDF4", label:"Excellent"        },
  B: { hex:"#4D7C0F", soft:"#F7FEE7", label:"Good"             },
  C: { hex:"#B45309", soft:"#FFFBEB", label:"Moderate risk"    },
  D: { hex:"#C2410C", soft:"#FFF7ED", label:"Significant risk" },
  F: { hex:"#B91C1C", soft:"#FEF2F2", label:"Critical"         },
};
const SEV = {
  HIGH:   { fg:"#991B1B", bg:"#FEE2E2", border:"#FECACA" },
  MEDIUM: { fg:"#92400E", bg:"#FEF3C7", border:"#FDE68A" },
  LOW:    { fg:"#1E40AF", bg:"#DBEAFE", border:"#BFDBFE" },
};
const CHECK_LABELS = {
  wildcard_policy:"Wildcard Policy", unused_keys:"Stale Keys",
  direct_attachment:"Direct Attachment", trust_policy:"Trust Policy",
  unused_role:"Unused Role", mfa_enforcement:"MFA Enforcement",
  s3_public_access:"S3 Public Access",
};
const SW = { HIGH:10, MEDIUM:5, LOW:2 };
const card = { background:"#FFFFFF", border:"1px solid #E0E1E8", borderRadius:12, boxShadow:"0 1px 4px rgba(0,0,0,0.07), 0 0 0 1px rgba(0,0,0,0.02)" };

// ── Finding helper ────────────────────────────────────────────────────────────
const f = (check, severity, resource_type, resource_name, arn, issue, description, remediation) => ({
  check, severity, resource_type, resource_name,
  resource_arn: arn, issues:[issue], description, remediation,
});
const A = "ACCOUNT";

// ── Finding pool ──────────────────────────────────────────────────────────────
const FP = {
  // HIGH — MFA
  root_mfa:      f("mfa_enforcement","HIGH","Root","root",`arn:aws:iam::${A}:root`,"Root account does not have MFA enabled","The AWS root account has no MFA. Root compromise is catastrophic — no recovery path exists.","Enable MFA immediately using a hardware key or virtual MFA device. Go to IAM → Security credentials → MFA."),
  root_key:      f("mfa_enforcement","HIGH","Root","root",`arn:aws:iam::${A}:root`,"Root account has an active access key","The root account has an active access key. Root keys must never exist — use IAM users or roles instead.","Delete root access keys immediately. Use IAM users or assume-role for all programmatic access."),
  con_mfa_alice: f("mfa_enforcement","HIGH","User","alice",`arn:aws:iam::${A}:user/alice`,"User has console (password) access but NO MFA device enrolled","User 'alice' can log into the AWS console with just a password. One phished credential = full console access.","Assign an MFA device immediately via IAM → user → Security credentials → Assign MFA device."),
  con_mfa_bob:   f("mfa_enforcement","HIGH","User","bob",`arn:aws:iam::${A}:user/bob`,"User has console (password) access but NO MFA device enrolled","User 'bob' can log into the AWS console with just a password.","Assign an MFA device immediately via IAM → user → Security credentials."),
  con_mfa_carol: f("mfa_enforcement","HIGH","User","carol",`arn:aws:iam::${A}:user/carol`,"User has console (password) access but NO MFA device enrolled","User 'carol' can log into the AWS console with just a password.","Assign an MFA device immediately. Enforce MFA via an IAM policy that denies all actions unless aws:MultiFactorAuthPresent is true."),
  con_mfa_admin: f("mfa_enforcement","HIGH","User","admin",`arn:aws:iam::${A}:user/admin`,"User has console (password) access but NO MFA device enrolled","User 'admin' has console access with no MFA — a high-value target.","Require MFA immediately. This is the account most attackers will target first."),
  con_mfa_ops:   f("mfa_enforcement","HIGH","User","ops-manager",`arn:aws:iam::${A}:user/ops-manager`,"User has console (password) access but NO MFA device enrolled","The ops manager has console access with no MFA.","Assign an MFA device immediately. Consider enforcing MFA via IAM policy."),
  con_mfa_dep:   f("mfa_enforcement","HIGH","User","deploy-admin",`arn:aws:iam::${A}:user/deploy-admin`,"User has console (password) access but NO MFA device enrolled","User 'deploy-admin' can log into the AWS console with just a password.","Assign an MFA device via IAM → user → Security credentials → Assign MFA device."),
  con_mfa_eng:   f("mfa_enforcement","HIGH","User","eng-lead",`arn:aws:iam::${A}:user/eng-lead`,"User has console (password) access but NO MFA device enrolled","User 'eng-lead' has console access with no MFA protection.","Assign MFA immediately and enforce it via IAM policy."),
  con_mfa_cto:   f("mfa_enforcement","HIGH","User","cto",`arn:aws:iam::${A}:user/cto`,"User has console (password) access but NO MFA device enrolled","The CTO account has console access with no MFA — extremely high-value target for attackers.","Assign hardware MFA (YubiKey) for privileged users. Enforce MFA via SCP at the organization level."),
  // HIGH — Wildcard
  wc_everyone:   f("wildcard_policy","HIGH","ManagedPolicy","EveryonePolicy",`arn:aws:iam::${A}:policy/EveryonePolicy`,"Action '*' on Resource '*' — full administrator access","Policy 'EveryonePolicy' grants full admin and is attached to every developer.","Delete this policy immediately. Replace with per-role least-privilege policies."),
  wc_dev:        f("wildcard_policy","HIGH","ManagedPolicy","DevTeamPolicy",`arn:aws:iam::${A}:policy/DevTeamPolicy`,"Action '*' on Resource '*' — full administrator access","Policy 'DevTeamPolicy' grants full administrator access to all AWS services.","Scope down to specific services each team member actually uses. Use IAM Access Analyzer."),
  wc_legacy:     f("wildcard_policy","HIGH","ManagedPolicy","LegacyAutoPolicy",`arn:aws:iam::${A}:policy/LegacyAutoPolicy`,"Service wildcard(s) ['s3:*', 'ec2:*', 'iam:*'] on Resource '*'","A legacy automation policy grants full S3, EC2, and IAM control to a service account.","Replace with specific actions required by the automation scripts."),
  wc_admin_u:    f("wildcard_policy","HIGH","ManagedPolicy","DevFullAccess",`arn:aws:iam::${A}:policy/DevFullAccess`,"Action '*' on Resource '*' — full administrator access","Managed policy 'DevFullAccess' grants full admin across all services and resources.","Replace wildcard actions with specific permissions. Use IAM Access Analyzer to generate least-privilege policy."),
  wc_founders:   f("wildcard_policy","HIGH","User","founders → AdministratorAccess",`arn:aws:iam::${A}:user/founders`,"Has AWS managed policy AdministratorAccess directly attached — full admin access","User 'founders' has AdministratorAccess, granting full control over every AWS service.","Remove AdministratorAccess. Grant only the specific permissions this user needs."),
  wc_iam_full:   f("wildcard_policy","HIGH","User","dev-lead → IAMFullAccess",`arn:aws:iam::${A}:user/dev-lead`,"Has AWS managed policy IAMFullAccess directly attached","User 'dev-lead' has IAMFullAccess — can modify any permission in the account.","Remove IAMFullAccess. Grant specific IAM permissions needed. Full IAM access = full account access."),
  // HIGH — S3
  s3_pub_up:     f("s3_public_access","HIGH","S3/Bucket","prod-user-uploads",`arn:aws:s3:::prod-user-uploads`,"ACL grants FULL_CONTROL to AllUsers (public internet)","The production uploads bucket is fully public — anyone can read, write, and delete files.","Remove the public ACL immediately, enable Block Public Access, and audit what data was exposed."),
  s3_pub_bk:     f("s3_public_access","HIGH","S3/Bucket","db-backups",`arn:aws:s3:::db-backups`,"Bucket policy is flagged as public by AWS","The database backups bucket is publicly accessible. Database dumps are exposed.","Remove the public bucket policy immediately. Database backups must never be public."),
  s3_pub_log:    f("s3_public_access","HIGH","S3/Bucket","app-logs-prod",`arn:aws:s3:::app-logs-prod`,"ACL grants READ to AllUsers (public internet)","Application logs bucket is publicly readable — potentially exposing user data and internal paths.","Remove the public ACL and enable Block Public Access on this bucket."),
  s3_pub_asset:  f("s3_public_access","HIGH","S3/Bucket","prod-static-assets",`arn:aws:s3:::prod-static-assets`,"Bucket policy is flagged as public by AWS","Production static assets bucket has an overly broad public policy.","Scope the bucket policy to allow only s3:GetObject from cloudfront.amazonaws.com, not public."),
  // HIGH — Trust
  trust_star:    f("trust_policy","HIGH","Role","CrossAccountDataRole",`arn:aws:iam::${A}:role/CrossAccountDataRole`,"Principal: '*' — ANY entity globally can assume this role","This role has a trust policy allowing any entity in the world to assume it.","Restrict the Principal to specific account IDs and add an ExternalId condition immediately."),
  trust_no_eid:  f("trust_policy","HIGH","Role","VendorIntegrationRole",`arn:aws:iam::${A}:role/VendorIntegrationRole`,"Cross-account trust with no ExternalId condition (confused deputy vulnerability)","This cross-account role has no ExternalId condition — vulnerable to confused deputy attacks.","Add an ExternalId condition to the trust policy and share the ID privately with the vendor."),
  trust_no_eid2: f("trust_policy","HIGH","Role","PartnerDataRole",`arn:aws:iam::${A}:role/PartnerDataRole`,"Cross-account trust to external account with no ExternalId condition","The partner data role can be assumed by any principal in the partner account — no ExternalId check.","Add an ExternalId condition. Rotate the ExternalId annually."),
  // MEDIUM — Stale keys
  stale_127_ci:  f("unused_keys","MEDIUM","AccessKey","ci-runner → key_1","arn:aws:iam::user/ci-runner/key_1","Key not rotated in 127 days (threshold: 90)","Access key 1 for ci-runner has not been rotated in 127 days.","Rotate the key and switch to short-lived credentials via IAM roles for CI/CD."),
  stale_200_dep: f("unused_keys","MEDIUM","AccessKey","deploy-svc → key_1","arn:aws:iam::user/deploy-svc/key_1","Key not rotated in 200 days (threshold: 90)","The deploy service key hasn't been rotated in over 6 months.","Rotate immediately and set up automated key rotation."),
  stale_300_aut: f("unused_keys","MEDIUM","AccessKey","automation → key_1","arn:aws:iam::user/automation/key_1","Key not rotated in 300 days (threshold: 90)","The automation account key hasn't been rotated in 10 months.","Rotate and migrate to IAM roles for service-to-service authentication."),
  stale_445_svc: f("unused_keys","MEDIUM","AccessKey","service-account → key_1","arn:aws:iam::user/service-account/key_1","Key not rotated in 445 days (threshold: 90)","This service account key hasn't been rotated in over a year.","Rotate immediately. A key this old has likely been exposed to multiple people and systems."),
  stale_94_leg:  f("unused_keys","MEDIUM","AccessKey","legacy-script → key_1","arn:aws:iam::user/legacy-script/key_1","Key not rotated in 94 days (threshold: 90)","Access key 1 for legacy-script is just past the rotation threshold.","Rotate this key as part of your regular 90-day rotation schedule."),
  stale_287_bot: f("unused_keys","MEDIUM","AccessKey","deploy-bot → key_1","arn:aws:iam::user/deploy-bot/key_1","Key not rotated in 287 days (threshold: 90)","The deploy bot key hasn't been rotated in nearly a year.","Rotate and switch to IAM roles with short-lived credentials."),
  stale_312_alc: f("unused_keys","MEDIUM","AccessKey","alice → key_1","arn:aws:iam::user/alice/key_1","Key not rotated in 312 days (threshold: 90)","Alice's access key hasn't been rotated in over 10 months.","Rotate immediately. Remind all users to rotate keys every 90 days."),
  never_45:      f("unused_keys","MEDIUM","AccessKey","deploy-user → key_2","arn:aws:iam::user/deploy-user/key_2","Key is active but has NEVER been used (45 days old)","This access key is 45 days old and has never been used.","Deactivate and delete this key immediately — unnecessary standing access."),
  never_67:      f("unused_keys","MEDIUM","AccessKey","monitoring → key_2","arn:aws:iam::user/monitoring/key_2","Key is active but has NEVER been used (67 days old)","This monitoring key was created 67 days ago and has never been used.","Delete this key. It was likely created by mistake."),
  never_134:     f("unused_keys","MEDIUM","AccessKey","ci-bot → key_2","arn:aws:iam::user/ci-bot/key_2","Key is active but has NEVER been used (134 days old)","This CI bot key has been active for 134 days and has never been used.","Delete this key immediately — unused access is unnecessary access."),
  // MEDIUM — Direct attachments
  dir_2pol_jane: f("direct_attachment","MEDIUM","User","analyst-jane",`arn:aws:iam::${A}:user/analyst-jane`,"Has 2 managed policies attached directly: S3ReadOnlyAccess, CloudWatchReadOnlyAccess","User 'analyst-jane' has policies attached directly rather than via a group.","Create an IAM group with these policies, add the user, remove direct attachments."),
  dir_3pol_ch:   f("direct_attachment","MEDIUM","User","charlie",`arn:aws:iam::${A}:user/charlie`,"Has 3 managed policies attached directly: S3FullAccess, RDSFullAccess, EC2FullAccess","User 'charlie' has three full-access policies attached directly — massively over-provisioned.","Scope down to read-only where possible and attach via a group."),
  dir_4pol_con:  f("direct_attachment","MEDIUM","User","contractor-alex",`arn:aws:iam::${A}:user/contractor-alex`,"Has 4 managed policies attached directly: EC2FullAccess, S3FullAccess, RDSFullAccess, LambdaFullAccess","A contractor has four full-access policies attached directly.","Scope down to exactly what the contractor needs. Set an expiry date on the access."),
  dir_inline_bob:f("direct_attachment","MEDIUM","User","developer-bob",`arn:aws:iam::${A}:user/developer-bob`,"Has 1 inline policy: DeveloperOverrides","User 'developer-bob' has an inline policy invisible in the IAM policy list.","Convert to a managed policy and attach via a group."),
  dir_inline_dan:f("direct_attachment","MEDIUM","User","dana",`arn:aws:iam::${A}:user/dana`,"Has 1 inline policy: InternalToolsAccess","User 'dana' has an inline policy that is harder to audit.","Convert to a managed policy and attach via a group."),
  dir_ops_multi: f("direct_attachment","MEDIUM","User","ops-team-lead",`arn:aws:iam::${A}:user/ops-team-lead`,"Has 3 managed policies attached directly: CloudWatchFullAccess, EC2FullAccess, SSMFullAccess","Ops team lead has 3 policies directly attached instead of via a group.","Create an OpsTeam IAM group, move policies there, and add the user to the group."),
  // MEDIUM — S3 BPA
  s3_staging_bpa:f("s3_public_access","MEDIUM","S3/Bucket","my-app-assets-staging",`arn:aws:s3:::my-app-assets-staging`,"Block public ACLs is disabled, Ignore public ACLs is disabled","Staging assets bucket has two Block Public Access settings disabled.","Enable all four Block Public Access settings unless this bucket intentionally serves public content."),
  s3_dev_bpa:    f("s3_public_access","MEDIUM","S3/Bucket","dev-environment",`arn:aws:s3:::dev-environment`,"Block public ACLs is disabled","Dev environment bucket has Block Public Access partially disabled.","Enable Block Public Access fully on this bucket."),
  s3_arch_bpa:   f("s3_public_access","MEDIUM","S3/Bucket","data-archive",`arn:aws:s3:::data-archive`,"Block public bucket policies is disabled","Data archive bucket has block public policy setting disabled.","Enable all four Block Public Access settings on this bucket."),
  s3_acct_bpa:   f("s3_public_access","MEDIUM","S3/AccountBPA","Account-level Block Public Access","arn:aws:s3:::*","Account-level Block Public Access is not configured at all","No account-level Block Public Access configuration found.","Enable all four Block Public Access settings at the account level in the S3 console."),
  s3_prod_bpa:   f("s3_public_access","MEDIUM","S3/Bucket","prod-assets",`arn:aws:s3:::prod-assets`,"Block public ACLs is disabled, Ignore public ACLs is disabled","Production assets bucket has two Block Public Access settings disabled.","Enable Block Public Access fully on this bucket. Review if any content needs to be public first."),
  // MEDIUM — MFA programmatic
  mfa_ci:        f("mfa_enforcement","MEDIUM","User","ci-runner",`arn:aws:iam::${A}:user/ci-runner`,"User has console (password) access but no MFA — programmatic account","CI runner user has console access added recently with no MFA.","Assign MFA and consider switching to IAM roles for CI/CD access."),
  mfa_vendor:    f("mfa_enforcement","MEDIUM","User","vendor-api",`arn:aws:iam::${A}:user/vendor-api`,"External vendor user has console access with no MFA enrolled","The vendor API user has console access but no MFA protection.","Work with the vendor to migrate to cross-account role assumption instead."),
  // LOW — Unused roles
  rol_142_lam:   f("unused_role","LOW","Role","LegacyLambdaRole",`arn:aws:iam::${A}:role/LegacyLambdaRole`,"Role not assumed in 142 days (threshold: 90)","Role 'LegacyLambdaRole' has not been assumed in 142 days.","Confirm still needed. If not, delete it to reduce your attack surface."),
  rol_203_pip:   f("unused_role","LOW","Role","DataPipelineRole",`arn:aws:iam::${A}:role/DataPipelineRole`,"Role not assumed in 203 days (threshold: 90)","Role 'DataPipelineRole' has not been assumed in over 6 months.","Delete if no longer in use."),
  rol_118_bak:   f("unused_role","LOW","Role","BackupAutomationRole",`arn:aws:iam::${A}:role/BackupAutomationRole`,"Role not assumed in 118 days (threshold: 90)","Role 'BackupAutomationRole' has not been assumed in 118 days.","Confirm still needed. If inactive, delete it."),
  rol_67_nev:    f("unused_role","LOW","Role","OldCodeBuildRole",`arn:aws:iam::${A}:role/OldCodeBuildRole`,"Role has NEVER been assumed (67 days since creation)","This role was created 67 days ago and has never been assumed.","Verify still needed. If not, delete it."),
  rol_198_app:   f("unused_role","LOW","Role","OldAppRole",`arn:aws:iam::${A}:role/OldAppRole`,"Role not assumed in 198 days (threshold: 90)","This role belongs to a deprecated application.","Delete immediately. This role has no current business purpose."),
  rol_380_dec:   f("unused_role","LOW","Role","DecommissionedRole",`arn:aws:iam::${A}:role/DecommissionedRole`,"Role not assumed in 380 days (threshold: 90)","This role belongs to a system decommissioned over a year ago.","Delete immediately — should have been removed during decommission."),
  rol_215_tst:   f("unused_role","LOW","Role","TestEnvironmentRole",`arn:aws:iam::${A}:role/TestEnvironmentRole`,"Role not assumed in 215 days (threshold: 90)","Test environment role not used since last quarter.","Check if the test environment still exists. Delete if not."),
  rol_88_nev:    f("unused_role","LOW","Role","DeprecatedPipelineRole",`arn:aws:iam::${A}:role/DeprecatedPipelineRole`,"Role has NEVER been assumed (88 days since creation)","Created 88 days ago and never used.","Delete this role to reduce your attack surface."),
  rol_96_mig:    f("unused_role","LOW","Role","OldMigrationRole",`arn:aws:iam::${A}:role/OldMigrationRole`,"Role not assumed in 96 days (threshold: 90)","Used for a one-time database migration and not needed since.","Confirm migration is complete and delete this role."),
  rol_112_stg:   f("unused_role","LOW","Role","StagingTestRole",`arn:aws:iam::${A}:role/StagingTestRole`,"Role not assumed in 112 days (threshold: 90)","Staging test role not used since last quarter.","Check if staging tests are still active. Delete if not."),
  rol_91_an:     f("unused_role","LOW","Role","TempAnalyticsRole",`arn:aws:iam::${A}:role/TempAnalyticsRole`,"Role has NEVER been assumed (91 days since creation)","Created for an analytics project that was deprioritized before launch.","Delete this role since the project was cancelled."),
  rol_320_rep:   f("unused_role","LOW","Role","OldReportingRole",`arn:aws:iam::${A}:role/OldReportingRole`,"Role not assumed in 320 days (threshold: 90)","Old reporting role not used in nearly a year.","Delete — reporting was migrated to a different system months ago."),
  rol_145_etl:   f("unused_role","LOW","Role","LegacyETLRole",`arn:aws:iam::${A}:role/LegacyETLRole`,"Role not assumed in 145 days (threshold: 90)","Legacy ETL pipeline role not used since the pipeline was rewritten.","Delete this role. The new ETL pipeline uses a different role."),
  rol_178_api:   f("unused_role","LOW","Role","DeprecatedAPIRole",`arn:aws:iam::${A}:role/DeprecatedAPIRole`,"Role not assumed in 178 days (threshold: 90)","Deprecated API service role not used since the v1 API was sunset.","Delete this role. The v2 API uses its own role."),
  // LOW — MFA programmatic
  mfa_low_ci:    f("mfa_enforcement","LOW","User","ci-runner",`arn:aws:iam::${A}:user/ci-runner`,"User has no MFA device enrolled (programmatic-only access)","Programmatic CI user with no MFA enrolled.","Prefer IAM roles over long-lived IAM users for programmatic access."),
  mfa_low_bot:   f("mfa_enforcement","LOW","User","deploy-bot",`arn:aws:iam::${A}:user/deploy-bot`,"User has no MFA device enrolled (programmatic-only access)","Programmatic deploy bot with no MFA enrolled.","Prefer IAM roles with short-lived credentials over long-lived IAM users."),
  mfa_low_bak:   f("mfa_enforcement","LOW","User","backup-svc",`arn:aws:iam::${A}:user/backup-svc`,"User has no MFA device enrolled (programmatic-only access)","Backup service user with no MFA.","Migrate to IAM roles for service-to-service authentication."),
  mfa_low_ven:   f("mfa_enforcement","LOW","User","vendor-api-user",`arn:aws:iam::${A}:user/vendor-api-user`,"User has no MFA device enrolled (programmatic-only access)","External vendor API user has no MFA enrolled.","Work with the vendor to migrate to cross-account role assumption."),
  mfa_low_aut:   f("mfa_enforcement","LOW","User","automation-svc",`arn:aws:iam::${A}:user/automation-svc`,"User has no MFA device enrolled (programmatic-only access)","Automation service account with no MFA.","Migrate to IAM roles for service authentication."),
  mfa_low_mon:   f("mfa_enforcement","LOW","User","monitoring-user",`arn:aws:iam::${A}:user/monitoring-user`,"User has no MFA device enrolled (programmatic-only access)","Monitoring service user with no MFA enrolled.","Prefer IAM roles with short-lived credentials."),
};

// ── Scenario templates (10 per grade) ─────────────────────────────────────────
const ST = {
  A:[
    { label:"Security best-in-class", description:"A perfectly maintained fintech account — zero findings across all 7 checks", account_id:"112233445566" },
    { label:"Cloud-native startup",   description:"Roles-only architecture with no long-lived IAM users or access keys", account_id:"223344556677" },
    { label:"Post-audit enterprise",  description:"Just completed a comprehensive security audit — all findings remediated", account_id:"334455667788" },
    { label:"AWS Control Tower org",  description:"Centrally managed via Control Tower with enforced SCPs and guardrails", account_id:"445566778899" },
    { label:"DevOps-mature SaaS",     description:"Automated everything — IAM rotation, role assumption, zero standing access", account_id:"556677889900" },
    { label:"Healthcare HIPAA org",   description:"HIPAA-compliant account with strict IAM policies and comprehensive audit logging", account_id:"667788990011" },
    { label:"FedRAMP authorized",     description:"Government contractor with FedRAMP High authorization — tightly controlled access", account_id:"778899001122" },
    { label:"Zero-trust startup",     description:"Built zero-trust from day one — no IAM users, all access via SSO and roles", account_id:"889900112233" },
    { label:"Security consultancy",   description:"A security consultancy that practices what it preaches — no findings detected", account_id:"990011223344" },
    { label:"Academic research org",  description:"University research account with read-only access controls and no standing keys", account_id:"101122334455" },
  ],
  B:[
    { label:"Growing SaaS startup",    description:"Well-maintained with a few stale access keys and unused roles to clean up",   account_id:"192837465001", findings:["stale_127_ci","rol_142_lam","rol_203_pip","rol_118_bak"] },
    { label:"E-commerce platform",     description:"Strong security posture with one direct policy attachment to address",         account_id:"192837465002", findings:["dir_2pol_jane","rol_67_nev","rol_198_app"] },
    { label:"Mobile gaming backend",   description:"Clean account with one key approaching the rotation threshold",               account_id:"192837465003", findings:["stale_94_leg","rol_96_mig","rol_112_stg","rol_91_an"] },
    { label:"Data analytics team",     description:"Solid setup with one vendor API user that needs MFA attention",               account_id:"192837465004", findings:["mfa_vendor","rol_380_dec","rol_215_tst"] },
    { label:"Independent game studio", description:"Good posture with one never-used access key and two lingering roles",         account_id:"192837465005", findings:["never_45","rol_88_nev","rol_145_etl"] },
    { label:"EdTech platform",         description:"Well-secured with one inline policy and a few unused roles to clean up",      account_id:"192837465006", findings:["dir_inline_bob","rol_142_lam","rol_203_pip","mfa_low_mon"] },
    { label:"HR software company",     description:"Good baseline with one programmatic user missing MFA and unused roles",       account_id:"192837465007", findings:["mfa_ci","rol_96_mig","rol_178_api"] },
    { label:"Digital marketing agency",description:"Minor S3 configuration gap on a dev bucket and a few unused roles",          account_id:"192837465008", findings:["s3_dev_bpa","rol_320_rep","rol_145_etl","mfa_low_aut"] },
    { label:"Legal tech startup",      description:"Clean security posture — one never-used key and two stale roles to address",  account_id:"192837465009", findings:["never_67","rol_112_stg","rol_91_an"] },
    { label:"Climate tech company",    description:"Strong security culture with one S3 configuration gap to clean up",          account_id:"192837465010", findings:["s3_arch_bpa","rol_215_tst","rol_88_nev"] },
  ],
  C:[
    { label:"Mid-stage startup",       description:"Growing fast with security starting to lag — one user with console access and no MFA", account_id:"283746556001", findings:["con_mfa_dep","stale_127_ci","never_45","rol_142_lam","rol_203_pip","rol_118_bak"] },
    { label:"Regional bank",           description:"Legacy wildcard policy still in use from early days alongside unused roles",           account_id:"283746556002", findings:["wc_dev","dir_2pol_jane","dir_inline_bob","rol_67_nev","rol_198_app","rol_91_an"] },
    { label:"Healthcare SaaS",         description:"HIPAA-adjacent workload with an admin user lacking MFA and some direct attachments",   account_id:"283746556003", findings:["con_mfa_admin","dir_3pol_ch","stale_94_leg","rol_96_mig","rol_112_stg","mfa_low_ci"] },
    { label:"Retail platform",         description:"Cross-account vendor role configured without ExternalId — confused deputy risk",       account_id:"283746556004", findings:["trust_no_eid","stale_200_dep","never_67","rol_145_etl","rol_178_api","mfa_low_bot"] },
    { label:"Media company",           description:"Application logs bucket is publicly readable alongside S3 configuration gaps",         account_id:"283746556005", findings:["s3_pub_log","s3_staging_bpa","stale_127_ci","dir_inline_dan","rol_380_dec","rol_215_tst","mfa_low_bak"] },
    { label:"Logistics startup",       description:"Console user with no MFA and a mix of direct attachments and unused roles",            account_id:"283746556006", findings:["con_mfa_carol","dir_2pol_jane","dir_inline_bob","rol_142_lam","rol_203_pip","rol_118_bak","rol_67_nev"] },
    { label:"Insurance tech",          description:"Full-access wildcard policy leftover from initial setup still attached to users",       account_id:"283746556007", findings:["wc_admin_u","dir_ops_multi","stale_300_aut","rol_320_rep","rol_145_etl","mfa_low_ven"] },
    { label:"Real estate platform",    description:"Ops manager has console access with no MFA — high-value target for attackers",         account_id:"283746556008", findings:["con_mfa_ops","stale_200_dep","dir_inline_dan","rol_198_app","rol_91_an","rol_88_nev","mfa_low_mon"] },
    { label:"Travel tech company",     description:"Partner data role configured without ExternalId and several stale access keys",        account_id:"283746556009", findings:["trust_no_eid2","stale_287_bot","never_134","rol_96_mig","rol_112_stg","mfa_low_aut"] },
    { label:"Food delivery startup",   description:"Multiple console users lacking MFA enforcement and stale access keys in CI/CD",        account_id:"283746556010", findings:["con_mfa_alice","stale_127_ci","s3_staging_bpa","rol_142_lam","rol_203_pip","rol_118_bak","rol_67_nev"] },
  ],
  D:[
    { label:"Legacy enterprise",       description:"Years of accumulated technical debt — significant misconfigurations across multiple categories", account_id:"374655660001", findings:["wc_dev","trust_no_eid","con_mfa_ops","con_mfa_admin","stale_445_svc","stale_312_alc","dir_3pol_ch","dir_inline_dan","s3_prod_bpa","rol_380_dec","rol_215_tst","mfa_low_ci"] },
    { label:"Government contractor",   description:"Compliance-required account with inherited IAM debt from a rushed initial deployment",         account_id:"374655660002", findings:["wc_legacy","trust_star","con_mfa_carol","con_mfa_eng","stale_300_aut","never_134","dir_ops_multi","s3_arch_bpa","s3_dev_bpa","rol_320_rep","rol_145_etl","mfa_low_bot"] },
    { label:"Financial services firm", description:"Financial sector account with MFA gaps on privileged users and legacy wildcard policies",      account_id:"374655660003", findings:["wc_admin_u","wc_iam_full","con_mfa_bob","stale_445_svc","stale_200_dep","dir_4pol_con","s3_staging_bpa","s3_acct_bpa","rol_178_api","rol_88_nev","mfa_low_bak","mfa_low_ven"] },
    { label:"Healthcare network",      description:"Multi-site healthcare network with inconsistent IAM governance across teams",                 account_id:"374655660004", findings:["con_mfa_admin","con_mfa_ops","trust_no_eid","stale_287_bot","stale_312_alc","dir_2pol_jane","dir_inline_bob","s3_staging_bpa","rol_380_dec","rol_203_pip","rol_142_lam","mfa_low_mon"] },
    { label:"Manufacturing corp",      description:"On-premises mindset applied to cloud — administrators have excessive permissions",              account_id:"374655660005", findings:["wc_everyone","con_mfa_alice","con_mfa_carol","con_mfa_dep","stale_200_dep","dir_ops_multi","s3_prod_bpa","rol_215_tst","rol_96_mig","rol_112_stg","mfa_low_aut"] },
    { label:"University IT dept",      description:"Decentralized IT with inconsistent IAM practices across departments",                         account_id:"374655660006", findings:["wc_dev","con_mfa_cto","con_mfa_eng","stale_127_ci","never_45","dir_2pol_jane","dir_inline_dan","s3_dev_bpa","rol_178_api","rol_91_an","mfa_low_ci","mfa_low_bot"] },
    { label:"Media conglomerate",      description:"Multiple acquired brands each with their own IAM sprawl merged into one account",             account_id:"374655660007", findings:["wc_legacy","trust_no_eid2","con_mfa_bob","con_mfa_carol","stale_300_aut","stale_445_svc","dir_3pol_ch","s3_arch_bpa","rol_320_rep","rol_88_nev","mfa_low_bak"] },
    { label:"Energy company",          description:"Operational technology teams using cloud with minimal security training",                      account_id:"374655660008", findings:["con_mfa_ops","con_mfa_alice","wc_admin_u","stale_312_alc","never_134","dir_inline_bob","dir_inline_dan","s3_acct_bpa","rol_145_etl","rol_198_app","mfa_low_ven","mfa_low_mon"] },
    { label:"Retail chain IT",         description:"Rapid store expansion led to IAM accounts created quickly without following best practices",   account_id:"374655660009", findings:["wc_founders","con_mfa_dep","con_mfa_admin","stale_445_svc","stale_287_bot","dir_4pol_con","s3_staging_bpa","s3_prod_bpa","rol_380_dec","rol_67_nev","mfa_low_aut"] },
    { label:"Telecom startup",         description:"Scaling infrastructure quickly while security struggles to keep pace with engineering",        account_id:"374655660010", findings:["wc_iam_full","trust_star","con_mfa_carol","stale_200_dep","never_67","dir_2pol_jane","dir_ops_multi","s3_dev_bpa","rol_96_mig","rol_112_stg","rol_91_an","mfa_low_ci"] },
  ],
  F:[
    { label:"Startup chaos",           description:"A freshly-configured account with no security structure — built fast, secured never",         account_id:"465566770001", findings:["root_mfa","root_key","wc_everyone","wc_founders","s3_pub_up","s3_pub_bk","con_mfa_alice","con_mfa_bob","trust_star","stale_312_alc","stale_287_bot","never_134","dir_3pol_ch","dir_inline_dan","rol_198_app","rol_88_nev","mfa_low_bot","mfa_low_ci"] },
    { label:"Legacy nightmare",        description:"A decade of accumulated IAM debt — every category has critical issues",                        account_id:"465566770002", findings:["root_mfa","wc_dev","wc_legacy","wc_admin_u","con_mfa_admin","con_mfa_ops","con_mfa_carol","trust_no_eid","stale_445_svc","stale_300_aut","stale_200_dep","dir_4pol_con","dir_ops_multi","s3_pub_log","rol_380_dec","rol_320_rep","mfa_low_bak","mfa_low_ven","mfa_low_mon"] },
    { label:"Acquired company",        description:"Newly acquired startup brought into the org — inherited all their security debt",              account_id:"465566770003", findings:["root_key","wc_everyone","wc_founders","s3_pub_bk","s3_pub_asset","con_mfa_cto","con_mfa_eng","con_mfa_alice","trust_star","trust_no_eid","stale_312_alc","never_134","dir_3pol_ch","dir_4pol_con","s3_acct_bpa","rol_215_tst","mfa_low_aut","mfa_low_ci"] },
    { label:"Shadow IT org",           description:"Teams spun up their own AWS accounts outside IT governance — now consolidated with the chaos",  account_id:"465566770004", findings:["root_mfa","root_key","wc_legacy","wc_iam_full","s3_pub_up","s3_pub_log","con_mfa_bob","con_mfa_dep","con_mfa_carol","trust_no_eid2","stale_445_svc","never_45","dir_ops_multi","dir_inline_dan","rol_88_nev","mfa_low_bot","mfa_low_bak","mfa_low_mon"] },
    { label:"Breach aftermath",        description:"This account was compromised 3 months ago — attackers got in through these exact issues",      account_id:"465566770005", findings:["root_mfa","wc_everyone","wc_dev","con_mfa_admin","con_mfa_alice","con_mfa_ops","s3_pub_bk","trust_star","stale_287_bot","stale_312_alc","dir_3pol_ch","s3_prod_bpa","s3_acct_bpa","rol_380_dec","mfa_low_ci","mfa_low_ven","mfa_low_mon"] },
    { label:"Contractor account",      description:"Multiple contractors each given admin access for convenience — never cleaned up",              account_id:"465566770006", findings:["wc_founders","wc_iam_full","con_mfa_eng","con_mfa_cto","trust_no_eid","trust_star","stale_445_svc","stale_300_aut","dir_4pol_con","dir_ops_multi","s3_pub_log","s3_pub_asset","mfa_vendor","rol_380_dec","mfa_low_bot","mfa_low_bak","mfa_low_aut"] },
    { label:"Rapid growth startup",    description:"Grew from 5 to 200 engineers in 18 months — IAM never kept pace with headcount",              account_id:"465566770007", findings:["root_mfa","wc_admin_u","wc_everyone","con_mfa_alice","con_mfa_bob","con_mfa_carol","s3_pub_up","trust_no_eid2","stale_312_alc","never_134","dir_3pol_ch","dir_inline_bob","s3_staging_bpa","rol_215_tst","mfa_low_ci","mfa_low_bot","mfa_low_ven"] },
    { label:"Dev account gone prod",   description:"What started as a dev sandbox became the production environment — with all the dev-level security", account_id:"465566770008", findings:["root_key","wc_dev","wc_legacy","con_mfa_admin","con_mfa_ops","con_mfa_dep","s3_pub_bk","trust_star","stale_445_svc","stale_287_bot","dir_2pol_jane","dir_inline_dan","s3_acct_bpa","rol_88_nev","rol_198_app","mfa_low_bak","mfa_low_mon"] },
    { label:"No security team",        description:"Fast-moving product team shipping features with zero dedicated security oversight",             account_id:"465566770009", findings:["root_mfa","wc_founders","wc_admin_u","con_mfa_alice","con_mfa_carol","con_mfa_eng","s3_pub_up","trust_no_eid","stale_300_aut","never_45","dir_4pol_con","s3_prod_bpa","rol_380_dec","rol_320_rep","mfa_low_ci","mfa_low_ven","mfa_low_aut"] },
    { label:"Cloud migration mess",    description:"Lifted-and-shifted from on-prem with no IAM redesign — on-prem admin habits applied to cloud", account_id:"465566770010", findings:["root_key","wc_everyone","wc_dev","s3_pub_log","s3_pub_asset","con_mfa_bob","con_mfa_cto","trust_no_eid2","trust_star","stale_445_svc","stale_312_alc","dir_3pol_ch","dir_ops_multi","rol_215_tst","mfa_low_bot","mfa_low_bak","mfa_low_mon"] },
  ],
};

const GRADE_LABELS = { A:"Excellent", B:"Good", C:"Moderate risk", D:"Significant risk", F:"Critical" };
const GRADE_FINDING_HINT = { A:"0 findings", B:"minor issues", C:"moderate risk", D:"significant risk", F:"critical" };

function buildScenario(grade, template) {
  const acct = template.account_id;
  const findings = (template.findings || []).map(id => {
    const fp = FP[id];
    if (!fp) return null;
    const clone = { ...fp };
    clone.resource_arn = clone.resource_arn.replace(/ACCOUNT/g, acct);
    return clone;
  }).filter(Boolean);
  const risk = findings.reduce((s, f2) => s + (SW[f2.severity] || 0), 0);
  const score = Math.max(1, Math.min(100, 100 - risk));
  const summary = {
    total: findings.length,
    high: findings.filter(f2 => f2.severity === "HIGH").length,
    medium: findings.filter(f2 => f2.severity === "MEDIUM").length,
    low: findings.filter(f2 => f2.severity === "LOW").length,
  };
  return { ...template, grade, score, summary, findings, generated_at: null };
}

function getRandomScenario(grade) {
  const templates = ST[grade];
  const template = templates[Math.floor(Math.random() * templates.length)];
  return buildScenario(grade, template);
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function SevTag({ s }) {
  const sv = SEV[s];
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:5, padding:"3px 8px", borderRadius:6, background:sv.bg, color:sv.fg, border:`1px solid ${sv.border}`, fontSize:10, fontWeight:700, letterSpacing:"0.07em", fontFamily:"ui-monospace,monospace" }}>
      <span style={{ width:5, height:5, borderRadius:1, background:sv.fg, flexShrink:0 }} />{s}
    </span>
  );
}

function GradePanel({ grade, score, isSample }) {
  const g = GRADE[grade] || GRADE.F;
  return (
    <div style={{ ...card, minWidth:210, flexShrink:0, background:`linear-gradient(145deg,${g.soft} 0%,#ffffff 55%)`, border:`1px solid ${g.hex}28`, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:"32px 24px", position:"relative", overflow:"hidden", userSelect:"none" }}>
      <span style={{ position:"absolute", fontSize:200, fontWeight:900, color:g.hex, opacity:0.055, lineHeight:1, fontFamily:"system-ui", letterSpacing:"-0.05em", top:"50%", left:"50%", transform:"translate(-44%,-52%)", pointerEvents:"none" }}>{grade}</span>
      <span style={{ fontSize:104, fontWeight:900, lineHeight:0.9, color:g.hex, fontFamily:"system-ui,-apple-system,sans-serif", letterSpacing:"-0.04em", position:"relative", zIndex:1 }}>{grade}</span>
      <span style={{ color:g.hex, fontSize:10, fontWeight:700, letterSpacing:"0.1em", textTransform:"uppercase", marginTop:14, position:"relative", zIndex:1, background:`${g.hex}15`, padding:"3px 10px", borderRadius:99, border:`1px solid ${g.hex}25` }}>{g.label}</span>
      <span style={{ color:C.muted, fontSize:10, fontFamily:"ui-monospace,monospace", marginTop:8, position:"relative", zIndex:1 }}>{score}/100</span>
    </div>
  );
}

function StatCards({ summary }) {
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:10, flex:1, minWidth:220 }}>
      {[["HIGH",summary.high,"Immediate action required"],["MEDIUM",summary.medium,"Should be addressed soon"],["LOW",summary.low,"Best-practice gaps"]].map(([k,n,note]) => {
        const sv = SEV[k];
        return (
          <div key={k} style={{ ...card, padding:"14px 18px", display:"flex", alignItems:"center", gap:14, background:n>0?`linear-gradient(to right,${sv.bg},#ffffff 55%)`:"#fff", border:n>0?`1px solid ${sv.border}`:`1px solid ${C.border}` }}>
            <span style={{ fontSize:40, fontWeight:900, color:n>0?sv.fg:C.muted, fontFamily:"ui-monospace,monospace", lineHeight:1, minWidth:52, textAlign:"right" }}>{n}</span>
            <div style={{ borderLeft:`2px solid ${n>0?sv.border:C.border}`, paddingLeft:12 }}>
              <p style={{ color:n>0?sv.fg:C.muted, fontSize:9, fontWeight:700, letterSpacing:"0.12em", margin:0 }}>{k}</p>
              <p style={{ color:C.muted, fontSize:11, margin:"2px 0 0" }}>{note}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Breakdown({ findings }) {
  const map = {};
  findings.forEach(f2 => {
    const name = CHECK_LABELS[f2.check] || f2.check;
    if (!map[name]) map[name] = { name, HIGH:0, MEDIUM:0, LOW:0 };
    map[name][f2.severity]++;
  });
  const data = Object.values(map).sort((a,b) => (b.HIGH*10+b.MEDIUM*5+b.LOW)-(a.HIGH*10+a.MEDIUM*5+a.LOW));
  const Tip = ({ active, payload, label }) => {
    if (!active||!payload?.length) return null;
    return <div style={{ ...card, padding:"10px 14px" }}><p style={{ color:C.text, fontSize:12, fontWeight:600, marginBottom:6 }}>{label}</p>{payload.filter(p=>p.value>0).map(p=><p key={p.dataKey} style={{ color:SEV[p.dataKey]?.fg, fontSize:11, fontFamily:"monospace", margin:"2px 0" }}>{p.dataKey}: {p.value}</p>)}</div>;
  };
  return (
    <div style={{ ...card, padding:"20px 22px" }}>
      <p style={{ color:C.muted, fontSize:9, letterSpacing:"0.14em", textTransform:"uppercase", marginBottom:16 }}>Findings by check</p>
      <ResponsiveContainer width="100%" height={Math.max(data.length*34+12,80)}>
        <BarChart layout="vertical" data={data} margin={{ top:0, right:4, left:0, bottom:0 }}>
          <XAxis type="number" allowDecimals={false} tick={{ fill:C.muted, fontSize:10, fontFamily:"monospace" }} axisLine={{ stroke:C.border }} tickLine={false} />
          <YAxis type="category" dataKey="name" width={130} tick={{ fill:C.sub, fontSize:11 }} axisLine={false} tickLine={false} />
          <Tooltip content={<Tip />} cursor={{ fill:"rgba(0,0,0,0.025)" }} />
          <Bar dataKey="HIGH" stackId="s" fill="#FCA5A5" barSize={10} />
          <Bar dataKey="MEDIUM" stackId="s" fill="#FCD34D" barSize={10} />
          <Bar dataKey="LOW" stackId="s" fill="#93C5FD" barSize={10} radius={[0,3,3,0]} />
        </BarChart>
      </ResponsiveContainer>
      <div style={{ display:"flex", gap:14, marginTop:12 }}>
        {[["HIGH","#FCA5A5"],["MEDIUM","#FCD34D"],["LOW","#93C5FD"]].map(([l,bg])=>(
          <div key={l} style={{ display:"flex", alignItems:"center", gap:5 }}>
            <span style={{ width:10, height:10, borderRadius:2, background:bg, display:"inline-block" }} />
            <span style={{ fontSize:10, color:C.muted, fontFamily:"monospace" }}>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Row({ f2, i }) {
  const [open, setOpen] = useState(false);
  const sv = SEV[f2.severity];
  return (
    <>
      <tr onClick={() => setOpen(o=>!o)} style={{ background:open?sv.bg:i%2?"#FAFAFA":"#fff", cursor:"pointer", transition:"background 0.1s" }}>
        <td style={{ padding:"10px 14px", whiteSpace:"nowrap" }}><SevTag s={f2.severity} /></td>
        <td style={{ padding:"10px 8px", color:C.sub, fontSize:11, whiteSpace:"nowrap" }}>{CHECK_LABELS[f2.check]||f2.check}</td>
        <td style={{ padding:"10px 8px", color:C.text, fontSize:12, fontFamily:"ui-monospace,monospace", whiteSpace:"nowrap" }}>{f2.resource_name}</td>
        <td style={{ padding:"10px 8px 10px 0", color:C.sub, fontSize:12, maxWidth:300 }}><span style={{ display:"-webkit-box", WebkitLineClamp:1, WebkitBoxOrient:"vertical", overflow:"hidden" }}>{f2.issues[0]}</span></td>
        <td style={{ padding:"10px 14px", textAlign:"right", color:C.muted }}>{open?<ChevronUp size={12}/>:<ChevronDown size={12}/>}</td>
      </tr>
      {open && (
        <tr><td colSpan={5} style={{ padding:0 }}>
          <div style={{ padding:"16px 18px 18px 18px", background:sv.bg, borderTop:`1px solid ${sv.border}`, borderBottom:`1px solid ${sv.border}`, display:"grid", gridTemplateColumns:"1fr 1fr", gap:"14px 28px" }}>
            <div><p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", marginBottom:6 }}>What's wrong</p><p style={{ color:C.text, fontSize:12, lineHeight:1.7 }}>{f2.description}</p></div>
            <div><p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", marginBottom:6 }}>How to fix it</p><p style={{ color:"#1D4ED8", fontSize:12, lineHeight:1.7 }}>{f2.remediation}</p></div>
            <div style={{ gridColumn:"1/-1" }}><p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", marginBottom:4 }}>ARN</p><code style={{ color:C.sub, fontSize:10, fontFamily:"ui-monospace,monospace" }}>{f2.resource_arn}</code></div>
          </div>
        </td></tr>
      )}
    </>
  );
}

function FindingsTable({ findings }) {
  const [filter, setFilter] = useState("ALL");
  const counts = { ALL:findings.length, HIGH:0, MEDIUM:0, LOW:0 };
  findings.forEach(f2 => counts[f2.severity]++);
  const ORDER = { HIGH:0, MEDIUM:1, LOW:2 };
  const visible = [...(filter==="ALL"?findings:findings.filter(f2=>f2.severity===filter))].sort((a,b)=>ORDER[a.severity]-ORDER[b.severity]);
  return (
    <div style={{ ...card, overflow:"hidden" }}>
      <div style={{ display:"flex", alignItems:"center", borderBottom:`1px solid ${C.border}`, background:"#F8F8FA", padding:"0 6px" }}>
        <span style={{ color:C.muted, fontSize:9, letterSpacing:"0.14em", textTransform:"uppercase", padding:"0 12px" }}>Findings</span>
        <div style={{ display:"flex", marginLeft:"auto" }}>
          {["ALL","HIGH","MEDIUM","LOW"].map(tab => {
            const active = filter===tab;
            const sv = SEV[tab];
            const col = tab==="ALL"?C.amber:sv?.fg;
            const bg2 = tab==="ALL"?"#FEF3C7":sv?.bg;
            return (
              <button key={tab} onClick={()=>setFilter(tab)} style={{ background:"transparent", border:"none", borderBottom:active?`2px solid ${col}`:"2px solid transparent", color:active?col:C.muted, padding:"10px 13px", cursor:"pointer", fontSize:10, fontWeight:700, letterSpacing:"0.08em", display:"flex", alignItems:"center", gap:6, fontFamily:"ui-monospace,monospace", transition:"color 0.12s" }}>
                {tab}<span style={{ background:active?bg2:"#EEEFF3", color:active?col:C.muted, border:`1px solid ${active?(col+"40"):C.border}`, borderRadius:999, padding:"0 6px", fontSize:9 }}>{counts[tab]}</span>
              </button>
            );
          })}
        </div>
      </div>
      <div style={{ overflowX:"auto" }}>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead>
            <tr style={{ background:"#F8F8FA", borderBottom:`1px solid ${C.border}` }}>
              {["Severity","Check","Resource","Issue",""].map((h,idx)=>(
                <th key={idx} style={{ padding:"8px 14px", textAlign:"left", color:C.muted, fontSize:9, fontWeight:700, letterSpacing:"0.12em", textTransform:"uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length===0
              ?<tr><td colSpan={5} style={{ padding:40, textAlign:"center", color:C.muted, fontSize:13 }}>No findings for this filter.</td></tr>
              :visible.map((f2,i)=><Row key={`${f2.resource_arn}-${i}`} f2={f2} i={i}/>)
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScenarioSwitcher({ currentGrade, onSwitch }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
      <span style={{ color:C.muted, fontSize:9, letterSpacing:"0.1em", textTransform:"uppercase", marginRight:2 }}>Switch</span>
      {["A","B","C","D","F"].map(g => {
        const gc = GRADE[g];
        const active = currentGrade===g;
        return (
          <button key={g} onClick={()=>!active&&onSwitch(g)} style={{ width:30, height:30, borderRadius:7, background:active?gc.hex:`${gc.hex}12`, color:active?"#fff":gc.hex, border:`1.5px solid ${active?gc.hex:gc.hex+"44"}`, fontWeight:800, fontSize:12, cursor:active?"default":"pointer", fontFamily:"system-ui", transition:"all 0.15s", display:"flex", alignItems:"center", justifyContent:"center" }}>
            {g}
          </button>
        );
      })}
      <button onClick={()=>onSwitch(currentGrade)} title="Randomize within grade" style={{ width:30, height:30, borderRadius:7, background:C.bg, border:`1px solid ${C.border}`, cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", color:C.muted, transition:"all 0.15s" }}>
        <RefreshCw size={13}/>
      </button>
    </div>
  );
}

function CleanAccount({ label }) {
  return (
    <div style={{ ...card, padding:"48px 32px", textAlign:"center" }}>
      <div style={{ width:64, height:64, borderRadius:"50%", background:"#F0FDF4", border:"2px solid #BBF7D0", display:"flex", alignItems:"center", justifyContent:"center", margin:"0 auto 16px", fontSize:28 }}>✓</div>
      <h2 style={{ fontSize:20, fontWeight:800, color:"#15803D", margin:"0 0 8px" }}>No findings detected</h2>
      <p style={{ color:C.muted, fontSize:14, maxWidth:400, margin:"0 auto", lineHeight:1.6 }}>All 7 security checks passed. This account follows AWS security best practices.</p>
    </div>
  );
}

function Dashboard({ report, isSample, onReset, onSwitch }) {
  const { grade, score, account_id, label, summary, findings } = report;
  const g = GRADE[grade] || GRADE.F;
  return (
    <div style={{ minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"system-ui,-apple-system,sans-serif" }}>
      <div style={{ height:3, background:`linear-gradient(to right,${g.hex},${C.amber})` }} />
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"11px 24px", background:"#fff", borderBottom:`1px solid ${C.border}`, position:"sticky", top:0, zIndex:10, boxShadow:"0 1px 3px rgba(0,0,0,0.06)" }}>
        <button onClick={onReset} style={{ display:"flex", alignItems:"center", gap:8, background:"transparent", border:"none", cursor:"pointer", padding:"4px 0", color:C.text }}>
          <Shield size={15} color={C.amber} />
          <span style={{ fontWeight:700, fontSize:13, letterSpacing:"-0.01em" }}>AWS IAM Scanner</span>
          {isSample && <span style={{ background:"#FEF3C7", color:C.amber, border:"1px solid #FDE68A", borderRadius:4, padding:"2px 7px", fontSize:8, fontWeight:700, letterSpacing:"0.12em" }}>DEMO</span>}
        </button>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          {isSample && <ScenarioSwitcher currentGrade={grade} onSwitch={onSwitch} />}
          <span style={{ color:C.muted, fontSize:11, fontFamily:"ui-monospace,monospace" }}>{account_id}</span>
          <button onClick={onReset} style={{ display:"flex", alignItems:"center", gap:5, background:C.bg, border:`1px solid ${C.border}`, color:C.sub, borderRadius:7, padding:"5px 12px", cursor:"pointer", fontSize:11, fontWeight:500 }}>
            <ArrowLeft size={11}/> Back
          </button>
        </div>
      </div>
      {isSample && label && (
        <div style={{ background:`${g.hex}10`, borderBottom:`1px solid ${g.hex}20`, padding:"8px 24px", display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:11, fontWeight:700, color:g.hex }}>DEMO — {label}</span>
          <span style={{ color:C.muted, fontSize:11 }}>{report.description}</span>
        </div>
      )}
      <div style={{ maxWidth:1040, margin:"0 auto", padding:"24px 18px", display:"flex", flexDirection:"column", gap:14 }}>
        <div style={{ display:"flex", gap:14, alignItems:"stretch", flexWrap:"wrap" }}>
          <GradePanel grade={grade} score={score} isSample={isSample} />
          <StatCards summary={summary} />
        </div>
        {findings.length===0 ? <CleanAccount label={label}/> : (
          <>
            <Breakdown findings={findings}/>
            <FindingsTable findings={findings}/>
          </>
        )}
      </div>
    </div>
  );
}

// ── Guide ─────────────────────────────────────────────────────────────────────
function Code({ children }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(children.trim()); setCopied(true); setTimeout(()=>setCopied(false),2000); };
  return (
    <div style={{ position:"relative", margin:"10px 0" }}>
      <pre style={{ background:"#1E1E2E", color:"#CDD6F4", borderRadius:10, padding:"14px 48px 14px 18px", fontSize:13, fontFamily:"ui-monospace,monospace", lineHeight:1.7, margin:0, overflowX:"auto", whiteSpace:"pre-wrap", wordBreak:"break-all" }}>{children.trim()}</pre>
      <button onClick={copy} style={{ position:"absolute", top:10, right:10, background:copied?"#22C55E22":"#ffffff18", border:"none", borderRadius:6, color:copied?"#22C55E":"#9CA3AF", padding:"4px 8px", cursor:"pointer", fontSize:11, display:"flex", alignItems:"center", gap:4 }}>
        {copied?<Check size={12}/>:<Copy size={12}/>}{copied?"Copied":"Copy"}
      </button>
    </div>
  );
}
function Step({ number, title, children }) {
  return (
    <div style={{ display:"flex", gap:18, padding:"24px 0", borderBottom:`1px solid ${C.border}` }}>
      <div style={{ flexShrink:0 }}><div style={{ width:34, height:34, borderRadius:"50%", background:C.amber, color:"#fff", display:"flex", alignItems:"center", justifyContent:"center", fontWeight:800, fontSize:14 }}>{number}</div></div>
      <div style={{ flex:1, minWidth:0 }}>
        <h3 style={{ margin:"4px 0 12px", fontSize:15, fontWeight:700, color:C.text }}>{title}</h3>
        {children}
      </div>
    </div>
  );
}
function Note({ children, type="info" }) {
  const s = { info:{ bg:"#EFF6FF",border:"#BFDBFE",color:"#1D4ED8",icon:"ℹ️" }, warning:{ bg:"#FFFBEB",border:"#FDE68A",color:"#B45309",icon:"⚠️" }, tip:{ bg:"#F0FDF4",border:"#BBF7D0",color:"#15803D",icon:"💡" } }[type];
  return <div style={{ background:s.bg, border:`1px solid ${s.border}`, borderRadius:8, padding:"10px 14px", fontSize:13, color:s.color, lineHeight:1.6, margin:"10px 0", display:"flex", gap:8 }}><span>{s.icon}</span><span>{children}</span></div>;
}
function PlatformToggle({ value, onChange }) {
  return (
    <div style={{ display:"flex", gap:4, margin:"10px 0 4px" }}>
      {["Mac / Linux","Windows"].map(p=>(
        <button key={p} onClick={()=>onChange(p)} style={{ background:value===p?C.amber:C.bg, color:value===p?"#fff":C.sub, border:`1px solid ${value===p?C.amber:C.border}`, borderRadius:6, padding:"4px 12px", cursor:"pointer", fontSize:12, fontWeight:600, transition:"all 0.12s" }}>{p}</button>
      ))}
    </div>
  );
}

function Guide({ onUpload }) {
  const [platform, setPlatform] = useState("Mac / Linux");
  const isMac = platform==="Mac / Linux";
  return (
    <div style={{ minHeight:"100vh", background:C.bg, fontFamily:"system-ui,-apple-system,sans-serif" }}>
      <div style={{ background:"#fff", borderBottom:`1px solid ${C.border}`, padding:"11px 24px", display:"flex", alignItems:"center", justifyContent:"space-between", position:"sticky", top:0, zIndex:10, boxShadow:"0 1px 3px rgba(0,0,0,0.06)" }}>
        <div style={{ display:"flex", alignItems:"center", gap:9 }}><Shield size={15} color={C.amber}/><span style={{ fontWeight:700, fontSize:13, color:C.text }}>AWS IAM Scanner</span></div>
        <button onClick={onUpload} style={{ display:"flex", alignItems:"center", gap:6, background:C.amber, color:"#fff", border:"none", borderRadius:7, padding:"6px 14px", cursor:"pointer", fontSize:12, fontWeight:600 }}><UploadIcon size={12}/> Upload report</button>
      </div>
      <div style={{ maxWidth:720, margin:"0 auto", padding:"36px 22px 80px" }}>
        <h1 style={{ fontSize:26, fontWeight:800, color:C.text, margin:"0 0 10px", letterSpacing:"-0.02em" }}>How to scan your AWS account</h1>
        <p style={{ color:C.sub, fontSize:14, lineHeight:1.75, margin:"0 0 24px" }}>This guide walks you through scanning your AWS account for security issues — step by step. You don't need to be a developer, but you'll need access to a terminal and an AWS account. The whole process takes about 10 minutes.</p>
        <div style={{ ...card, padding:"16px 20px", marginBottom:24 }}>
          <p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", margin:"0 0 10px" }}>What the scanner checks</p>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"6px 20px" }}>
            {["Overly permissive IAM policies","Users without MFA enabled","Stale or unused access keys","Publicly exposed S3 buckets","Misconfigured trust policies","Roles that should be deleted","Least-privilege policy generator"].map(item=>(
              <div key={item} style={{ display:"flex", alignItems:"center", gap:8, fontSize:13, color:C.sub }}><span style={{ color:"#22C55E", fontWeight:700 }}>✓</span>{item}</div>
            ))}
          </div>
        </div>
        <Step number={1} title="Open your terminal">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 10px" }}>The terminal is a text-based way to control your computer. You'll just be copying and pasting commands into it.</p>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
            {[{os:"Mac",how:"Press ⌘ + Space, type Terminal, press Enter"},{os:"Windows",how:"Press the Windows key, type PowerShell, press Enter"}].map(({os,how})=>(
              <div key={os} style={{ background:C.bg, borderRadius:8, padding:"12px 14px", border:`1px solid ${C.border}` }}><p style={{ fontWeight:700, fontSize:13, color:C.text, margin:"0 0 4px" }}>{os}</p><p style={{ color:C.sub, fontSize:12, margin:0 }}>{how}</p></div>
            ))}
          </div>
        </Step>
        <Step number={2} title="Check that Python is installed">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 10px" }}>Paste this into your terminal and hit Enter:</p>
          <Code>python3 --version</Code>
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"10px 0" }}>You should see something like <code style={{ background:C.bg, padding:"1px 6px", borderRadius:4, fontFamily:"monospace", fontSize:13 }}>Python 3.11.0</code>. If not, download Python from <a href="https://python.org" target="_blank" rel="noopener noreferrer" style={{ color:C.amber }}>python.org</a>.</p>
          <Note type="tip">Python 3.9 or newer will work.</Note>
        </Step>
        <Step number={3} title="Download the scanner">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 10px" }}>If you have Git installed:</p>
          <Code>{`git clone https://github.com/agandbhir123/aws-iam-scanner.git\ncd aws-iam-scanner`}</Code>
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"12px 0 10px" }}>Or <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ color:C.amber }}>download the ZIP from GitHub</a>, extract it, then:</p>
          <PlatformToggle value={platform} onChange={setPlatform}/>
          <Code>{isMac?"cd ~/Downloads/aws-iam-scanner":"cd C:\\Users\\YourName\\Downloads\\aws-iam-scanner"}</Code>
        </Step>
        <Step number={4} title="Install dependencies">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 6px" }}>Run these three commands in order:</p>
          <PlatformToggle value={platform} onChange={setPlatform}/>
          <Code>{isMac?`python3 -m venv venv\nsource venv/bin/activate\npip install -r requirements.txt`:`python3 -m venv venv\nvenv\\\\Scripts\\\\activate\npip install -r requirements.txt`}</Code>
          <Note type="info">Wait until you see <code style={{ fontFamily:"monospace" }}>Successfully installed</code> before moving on.</Note>
        </Step>
        <Step number={5} title="Get your AWS credentials">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 12px" }}>AWS credentials let programs read your account. The scanner only needs <strong>read access</strong> — it cannot change anything.</p>
          {[{n:"1",t:"Log into AWS",d:"Go to console.aws.amazon.com"},{n:"2",t:"Go to IAM",d:'Search for "IAM" in the top search bar'},{n:"3",t:"Create a user",d:'Users → Create user. Name it "scanner-user"'},{n:"4",t:"Attach a policy",d:'Choose ReadOnlyAccess (AWS managed - job function). Hit Next → Create user'},{n:"5",t:"Create an access key",d:"Security credentials tab → Create access key → CLI use case → Create"},{n:"6",t:"Copy your credentials",d:"Copy the Access key ID and Secret — you won't see the secret again"}].map(({n,t,d})=>(
            <div key={n} style={{ display:"flex", gap:12, marginBottom:10 }}>
              <span style={{ width:22, height:22, borderRadius:"50%", background:C.bg, border:`1px solid ${C.border}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color:C.sub, flexShrink:0, marginTop:1 }}>{n}</span>
              <div><span style={{ fontWeight:600, fontSize:13, color:C.text }}>{t} — </span><span style={{ fontSize:13, color:C.sub }}>{d}</span></div>
            </div>
          ))}
          <PlatformToggle value={platform} onChange={setPlatform}/>
          <Code>{isMac?`export AWS_ACCESS_KEY_ID=AKIA...your key...\nexport AWS_SECRET_ACCESS_KEY=...your secret...\nexport AWS_DEFAULT_REGION=us-east-1`:`$env:AWS_ACCESS_KEY_ID="AKIA...your key..."\n$env:AWS_SECRET_ACCESS_KEY="...your secret..."\n$env:AWS_DEFAULT_REGION="us-east-1"`}</Code>
          <Note type="warning">Never share credentials. Don't paste them into chat apps or websites.</Note>
        </Step>
        <Step number={6} title="Run the scanner">
          <Code>python -m scanner</Code>
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"10px 0" }}>Takes 1–2 minutes. When done, a file called <code style={{ background:C.bg, padding:"1px 6px", borderRadius:4, fontFamily:"monospace", fontSize:13 }}>iam_scan_report.json</code> will appear in the project folder.</p>
        </Step>
        <Step number={7} title="Upload your results here">
          <p style={{ color:C.sub, fontSize:14, lineHeight:1.7, margin:"0 0 14px" }}>Come back to this page and upload <code style={{ background:C.bg, padding:"1px 6px", borderRadius:4, fontFamily:"monospace", fontSize:13 }}>iam_scan_report.json</code>. You'll see your security grade, a breakdown of every finding, and fix instructions.</p>
          <button onClick={onUpload} style={{ display:"inline-flex", alignItems:"center", gap:8, background:C.amber, color:"#fff", border:"none", borderRadius:8, padding:"10px 22px", fontSize:14, fontWeight:700, cursor:"pointer", boxShadow:"0 1px 3px rgba(0,0,0,0.15)" }}><UploadIcon size={14}/> Upload report</button>
        </Step>
        <div style={{ textAlign:"center", marginTop:36 }}><p style={{ color:C.muted, fontSize:12 }}>Questions? Open an issue on <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ color:C.amber }}>GitHub</a></p></div>
      </div>
    </div>
  );
}

// ── Upload ────────────────────────────────────────────────────────────────────
function Upload({ onLoad, onGuide }) {
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState(null);
  const [leftPct, setLeftPct] = useState(34);
  const isDragging = useRef(false);
  const containerRef = useRef();
  const fileRef = useRef();

  const handle = useCallback(file => {
    if (!file) return;
    const r = new FileReader();
    r.onload = e => {
      try {
        const json = JSON.parse(e.target.result);
        if (!json.findings||!json.grade) throw new Error();
        onLoad({ report:json, isSample:false });
      } catch { setErr("Invalid file — upload the iam_scan_report.json from the scanner CLI."); }
    };
    r.readAsText(file);
  }, [onLoad]);

  const onDividerDown = useCallback(e => {
    isDragging.current = true; e.preventDefault();
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const onMove = e2 => {
      if (!isDragging.current||!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((e2.clientX-rect.left)/rect.width)*100;
      setLeftPct(Math.min(Math.max(pct,0),34));
    };
    const onUp = () => {
      isDragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove",onMove);
      document.removeEventListener("mouseup",onUp);
    };
    document.addEventListener("mousemove",onMove);
    document.addEventListener("mouseup",onUp);
  }, []);

  const checks = ["Overly permissive IAM policies","Users without MFA enabled","Stale or unused access keys","Publicly exposed S3 buckets","Misconfigured trust policies","Roles that should be deleted","Least-privilege policy generator"];

  return (
    <div style={{ minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"system-ui,-apple-system,sans-serif", display:"flex", flexDirection:"column" }}>
      <div style={{ height:3, background:C.amber, flexShrink:0 }} />
      <div style={{ background:"#fff", borderBottom:`1px solid ${C.border}`, padding:"11px 24px", display:"flex", alignItems:"center", gap:9, flexShrink:0 }}>
        <Shield size={15} color={C.amber}/><span style={{ fontWeight:700, fontSize:13, color:C.text }}>AWS IAM Scanner</span>
      </div>
      <div ref={containerRef} style={{ flex:1, display:"flex", minHeight:0 }}>
        {leftPct>1 && (
          <div style={{ flex:`0 0 ${leftPct}%`, background:"#fff", overflow:"auto", padding:"52px 36px", display:"flex", flexDirection:"column", justifyContent:"center" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:18 }}>
              <Shield size={28} color={C.amber}/>
              <div>
                <h1 style={{ fontSize:22, fontWeight:800, letterSpacing:"-0.02em", margin:0, color:C.text, lineHeight:1.1 }}>AWS IAM Scanner</h1>
                <p style={{ color:C.muted, fontSize:12, margin:"3px 0 0" }}>Security audit for your AWS account</p>
              </div>
            </div>
            <p style={{ color:C.sub, fontSize:13, lineHeight:1.75, margin:"0 0 28px", maxWidth:360 }}>Run the scanner locally against your AWS account, then upload the report here to see your security grade, a breakdown of every finding, and step-by-step fix instructions.</p>
            <div style={{ marginBottom:28 }}>
              <p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", margin:"0 0 12px", fontWeight:700 }}>What gets checked</p>
              <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                {checks.map(item=>(
                  <div key={item} style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ width:18, height:18, borderRadius:"50%", background:"#F0FDF4", border:"1px solid #BBF7D0", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, fontSize:10, color:"#16A34A", fontWeight:700 }}>✓</span>
                    <span style={{ fontSize:13, color:C.sub }}>{item}</span>
                  </div>
                ))}
              </div>
            </div>
            <a href="https://github.com/agandbhir123/aws-iam-scanner" target="_blank" rel="noopener noreferrer" style={{ display:"inline-flex", alignItems:"center", gap:6, color:C.muted, fontSize:12, textDecoration:"none" }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              View on GitHub
            </a>
          </div>
        )}
        <div onMouseDown={onDividerDown} style={{ width:5, flexShrink:0, background:C.border, cursor:"col-resize", display:"flex", alignItems:"center", justifyContent:"center", transition:"background 0.15s" }} onMouseEnter={e=>e.currentTarget.style.background=C.amber} onMouseLeave={e=>e.currentTarget.style.background=C.border}>
          <div style={{ display:"flex", flexDirection:"column", gap:3, pointerEvents:"none" }}>
            {[0,1,2].map(i=><div key={i} style={{ width:3, height:3, borderRadius:"50%", background:C.muted }}/>)}
          </div>
        </div>
        <div style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:"48px 36px", overflow:"auto" }}>
          <div style={{ display:"flex", background:"#fff", border:`1px solid ${C.border}`, borderRadius:10, padding:4, gap:4, marginBottom:24, boxShadow:"0 1px 3px rgba(0,0,0,0.05)" }}>
            {[{key:"upload",label:"Upload report",Icon:UploadIcon},{key:"guide",label:"How to use",Icon:BookOpen}].map(({key,label,Icon})=>(
              <button key={key} onClick={()=>key==="guide"&&onGuide()} style={{ display:"flex", alignItems:"center", gap:6, background:key==="upload"?C.amber:"transparent", color:key==="upload"?"#fff":C.muted, border:"none", borderRadius:7, padding:"8px 18px", cursor:"pointer", fontSize:13, fontWeight:600, transition:"all 0.15s" }}>
                <Icon size={13}/>{label}
              </button>
            ))}
          </div>
          <div onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);handle(e.dataTransfer.files[0]);}} onClick={()=>fileRef.current?.click()} style={{ width:"100%", maxWidth:420, border:`2px dashed ${drag?C.amber:C.border}`, borderRadius:16, background:drag?"#FFFBEB":"#fff", padding:"48px 28px", display:"flex", flexDirection:"column", alignItems:"center", gap:12, cursor:"pointer", transition:"all 0.15s", boxShadow:"0 1px 4px rgba(0,0,0,0.06)" }}>
            <div style={{ width:52, height:52, borderRadius:12, background:drag?"#FEF3C7":C.bg, display:"flex", alignItems:"center", justifyContent:"center", transition:"all 0.15s" }}>
              <FileJson size={26} color={drag?C.amber:C.muted}/>
            </div>
            <div style={{ textAlign:"center" }}>
              <p style={{ fontWeight:700, fontSize:15, margin:"0 0 6px", color:C.text }}>Drop your scan report here</p>
              <p style={{ color:C.muted, fontSize:13, margin:0 }}>Upload <code style={{ fontFamily:"monospace", color:C.amber, fontSize:12, background:"#FEF3C7", padding:"1px 5px", borderRadius:4 }}>iam_scan_report.json</code></p>
            </div>
            <span style={{ color:C.muted, fontSize:12, marginTop:4 }}>or click to browse files</span>
            <input ref={fileRef} type="file" accept=".json" style={{ display:"none" }} onChange={e=>handle(e.target.files[0])}/>
          </div>
          {err && <p style={{ color:"#991B1B", fontSize:12, marginTop:10 }}>{err}</p>}
          <div style={{ display:"flex", alignItems:"center", gap:14, margin:"22px 0", width:"100%", maxWidth:420 }}>
            <div style={{ flex:1, height:1, background:C.border }}/>
            <span style={{ color:C.muted, fontSize:11 }}>or explore a demo</span>
            <div style={{ flex:1, height:1, background:C.border }}/>
          </div>
          <div style={{ width:"100%", maxWidth:420 }}>
            <p style={{ color:C.muted, fontSize:9, letterSpacing:"0.12em", textTransform:"uppercase", margin:"0 0 10px", fontWeight:700 }}>Pick a scenario</p>
            <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
              {["A","B","C","D","F"].map(grade => {
                const g = GRADE[grade];
                return (
                  <button key={grade} onClick={()=>onLoad({ report:getRandomScenario(grade), isSample:true })} style={{ display:"flex", alignItems:"center", gap:14, background:"#fff", border:`1px solid ${C.border}`, borderRadius:12, padding:"12px 16px", cursor:"pointer", textAlign:"left", transition:"border-color 0.15s, box-shadow 0.15s", boxShadow:"0 1px 3px rgba(0,0,0,0.05)" }} onMouseEnter={e=>{e.currentTarget.style.borderColor=g.hex;e.currentTarget.style.boxShadow=`0 0 0 3px ${g.hex}12`;}} onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.boxShadow="0 1px 3px rgba(0,0,0,0.05)";}}>
                    <div style={{ width:44, height:44, borderRadius:10, flexShrink:0, background:`linear-gradient(135deg,${g.soft},${g.hex}18)`, border:`1px solid ${g.hex}28`, display:"flex", alignItems:"center", justifyContent:"center" }}>
                      <span style={{ fontSize:22, fontWeight:900, color:g.hex, fontFamily:"system-ui", letterSpacing:"-0.03em" }}>{grade}</span>
                    </div>
                    <div style={{ flex:1, minWidth:0 }}>
                      <p style={{ margin:0, fontWeight:700, fontSize:13, color:C.text }}>{g.label}</p>
                      <p style={{ margin:"2px 0 0", fontSize:11, color:C.muted }}>{GRADE_FINDING_HINT[grade]} · 10 account profiles</p>
                    </div>
                    <RefreshCw size={13} color={C.muted} style={{ flexShrink:0 }}/>
                  </button>
                );
              })}
            </div>
            <p style={{ color:C.muted, fontSize:10, marginTop:10, textAlign:"center" }}>Each click loads a random real-world profile from 10 per grade</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [state, setState] = useState(null);
  const [showGuide, setShowGuide] = useState(false);

  const goBack = useCallback(() => { setState(null); setShowGuide(false); }, []);

  useEffect(() => {
    const onPop = () => goBack();
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [goBack]);

  const navigate = useCallback(newState => {
    window.history.pushState({},"");
    setState(newState);
    setShowGuide(false);
  }, []);

  const switchScenario = useCallback(grade => {
    navigate({ report:getRandomScenario(grade), isSample:true });
  }, [navigate]);

  if (showGuide) return <Guide onUpload={()=>{ setShowGuide(false); window.history.pushState({},""); }}/>;
  if (!state) return <Upload onLoad={navigate} onGuide={()=>{ setShowGuide(true); window.history.pushState({},""); }}/>;
  return <Dashboard report={state.report} isSample={state.isSample} onReset={goBack} onSwitch={switchScenario}/>;
}