"use client";

import { useMemo, useState } from "react";
import {
  countrySetCommitment,
  normalizeZkIdentityPolicy,
  serializeZkIdentityPolicy,
  zkIdentityPolicyHash,
  type ZkIdentityPolicy,
  type ZkIdentityPolicyInput,
} from "@ubi2/sdk";
import { keccak256, stringToBytes } from "viem";
import { CountryCombobox } from "./country-combobox";
import { FieldLabel } from "./field-help";

type DemoKind =
  | "age-range"
  | "country-set"
  | "document-validity"
  | "document-authenticity"
  | "unique-human"
  | "dynamic-status"
  | "private-field-match";

interface DemoDefinition {
  kind: DemoKind;
  icon: string;
  title: string;
  summary: string;
  availability: "circuit" | "status" | "consent";
}

const DEMOS: DemoDefinition[] = [
  { kind: "age-range", icon: "Aa", title: "Age range", summary: "Prove a minimum or bounded range without revealing birth date.", availability: "circuit" },
  { kind: "country-set", icon: "◎", title: "Country set", summary: "Prove nationality or issuing state is in—or outside—a versioned group.", availability: "circuit" },
  { kind: "document-validity", icon: "◷", title: "Document validity", summary: "Prove the passport remains valid for a required number of days.", availability: "circuit" },
  { kind: "document-authenticity", icon: "◇", title: "Authentic document", summary: "Require passive authentication or stronger chip authentication.", availability: "circuit" },
  { kind: "unique-human", icon: "1", title: "Unique human", summary: "One person per action, or the same pseudonymous person inside one scope.", availability: "circuit" },
  { kind: "dynamic-status", icon: "✓", title: "Sanctions status", summary: "Require a fresh, versioned status credential instead of a stale passport claim.", availability: "status" },
  { kind: "private-field-match", icon: "=", title: "Private name match", summary: "Compare a committed application value only with explicit user consent.", availability: "consent" },
];

const SAMPLE_REGIONS = {
  "eu-eea:2026-08": ["AUT", "BEL", "BGR", "HRV", "CYP", "CZE", "DNK", "EST", "FIN", "FRA", "DEU", "GRC", "HUN", "ISL", "IRL", "ITA", "LVA", "LIE", "LTU", "LUX", "MLT", "NLD", "NOR", "POL", "PRT", "ROU", "SVK", "SVN", "ESP", "SWE"],
  "mercosur:2026-08": ["ARG", "BOL", "BRA", "PRY", "URY"],
  "latam-caribbean:2026-08": ["ARG", "BOL", "BRA", "CHL", "COL", "CRI", "CUB", "DOM", "ECU", "SLV", "GTM", "HTI", "HND", "MEX", "NIC", "PAN", "PRY", "PER", "URY", "VEN"],
} as const;

function isoToday(): string {
  return new Date().toISOString().slice(0, 10);
}

function shortHash(value: string): string {
  return `${value.slice(0, 12)}…${value.slice(-10)}`;
}

function buildPolicy(input: {
  ageMaximum: string;
  ageMinimum: string;
  assurance: "passive-auth" | "chip-auth";
  countryAttribute: "nationality" | "issuing-state";
  countryCode: string;
  countryOperator: "in" | "not-in";
  countrySetId: string;
  daysRemaining: string;
  demo: DemoKind;
  fieldCommitment: string;
  listVersion: string;
  nullifierMode: "single-use" | "stable-pseudonym";
  referenceDate: string;
  scope: string;
  statusMaxHours: string;
  statusRoot: string;
}): ZkIdentityPolicyInput {
  switch (input.demo) {
    case "age-range":
      return {
        kind: input.demo,
        minimumInclusive: Number(input.ageMinimum),
        maximumExclusive: input.ageMaximum.trim() ? Number(input.ageMaximum) : null,
        referenceDate: input.referenceDate,
      };
    case "country-set": {
      const members = input.countrySetId === "single-country:demo"
        ? [input.countryCode]
        : SAMPLE_REGIONS[input.countrySetId as keyof typeof SAMPLE_REGIONS] ?? [];
      return {
        kind: input.demo,
        attribute: input.countryAttribute,
        operator: input.countryOperator,
        setId: input.countrySetId,
        setRoot: countrySetCommitment({ setId: input.countrySetId, members: [...members] }),
      };
    }
    case "document-validity":
      return { kind: input.demo, referenceDate: input.referenceDate, minimumRemainingDays: Number(input.daysRemaining) };
    case "document-authenticity":
      return { kind: input.demo, minimumAssurance: input.assurance };
    case "unique-human":
      return { kind: input.demo, scope: input.scope, nullifierMode: input.nullifierMode };
    case "dynamic-status":
      return {
        kind: input.demo,
        status: "sanctions-clear",
        providerId: "self:ofac",
        listVersion: input.listVersion,
        statusRoot: input.statusRoot as `0x${string}`,
        maximumAgeSeconds: Number(input.statusMaxHours) * 3600,
      };
    case "private-field-match":
      return {
        kind: input.demo,
        field: "name",
        expectedCommitment: input.fieldCommitment as `0x${string}`,
        consentRequired: true,
      };
  }
}

function policyMeaning(policy: ZkIdentityPolicy): string {
  switch (policy.kind) {
    case "age-range":
      return policy.maximumExclusive === null
        ? `The credential holder is at least ${policy.minimumInclusive} on ${policy.referenceDate}.`
        : `The credential holder is ${policy.minimumInclusive}–${policy.maximumExclusive - 1} on ${policy.referenceDate}.`;
    case "country-set":
      return `Private ${policy.attribute} is ${policy.operator === "in" ? "inside" : "outside"} ${policy.setId}.`;
    case "document-validity":
      return `The passport is valid for at least ${policy.minimumRemainingDays} days after ${policy.referenceDate}.`;
    case "document-authenticity":
      return policy.minimumAssurance === "chip-auth"
        ? "The document passed signed-data verification and active/chip authentication."
        : "The document data is signed by an accepted passport issuer root.";
    case "unique-human":
      return policy.nullifierMode === "single-use"
        ? `The holder has not acted before in ${policy.scope}.`
        : `The holder has a stable pseudonym only inside ${policy.scope}.`;
    case "dynamic-status":
      return `A ${policy.providerId} sanctions-clear status under ${policy.listVersion} is no older than ${policy.maximumAgeSeconds / 3600} hours.`;
    case "private-field-match":
      return "The private passport name matches the committed application value; neither name is revealed.";
  }
}

export function V2PolicyLab() {
  const [demo, setDemo] = useState<DemoKind>("age-range");
  const [ageMinimum, setAgeMinimum] = useState("18");
  const [ageMaximum, setAgeMaximum] = useState("");
  const [referenceDate, setReferenceDate] = useState(isoToday);
  const [countryAttribute, setCountryAttribute] = useState<"nationality" | "issuing-state">("nationality");
  const [countryOperator, setCountryOperator] = useState<"in" | "not-in">("in");
  const [countrySetId, setCountrySetId] = useState("eu-eea:2026-08");
  const [countryCode, setCountryCode] = useState("ARG");
  const [daysRemaining, setDaysRemaining] = useState("180");
  const [assurance, setAssurance] = useState<"passive-auth" | "chip-auth">("passive-auth");
  const [scope, setScope] = useState("vote:proposal-42");
  const [nullifierMode, setNullifierMode] = useState<"single-use" | "stable-pseudonym">("single-use");
  const [listVersion, setListVersion] = useState(isoToday);
  const [statusMaxHours, setStatusMaxHours] = useState("24");
  const [statusRoot, setStatusRoot] = useState<string>(() => keccak256(stringToBytes("demo:self:ofac:2026-08-12")));
  const [fieldCommitment, setFieldCommitment] = useState<string>(() => keccak256(stringToBytes("demo:application-name-commitment")));
  const [copied, setCopied] = useState(false);

  const built = useMemo(() => {
    try {
      const policy = normalizeZkIdentityPolicy(buildPolicy({
        ageMaximum,
        ageMinimum,
        assurance,
        countryAttribute,
        countryCode,
        countryOperator,
        countrySetId,
        daysRemaining,
        demo,
        fieldCommitment,
        listVersion,
        nullifierMode,
        referenceDate,
        scope,
        statusMaxHours,
        statusRoot,
      }));
      return { policy, hash: zkIdentityPolicyHash(policy), error: null };
    } catch (error) {
      return { policy: null, hash: null, error: error instanceof Error ? error.message : String(error) };
    }
  }, [ageMaximum, ageMinimum, assurance, countryAttribute, countryCode, countryOperator, countrySetId, daysRemaining, demo, fieldCommitment, listVersion, nullifierMode, referenceDate, scope, statusMaxHours, statusRoot]);

  const selected = DEMOS.find((item) => item.kind === demo) ?? DEMOS[0];

  const copyPolicy = async () => {
    if (!built.policy || !built.hash) return;
    await navigator.clipboard.writeText(JSON.stringify({ policy: built.policy, policyHash: built.hash }, null, 2));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <section className="v2-policy-lab" aria-labelledby="v2-policy-title">
      <div className="v2-policy-heading">
        <div>
          <span className="eyebrow">v2 policy designer · development preview</span>
          <h2 id="v2-policy-title">Explore what one private passport credential can prove.</h2>
          <p>
            These demos build the real canonical policy objects and hashes planned for the v2 circuits and EVM
            verifier. They do <strong>not</strong> create a proof yet—the credential issuance circuit, local prover,
            status registry, and prover contracts are still under development.
          </p>
        </div>
        <span className="pill warn">No live v2 proof generated</span>
      </div>

      <div className="v2-use-case-grid" role="radiogroup" aria-label="v2 passport use cases">
        {DEMOS.map((item) => (
          <button
            type="button"
            role="radio"
            aria-checked={demo === item.kind}
            className={`v2-use-case${demo === item.kind ? " selected" : ""}`}
            key={item.kind}
            onClick={() => setDemo(item.kind)}
          >
            <span className="v2-use-case-icon" aria-hidden="true">{item.icon}</span>
            <b>{item.title}</b>
            <small>{item.summary}</small>
          </button>
        ))}
      </div>

      <div className="v2-builder-grid">
        <div className="v2-builder-controls">
          <div className="field-head"><span>Configure {selected.title.toLowerCase()}</span></div>

          {demo === "age-range" && (
            <>
              <div className="predicate-fields">
                <label className="predicate-field"><span>Minimum age</span><input type="number" min="0" max="125" value={ageMinimum} onChange={(event) => setAgeMinimum(event.target.value)} /></label>
                <label className="predicate-field"><span>Maximum age (optional)</span><input type="number" min="1" max="126" value={ageMaximum} onChange={(event) => setAgeMaximum(event.target.value)} placeholder="No maximum" /></label>
              </div>
              <label className="predicate-field"><span>Reference date</span><input type="date" value={referenceDate} onChange={(event) => setReferenceDate(event.target.value)} /></label>
            </>
          )}

          {demo === "country-set" && (
            <>
              <div className="predicate-fields">
                <label className="predicate-field"><span>Private passport field</span><select value={countryAttribute} onChange={(event) => setCountryAttribute(event.target.value as typeof countryAttribute)}><option value="nationality">Nationality</option><option value="issuing-state">Issuing state</option></select></label>
                <label className="predicate-field"><span>Rule</span><select value={countryOperator} onChange={(event) => setCountryOperator(event.target.value as typeof countryOperator)}><option value="in">Is in the set</option><option value="not-in">Is not in the set</option></select></label>
              </div>
              <label className="predicate-field"><span>Versioned country set</span><select value={countrySetId} onChange={(event) => setCountrySetId(event.target.value)}><option value="eu-eea:2026-08">EU + EEA · August 2026</option><option value="mercosur:2026-08">Mercosur full members · August 2026</option><option value="latam-caribbean:2026-08">Latin America + Caribbean · August 2026</option><option value="single-country:demo">One selected country · demo</option></select></label>
              {countrySetId === "single-country:demo" && (
                <div className="predicate-field country-field"><FieldLabel htmlFor="v2-country" label="Country">The country is used to build a one-member set commitment. A future proof reveals the set policy, not the private passport nationality.</FieldLabel><CountryCombobox id="v2-country" value={countryCode} onChange={setCountryCode} /></div>
              )}
            </>
          )}

          {demo === "document-validity" && (
            <div className="predicate-fields">
              <label className="predicate-field"><span>Reference date</span><input type="date" value={referenceDate} onChange={(event) => setReferenceDate(event.target.value)} /></label>
              <label className="predicate-field"><span>Required remaining days</span><input type="number" min="0" max="3650" value={daysRemaining} onChange={(event) => setDaysRemaining(event.target.value)} /></label>
            </div>
          )}

          {demo === "document-authenticity" && (
            <label className="predicate-field"><span>Minimum assurance</span><select value={assurance} onChange={(event) => setAssurance(event.target.value as typeof assurance)}><option value="passive-auth">Passive authentication · signed document data</option><option value="chip-auth">Chip authentication · where the passport supports it</option></select></label>
          )}

          {demo === "unique-human" && (
            <>
              <label className="predicate-field"><FieldLabel htmlFor="v2-scope" label="Uniqueness scope">A public, non-personal action identifier. It controls where the same holder secret produces the same or spendable nullifier.</FieldLabel><input id="v2-scope" value={scope} onChange={(event) => setScope(event.target.value)} /></label>
              <label className="predicate-field"><span>Nullifier behavior</span><select value={nullifierMode} onChange={(event) => setNullifierMode(event.target.value as typeof nullifierMode)}><option value="single-use">Single-use · one action per person</option><option value="stable-pseudonym">Stable only in this scope</option></select></label>
            </>
          )}

          {demo === "dynamic-status" && (
            <>
              <div className="notice warn">Sanctions status is external and changes over time. v2 treats it as a short-lived status credential, not as a permanent passport fact.</div>
              <div className="predicate-fields"><label className="predicate-field"><span>List version</span><input value={listVersion} onChange={(event) => setListVersion(event.target.value)} /></label><label className="predicate-field"><span>Maximum age (hours)</span><input type="number" min="1" max="8760" value={statusMaxHours} onChange={(event) => setStatusMaxHours(event.target.value)} /></label></div>
              <label className="predicate-field"><span>Status root (demo)</span><input value={statusRoot} onChange={(event) => setStatusRoot(event.target.value)} /></label>
            </>
          )}

          {demo === "private-field-match" && (
            <>
              <div className="notice warn">Exact names are sensitive and are excluded from the default credential. This optional equality policy requires explicit consent and a separately committed application value.</div>
              <label className="predicate-field"><span>Expected-name commitment</span><input value={fieldCommitment} onChange={(event) => setFieldCommitment(event.target.value)} /></label>
            </>
          )}

          {built.error && <div className="notice err" role="alert">{built.error}</div>}
        </div>

        <div className="v2-policy-preview" aria-live="polite">
          <span className="result-kicker">Canonical policy preview</span>
          <h3>{selected.title}</h3>
          {built.policy && built.hash ? (
            <>
              <p>{policyMeaning(built.policy)}</p>
              <div className="v2-policy-hash"><span>Policy hash</span><code title={built.hash}>{shortHash(built.hash)}</code></div>
              <pre><code>{serializeZkIdentityPolicy(built.policy)}</code></pre>
              <button className="btn ghost sm" type="button" onClick={copyPolicy}>{copied ? "Policy copied ✓" : "Copy policy + hash"}</button>
              <div className="v2-proof-boundary"><b>What a future verifier sees</b><span>policy hash · Boolean result · consumer/context binding · scoped nullifier · freshness</span><b>What stays private</b><span>passport fields · holder secret · issuer signature witness · registry path</span></div>
            </>
          ) : (
            <p className="muted">Fix the highlighted policy input to produce a canonical preview.</p>
          )}
        </div>
      </div>
    </section>
  );
}
