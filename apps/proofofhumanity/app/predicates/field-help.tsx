import type { ReactNode } from "react";

export function FieldHelp({ label, children }: { label: string; children: ReactNode }) {
  return (
    <details className="field-help">
      <summary aria-label={`What does ${label} mean?`}>?</summary>
      <span className="field-tooltip" role="tooltip">
        {children}
      </span>
    </details>
  );
}

export function FieldLabel({
  htmlFor,
  label,
  children,
}: {
  htmlFor: string;
  label: string;
  children: ReactNode;
}) {
  return (
    <span className="field-label-line">
      <label htmlFor={htmlFor}>{label}</label>
      <FieldHelp label={label}>{children}</FieldHelp>
    </span>
  );
}
