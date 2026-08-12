"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { countryByAlpha3, searchCountries, type CountryOption } from "../lib/countries";

interface CountryComboboxProps {
  disabled?: boolean;
  id: string;
  onChange(value: string): void;
  value: string;
}

export function CountryCombobox({ disabled = false, id, onChange, value }: CountryComboboxProps) {
  const selected = countryByAlpha3(value);
  const [query, setQuery] = useState(selected?.name ?? "");
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const listId = useId();

  useEffect(() => {
    setQuery(countryByAlpha3(value)?.name ?? "");
  }, [value]);

  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const matches = useMemo(() => {
    if (open && selected && query === selected.name) return searchCountries("");
    return searchCountries(query);
  }, [open, query, selected]);

  useEffect(() => {
    if (!open || !matches[activeIndex]) return;
    document
      .getElementById(`${listId}-${matches[activeIndex].alpha3}`)
      ?.scrollIntoView({ block: "nearest" });
  }, [activeIndex, listId, matches, open]);

  const showOptions = () => {
    setOpen(true);
    setActiveIndex(
      selected && query === selected.name
        ? Math.max(0, searchCountries("").findIndex((country) => country.alpha3 === selected.alpha3))
        : 0,
    );
  };

  const choose = (country: CountryOption) => {
    onChange(country.alpha3);
    setQuery(country.name);
    setOpen(false);
    setActiveIndex(0);
  };

  const updateQuery = (next: string) => {
    setQuery(next);
    setOpen(true);
    setActiveIndex(0);
    if (next !== selected?.name) onChange("");
  };

  return (
    <div className="country-combobox" ref={rootRef}>
      <div className={`country-input${open ? " open" : ""}`}>
        <span className="country-current-flag" aria-hidden="true">
          {selected?.flag ?? "🌐"}
        </span>
        <input
          id={id}
          type="text"
          role="combobox"
          aria-autocomplete="list"
          aria-controls={listId}
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-activedescendant={open && matches[activeIndex] ? `${listId}-${matches[activeIndex].alpha3}` : undefined}
          autoComplete="off"
          disabled={disabled}
          placeholder="Search country or code"
          value={query}
          onChange={(event) => updateQuery(event.target.value)}
          onFocus={showOptions}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              if (!open) showOptions();
              setActiveIndex((current) => Math.min(current + 1, Math.max(0, matches.length - 1)));
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              if (!open) showOptions();
              setActiveIndex((current) => Math.max(0, current - 1));
            } else if (event.key === "Home" && open) {
              event.preventDefault();
              setActiveIndex(0);
            } else if (event.key === "End" && open) {
              event.preventDefault();
              setActiveIndex(Math.max(0, matches.length - 1));
            } else if (event.key === "Enter" && open && matches[activeIndex]) {
              event.preventDefault();
              choose(matches[activeIndex]);
            } else if (event.key === "Escape") {
              setOpen(false);
              setQuery(selected?.name ?? "");
            } else if (event.key === "Tab") {
              setOpen(false);
            }
          }}
        />
        <button
          className="country-toggle"
          type="button"
          aria-label={open ? "Close country list" : "Open country list"}
          aria-expanded={open}
          disabled={disabled}
          onClick={() => {
            if (open) setOpen(false);
            else showOptions();
          }}
        >
          <span aria-hidden="true">⌄</span>
        </button>
      </div>

      {open && !disabled && (
        <ul className="country-options" id={listId} role="listbox" aria-label="Countries">
          {matches.length > 0 ? (
            matches.map((country, index) => (
              <li
                id={`${listId}-${country.alpha3}`}
                key={country.alpha3}
                role="option"
                aria-selected={country.alpha3 === value}
                className={`${index === activeIndex ? "active" : ""}${country.alpha3 === value ? " selected" : ""}`}
                onMouseDown={(event) => event.preventDefault()}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(country)}
              >
                <span className="country-flag" aria-hidden="true">{country.flag}</span>
                <span className="country-name">{country.name}</span>
                <span className="country-code">{country.alpha3}</span>
              </li>
            ))
          ) : (
            <li className="country-no-results" role="option" aria-disabled="true">
              No country matches “{query}”. Try a name or three-letter code.
            </li>
          )}
        </ul>
      )}
    </div>
  );
}
