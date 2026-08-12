import isoCountries from "i18n-iso-countries";
import englishCountries from "i18n-iso-countries/langs/en.json";

isoCountries.registerLocale(englishCountries);

export interface CountryOption {
  alpha2: string;
  alpha3: string;
  flag: string;
  name: string;
  search: string;
}

function flagFor(alpha2: string): string {
  return Array.from(alpha2.toUpperCase(), (letter) =>
    String.fromCodePoint(0x1f1e6 + letter.charCodeAt(0) - 65),
  ).join("");
}

function searchable(value: string): string {
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

const collator = new Intl.Collator("en", { sensitivity: "base" });

/** ISO 3166-1 countries supported by the three-letter predicate descriptor. */
export const COUNTRIES: CountryOption[] = Object.entries(isoCountries.getAlpha3Codes())
  // XKK is a useful user-assigned code, but it is not ISO 3166-1 and is not emitted by Self.
  .filter(([alpha3]) => alpha3 !== "XKK")
  .map(([alpha3, alpha2]) => {
    const name = isoCountries.getName(alpha2, "en") ?? alpha3;
    return {
      alpha2,
      alpha3,
      flag: flagFor(alpha2),
      name,
      search: searchable(`${name} ${alpha2} ${alpha3}`),
    };
  })
  .sort((a, b) => collator.compare(a.name, b.name));

export function countryByAlpha3(alpha3: string): CountryOption | null {
  const code = alpha3.trim().toUpperCase();
  return COUNTRIES.find((country) => country.alpha3 === code) ?? null;
}

export function searchCountries(query: string): CountryOption[] {
  const terms = searchable(query).split(/\s+/).filter(Boolean);
  if (terms.length === 0) return COUNTRIES;
  return COUNTRIES.filter((country) => terms.every((term) => country.search.includes(term)));
}
