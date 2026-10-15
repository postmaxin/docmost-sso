// A small User-Agent → "Browser on OS" label for Docmost's session list.
// Cosmetic only; it approximates the labels Docmost shows for password logins.

const BROWSERS: Array<[RegExp, string]> = [
  [/Edg(?:e|A|iOS)?\//, 'Microsoft Edge'],
  [/OPR\/|Opera/, 'Opera'],
  [/Firefox\/|FxiOS\//, 'Firefox'],
  [/Chrome\/|CriOS\//, 'Chrome'],
  [/Safari\//, 'Safari'],
];

const OSES: Array<[RegExp, string]> = [
  [/iPhone|iPad|iPod/, 'iOS'],
  [/Android/, 'Android'],
  [/Mac OS X|Macintosh/, 'macOS'],
  [/Windows/, 'Windows'],
  [/CrOS/, 'Chrome OS'],
  [/Linux/, 'Linux'],
];

export function deviceName(userAgent: string | undefined): string | null {
  if (!userAgent) return null;
  const ua = userAgent.slice(0, 512);
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1];
  const os = OSES.find(([re]) => re.test(ua))?.[1];
  if (/iPhone|iPad|iPod|Android.*Mobile/.test(ua)) {
    return /iPad/.test(ua) ? 'iPad' : /iPhone/.test(ua) ? 'iPhone' : os ?? 'Mobile Device';
  }
  if (os) return browser ? `${browser} on ${os}` : os;
  return browser ?? null;
}
