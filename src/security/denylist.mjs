import ipaddr from 'ipaddr.js';
import { lookup } from 'node:dns/promises';

// Anti-SSRF (audit 04 P0-11 — DANGER RÉEL : ce VPS héberge Katya Pole/PM2/metadata). On REFUSE toute IP
// interne. IPv4-mapped (::ffff:127.0.0.1) et CGNAT (100.64/10) couverts (pièges de contournement classiques).
const BLOCKED_RANGES = new Set([
  'unspecified',
  'broadcast',
  'multicast',
  'linkLocal',
  'loopback',
  'carrierGradeNat',
  'private',
  'reserved',
  'uniqueLocal', // IPv6 ULA
  'ipv4Mapped', // au cas où non démappé
]);

export function isBlockedIp(ip) {
  let addr;
  try {
    addr = ipaddr.parse(ip);
  } catch {
    return true; // non parsable → bloqué par prudence
  }
  if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
  return BLOCKED_RANGES.has(addr.range());
}

// Résolution DNS CONTRÔLÉE (anti-DNS-rebinding) : on résout soi-même, on vérifie CHAQUE IP, on connecte par IP.
export async function assertSafeHost(host, dnsLookup = lookup) {
  let isLiteral = false;
  try {
    ipaddr.parse(host);
    isLiteral = true;
  } catch {
    isLiteral = false;
  }
  if (isLiteral) {
    if (isBlockedIp(host)) throw new Error('SSRF_BLOCKED');
    return host;
  }
  const results = await dnsLookup(host, { all: true });
  if (!results || results.length === 0) throw new Error('SSRF_BLOCKED');
  for (const r of results) if (isBlockedIp(r.address)) throw new Error('SSRF_BLOCKED');
  return results[0].address;
}
