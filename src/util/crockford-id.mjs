import crypto from "crypto";

// ULID-ish 26 chars, Crockford Base32 (no I,L,O,U)
const ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function crockford26() {
  // 16 bytes -> 26 base32 chars (roughly)
  const b = crypto.randomBytes(16);
  let out = "";
  let bits = 0;
  let val = 0;
  for (const byte of b) {
    val = (val << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPH[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPH[(val << (5 - bits)) & 31];
  return out.slice(0, 26);
}
