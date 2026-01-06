import crypto from "crypto";

// Crockford Base32 alphabet (no I, L, O, U)
const ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// ^[0-9A-HJKMNP-TV-Z]{26}$
export function crockford26() {
  const bytes = crypto.randomBytes(26);
  let out = "";
  for (let i = 0; i < 26; i++) out += ALPH[bytes[i] % 32];
  return out;
}
