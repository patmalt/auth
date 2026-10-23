export const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')), c => c.charCodeAt(0));
export const random = () => encode(crypto.getRandomValues(new Uint8Array(32)));
const jsonPart = part => JSON.parse(new TextDecoder().decode(decode(part)));

export async function validateIDToken(token, jwks, { issuer, clientID, nonce, subject, now = Date.now() / 1000 }) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Malformed ID token');
    const header = jsonPart(parts[0]), claims = jsonPart(parts[1]);
    if (header.alg !== 'ES256' || typeof header.kid !== 'string' || header.crit !== undefined) throw new Error('Unsupported ID token algorithm');
    const keys = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'EC' && k.crv === 'P-256' && k.use === 'sig' && k.alg === 'ES256');
    if (keys.length !== 1) throw new Error('Unknown or ambiguous signing key');
    const key = await crypto.subtle.importKey('jwk', keys[0], { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, decode(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]))) throw new Error('Invalid ID token signature');
    // This sample/provider profile uses a single string audience.
    if (claims.iss !== issuer || claims.aud !== clientID || (claims.azp !== undefined && claims.azp !== clientID) ||
        typeof claims.sub !== 'string' || !claims.sub || !Number.isFinite(claims.exp) || claims.exp <= now ||
        !Number.isFinite(claims.iat) || claims.iat > now + 60 || claims.exp <= claims.iat ||
        (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + 60)) ||
        (nonce !== undefined && claims.nonce !== nonce) || (subject !== undefined && claims.sub !== subject)) throw new Error('Invalid ID token claims');
    return claims;
}

export function validateCallback(url, pending, now = Date.now()) {
    const callback = new URL(url);
    const expected = new URL(pending.redirectURI);
    for (const name of ['state', 'iss', 'code', 'error']) if (callback.searchParams.getAll(name).length > 1) throw new Error('Duplicate callback parameter');
    if (callback.origin !== expected.origin || callback.pathname !== expected.pathname || callback.hash ||
        now - pending.created > 300000 || pending.created > now || callback.searchParams.get('state') !== pending.state ||
        callback.searchParams.get('iss') !== pending.issuer) throw new Error('Invalid OIDC callback');
    if (callback.searchParams.has('error')) throw new Error(callback.searchParams.get('error'));
    const code = callback.searchParams.get('code');
    if (!code) throw new Error('Missing authorization code');
    return code;
}

export async function discovery(issuer) {
    const origin = new URL(issuer);
    if (origin.protocol !== 'https:' || issuer !== origin.origin) throw new Error('Issuer must be an HTTPS origin');
    const response = await fetch(issuer + '/.well-known/openid-configuration');
    if (!response.ok) throw new Error('Discovery failed');
    const metadata = await response.json();
    if (metadata.issuer !== issuer || !metadata.code_challenge_methods_supported?.includes('S256')) throw new Error('Invalid discovery document');
    for (const name of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'revocation_endpoint']) {
        const url = new URL(metadata[name]);
        if (url.origin !== issuer || url.username || url.password || url.hash) throw new Error('Unexpected discovery endpoint');
    }
    return metadata;
}
