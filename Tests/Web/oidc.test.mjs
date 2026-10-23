import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encode, validateIDToken, validateCallback } from '../../Samples/AuthDemoWebApp/oidc.js';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const issuer = 'https://auth.example.com', clientID = 'web';
async function fixture() {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicKey = { ...await crypto.subtle.exportKey('jwk', keys.publicKey), kid: 'key', use: 'sig', alg: 'ES256' };
    const sign = async (overrides = {}, headerOverrides = {}) => {
        const now = Date.now() / 1000;
        const header = encode(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key', ...headerOverrides })));
        const payload = encode(new TextEncoder().encode(JSON.stringify({ iss: issuer, aud: clientID, sub: 'alice', nonce: 'nonce', iat: now, exp: now + 600, ...overrides })));
        const input = header + '.' + payload;
        return input + '.' + encode(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(input)));
    };
    return { jwks: { keys: [publicKey] }, sign };
}
test('validates ES256 signature and expected identity', async () => {
    const { jwks, sign } = await fixture();
    const claims = await validateIDToken(await sign(), jwks, { issuer, clientID, nonce: 'nonce' });
    assert.equal(claims.sub, 'alice');
});
test('rejects wrong issuer, audience, nonce, subject, expiry and algorithm', async () => {
    const { jwks, sign } = await fixture();
    for (const invalid of [{ iss: 'https://evil.example' }, { aud: 'other' }, { nonce: 'other' }, { exp: 1 }, { iat: Date.now() / 1000 + 1000 }]) {
        await assert.rejects(validateIDToken(await sign(invalid), jwks, { issuer, clientID, nonce: 'nonce' }));
    }
    await assert.rejects(validateIDToken(await sign(), jwks, { issuer, clientID, subject: 'someone-else' }));
    await assert.rejects(validateIDToken(await sign({}, { alg: 'HS256' }), jwks, { issuer, clientID }));
    const token = await sign();
    const parts = token.split('.'); parts[1] = encode(new TextEncoder().encode(JSON.stringify({ sub: 'attacker' })));
    await assert.rejects(validateIDToken(parts.join('.'), jwks, { issuer, clientID }));
});
test('callback requires matching state, issuer, URI and an unexpired transaction', () => {
    const pending = { issuer, redirectURI: 'https://app.example/callback', state: 'state', created: Date.now() };
    const callback = 'https://app.example/callback?code=code&state=state&iss=' + encodeURIComponent(issuer);
    assert.equal(validateCallback(callback, pending), 'code');
    assert.throws(() => validateCallback(callback + '&state=state', pending));
    assert.throws(() => validateCallback(callback.replace('state=state', 'state=evil'), pending));
    assert.throws(() => validateCallback(callback.replace('https://app.example', 'https://evil.example'), pending));
    assert.throws(() => validateCallback(callback, { ...pending, created: Date.now() - 300001 }));
});
