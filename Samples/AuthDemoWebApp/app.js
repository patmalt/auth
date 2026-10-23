import { demoConfig } from './config.js';
import { encode, random, validateIDToken, validateCallback, discovery } from './oidc.js';

const pendingKey = 'auth-demo.oidc.pending';
let session = null;
const $ = id => document.getElementById(id);
function status(message) { $('status').textContent = message; }
async function run(action) {
    for (const button of document.querySelectorAll('button')) button.disabled = true;
    try { await action(); } catch (error) { status(error.message); }
    finally { for (const button of document.querySelectorAll('button')) button.disabled = false; }
}
async function signIn() {
    const issuer = demoConfig.issuer;
    const metadata = await discovery(issuer);
    const pending = { issuer, clientID: demoConfig.clientID, redirectURI: demoConfig.redirectURI || location.origin + location.pathname,
        state: random(), nonce: random(), verifier: random(), created: Date.now() };
    const challenge = encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pending.verifier)));
    // Only the short-lived authorization transaction survives the browser redirect. Tokens remain in memory.
    sessionStorage.setItem(pendingKey, JSON.stringify(pending));
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({ client_id: pending.clientID, redirect_uri: pending.redirectURI, response_type: 'code',
        scope: 'openid profile', state: pending.state, nonce: pending.nonce, code_challenge: challenge, code_challenge_method: 'S256' });
    location.assign(url);
}
async function callback() {
    const callbackURL = location.href;
    const url = new URL(callbackURL);
    if (!url.searchParams.has('code') && !url.searchParams.has('error')) return;
    history.replaceState(null, '', location.pathname);
    const raw = sessionStorage.getItem(pendingKey); sessionStorage.removeItem(pendingKey);
    if (!raw) throw new Error('No pending sign-in');
    const pending = JSON.parse(raw);
    if (pending.issuer !== demoConfig.issuer || pending.clientID !== demoConfig.clientID) throw new Error('Configuration changed during sign-in');
    const code = validateCallback(callbackURL, pending);
    const metadata = await discovery(pending.issuer);
    const response = await fetch(metadata.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: pending.clientID, redirect_uri: pending.redirectURI, code, code_verifier: pending.verifier }) });
    const tokens = await response.json();
    if (!response.ok) throw new Error(tokens.error || 'Token exchange failed');
    if (tokens.token_type?.toLowerCase() !== 'bearer' || typeof tokens.access_token !== 'string') throw new Error('Invalid token response');
    const keysResponse = await fetch(metadata.jwks_uri);
    if (!keysResponse.ok) throw new Error('JWKS request failed');
    const claims = await validateIDToken(tokens.id_token, await keysResponse.json(), pending);
    session = { accessToken: tokens.access_token, subject: claims.sub, metadata };
    $('session').textContent = JSON.stringify({ subject: claims.sub, issuer: claims.iss, expires: new Date(claims.exp * 1000).toISOString() }, null, 2);
    status('Signed in through OIDC. Tokens are held in memory; reload requires sign-in again.');
}
async function profile() {
    if (!session) throw new Error('Sign in first');
    const response = await fetch(session.metadata.userinfo_endpoint, { headers: { Authorization: 'Bearer ' + session.accessToken } });
    const info = await response.json();
    if (!response.ok || info.sub !== session.subject) throw new Error('UserInfo failed or subject mismatch');
    $('profile').textContent = JSON.stringify(info, null, 2);
}
async function signOut() {
    const previous = session; session = null; sessionStorage.removeItem(pendingKey);
    $('session').textContent = 'Signed out'; $('profile').textContent = '';
    if (previous) {
        const response = await fetch(previous.metadata.revocation_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ client_id: demoConfig.clientID, token: previous.accessToken }) });
        if (!response.ok) throw new Error('Local session cleared, but server revocation failed');
    }
    status('Signed out');
}
$('signin').onclick = () => run(signIn);
$('userinfo').onclick = () => run(profile);
$('signout').onclick = () => run(signOut);
$('issuer').textContent = demoConfig.issuer;
run(callback);
