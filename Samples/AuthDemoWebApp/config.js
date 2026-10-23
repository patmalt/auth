export const demoConfig = Object.freeze({
    issuer: 'https://auth.example.com',
    clientID: 'auth-demo-web',
    // Register this exact URL in OIDC_CLIENTS_JSON; an empty value uses the current origin + pathname.
    redirectURI: '',
});
