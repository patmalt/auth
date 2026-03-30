import { demoConfig } from "./config.js";

const STORAGE_KEYS = {
    apiBaseURL: "auth-demo-web.api-base-url",
    username: "auth-demo-web.username",
    accessToken: "auth-demo-web.access-token",
};

const MAX_STATUS_ENTRIES = 8;
const timeFormatter = new Intl.DateTimeFormat([], {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
});

const state = {
    busy: false,
    busyLabel: "Ready",
    accessToken: readSessionValue(STORAGE_KEYS.accessToken),
    profile: null,
    statusEntries: [],
    diagnostics: {
        secureContext: window.isSecureContext,
        webAuthn: typeof window.PublicKeyCredential !== "undefined",
        jsonHelpers: hasNativeJSONHelpers(),
        platformAuthenticator: null,
    },
};

const elements = {
    apiBaseURL: document.querySelector("#api-base-url"),
    username: document.querySelector("#username"),
    registerButton: document.querySelector("#register-button"),
    authenticateButton: document.querySelector("#authenticate-button"),
    meButton: document.querySelector("#me-button"),
    resetButton: document.querySelector("#reset-button"),
    tokenOutput: document.querySelector("#token-output"),
    profileOutput: document.querySelector("#profile-output"),
    tokenState: document.querySelector("#token-state"),
    busyIndicator: document.querySelector("#busy-indicator"),
    diagnostics: document.querySelector("#diagnostics"),
    frontendOrigin: document.querySelector("#frontend-origin"),
    supportSummary: document.querySelector("#support-summary"),
    statusLog: document.querySelector("#status-log"),
};

initialize();

async function initialize() {
    elements.apiBaseURL.value = readLocalValue(STORAGE_KEYS.apiBaseURL) ?? demoConfig.apiBaseURL;
    elements.username.value = readLocalValue(STORAGE_KEYS.username) ?? demoConfig.defaultUsername;
    elements.frontendOrigin.textContent = window.location.origin;

    bindEvents();
    renderDiagnostics();
    updateUI();

    if (state.accessToken) {
        pushStatus("Restored access token from this browser session.");
    } else {
        pushStatus("Ready.");
    }

    await probePlatformAuthenticator();
}

function bindEvents() {
    elements.apiBaseURL.addEventListener("input", () => {
        writeLocalValue(STORAGE_KEYS.apiBaseURL, elements.apiBaseURL.value.trim());
        updateUI();
    });

    elements.username.addEventListener("input", () => {
        writeLocalValue(STORAGE_KEYS.username, elements.username.value.trim());
        updateUI();
    });

    elements.registerButton.addEventListener("click", () => {
        void registerPasskey();
    });

    elements.authenticateButton.addEventListener("click", () => {
        void authenticate();
    });

    elements.meButton.addEventListener("click", () => {
        void loadProfile();
    });

    elements.resetButton.addEventListener("click", resetSession);
}

async function probePlatformAuthenticator() {
    if (!state.diagnostics.webAuthn) {
        state.diagnostics.platformAuthenticator = false;
        renderDiagnostics();
        return;
    }

    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        state.diagnostics.platformAuthenticator = false;
        renderDiagnostics();
        return;
    }

    try {
        state.diagnostics.platformAuthenticator =
            await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
        state.diagnostics.platformAuthenticator = false;
    }

    renderDiagnostics();
}

async function registerPasskey() {
    await runAction("Creating passkey", async () => {
        ensureBrowserReady();

        const username = currentUsername();
        const beginResponse = await requestJSON("register/begin", {
            method: "POST",
            body: {
                username,
                displayName: username,
            },
        });

        const publicKey = parseCreationOptions(beginResponse);
        const credential = await navigator.credentials.create({ publicKey });

        if (!(credential instanceof PublicKeyCredential)) {
            throw new Error("Passkey creation did not return a public-key credential.");
        }

        await requestJSON("register/complete", {
            method: "POST",
            body: {
                username,
                credential: registrationPayload(credential),
            },
        });

        pushStatus("Passkey created and uploaded to the server.");
    });
}

async function authenticate() {
    await runAction("Authenticating with passkey", async () => {
        ensureBrowserReady();

        const username = currentUsername();
        const beginResponse = await requestJSON("authenticate/begin", {
            method: "POST",
            body: {
                username,
            },
        });

        const publicKey = parseRequestOptions(beginResponse);
        const credential = await navigator.credentials.get({ publicKey });

        if (!(credential instanceof PublicKeyCredential)) {
            throw new Error("Passkey authentication did not return a public-key credential.");
        }

        const token = await requestJSON("authenticate/complete", {
            method: "POST",
            body: {
                username,
                credential: assertionPayload(credential),
            },
        });

        state.accessToken = token.accessToken;
        state.profile = null;
        writeSessionValue(STORAGE_KEYS.accessToken, token.accessToken);
        pushStatus(`Authenticated. Token expires at ${token.expiresAt}.`);
    });
}

async function loadProfile() {
    await runAction("Calling protected endpoint", async () => {
        const token = state.accessToken ?? readSessionValue(STORAGE_KEYS.accessToken);
        if (!token) {
            throw new Error("Authenticate first so the sample has a bearer token.");
        }

        const profile = await requestJSON("me", {
            method: "GET",
            token,
        });

        state.profile = profile;
        pushStatus(`Authenticated subject: ${profile.subject}`);
    });
}

function resetSession() {
    state.accessToken = null;
    state.profile = null;
    writeSessionValue(STORAGE_KEYS.accessToken, null);
    pushStatus("Cleared the browser session.");
    updateUI();
}

async function runAction(activity, action) {
    if (state.busy) {
        return;
    }

    setBusy(true, activity);
    try {
        await action();
    } catch (error) {
        pushStatus(formatError(error));
    } finally {
        setBusy(false, "Ready");
        updateUI();
    }
}

function ensureBrowserReady() {
    if (!state.diagnostics.secureContext) {
        throw new Error("Passkeys require HTTPS or localhost. Serve this page from a secure context.");
    }

    if (!state.diagnostics.webAuthn) {
        throw new Error("This browser does not expose the WebAuthn APIs required for passkeys.");
    }
}

function currentUsername() {
    const username = elements.username.value.trim();
    if (!username) {
        throw new Error("Enter a username before starting a passkey flow.");
    }
    return username;
}

function currentAPIBaseURL() {
    const value = elements.apiBaseURL.value.trim().replace(/\/+$/, "");
    if (!value) {
        throw new Error("Enter the auth service base URL first.");
    }

    try {
        const url = new URL(value);
        if (url.protocol !== "http:" && url.protocol !== "https:") {
            throw new Error("invalid-protocol");
        }
    } catch {
        throw new Error("The auth service base URL must be a valid absolute URL.");
    }

    return value;
}

async function requestJSON(path, options) {
    const baseURL = currentAPIBaseURL();
    const url = new URL(path, `${baseURL}/`);
    const headers = {
        Accept: "application/json",
    };

    if (options.body !== undefined) {
        headers["Content-Type"] = "application/json";
    }

    if (options.token) {
        headers.Authorization = `Bearer ${options.token}`;
    }

    try {
        const response = await fetch(url, {
            method: options.method,
            headers,
            body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        });

        const text = await response.text();
        const payload = text ? safeJSONParse(text) : null;

        if (!response.ok) {
            const message =
                payload?.error ??
                payload?.message ??
                `Request failed with status ${response.status}.`;
            throw new Error(message);
        }

        return payload;
    } catch (error) {
        if (error instanceof TypeError) {
            throw new Error(await describeConnectivityFailure(baseURL));
        }

        throw error;
    }
}

async function describeConnectivityFailure(baseURL) {
    const serviceReachable = await canReachServiceHealthCheck(baseURL);
    if (serviceReachable) {
        return `The browser reached ${baseURL}, but could not read the response. This usually means CORS is blocking ${window.location.origin}. Confirm CORS_ALLOWED_ORIGINS includes ${window.location.origin}.`;
    }

    return `The browser could not reach ${baseURL}. Confirm the service is running, then make sure CORS_ALLOWED_ORIGINS includes ${window.location.origin}.`;
}

async function canReachServiceHealthCheck(baseURL) {
    try {
        const healthURL = new URL("health", `${baseURL}/`);
        await fetch(healthURL, {
            method: "GET",
            mode: "no-cors",
            cache: "no-store",
        });
        return true;
    } catch {
        return false;
    }
}

function renderDiagnostics() {
    const diagnostics = [
        {
            label: "Secure context",
            value: state.diagnostics.secureContext ? "Ready" : "Required",
            hint: state.diagnostics.secureContext
                ? "This page is using HTTPS or localhost."
                : "Serve the sample from HTTPS or localhost before using passkeys.",
        },
        {
            label: "WebAuthn APIs",
            value: state.diagnostics.webAuthn ? "Available" : "Missing",
            hint: state.diagnostics.webAuthn
                ? "The browser exposes PublicKeyCredential."
                : "A passkey-capable browser is required.",
        },
        {
            label: "JSON helpers",
            value: state.diagnostics.jsonHelpers ? "Native" : "Fallback",
            hint: state.diagnostics.jsonHelpers
                ? "The sample can use native parse/toJSON WebAuthn helpers."
                : "The sample will fall back to its bundled base64url helpers.",
        },
        {
            label: "Platform authenticator",
            value:
                state.diagnostics.platformAuthenticator === null
                    ? "Checking"
                    : state.diagnostics.platformAuthenticator
                      ? "Available"
                      : "Not detected",
            hint:
                state.diagnostics.platformAuthenticator === null
                    ? "Asking the browser whether this device can store passkeys."
                    : state.diagnostics.platformAuthenticator
                      ? "Face ID, Touch ID, Windows Hello, or another local authenticator is available."
                      : "The browser did not confirm a local authenticator. Cross-device passkeys may still work.",
        },
    ];

    const fragment = document.createDocumentFragment();
    diagnostics.forEach((item) => {
        const li = document.createElement("li");
        const strong = document.createElement("strong");
        strong.textContent = `${item.label}: ${item.value}`;
        const span = document.createElement("span");
        span.textContent = item.hint;
        li.append(strong, span);
        fragment.append(li);
    });

    elements.diagnostics.replaceChildren(fragment);
    elements.supportSummary.textContent = summarizeSupport();
}

function summarizeSupport() {
    if (!state.diagnostics.secureContext || !state.diagnostics.webAuthn) {
        return "Needs setup";
    }

    return state.diagnostics.jsonHelpers ? "Ready" : "Ready with fallback";
}

function updateUI() {
    const hasUsername = Boolean(elements.username.value.trim());
    const hasBaseURL = isValidAbsoluteURL(elements.apiBaseURL.value.trim());

    elements.registerButton.disabled = state.busy || !hasUsername || !hasBaseURL || !state.diagnostics.webAuthn;
    elements.authenticateButton.disabled = state.busy || !hasUsername || !hasBaseURL || !state.diagnostics.webAuthn;
    elements.meButton.disabled = state.busy || !hasBaseURL || !state.accessToken;
    elements.resetButton.disabled = state.busy || (!state.accessToken && !state.profile);

    elements.busyIndicator.textContent = state.busy ? state.busyLabel : "Ready";
    elements.tokenState.textContent = state.accessToken ? "Token ready" : "No token";
    renderOutput(elements.tokenOutput, state.accessToken, "Authenticate to mint an access token.");
    renderOutput(
        elements.profileOutput,
        state.profile ? JSON.stringify(state.profile, null, 2) : "",
        "Call /me after authenticating."
    );
    renderStatusLog();
}

function renderOutput(element, value, emptyMessage) {
    const hasValue = Boolean(value);
    element.textContent = hasValue ? value : emptyMessage;
    element.classList.toggle("empty", !hasValue);
}

function renderStatusLog() {
    const fragment = document.createDocumentFragment();

    state.statusEntries.forEach((entry) => {
        const item = document.createElement("li");
        const timestamp = document.createElement("time");
        timestamp.textContent = entry.time;
        const message = document.createElement("span");
        message.textContent = entry.message;
        item.append(timestamp, message);
        fragment.append(item);
    });

    elements.statusLog.replaceChildren(fragment);
}

function pushStatus(message) {
    state.statusEntries.unshift({
        time: timeFormatter.format(new Date()),
        message,
    });
    state.statusEntries = state.statusEntries.slice(0, MAX_STATUS_ENTRIES);
    updateUI();
}

function setBusy(isBusy, label) {
    state.busy = isBusy;
    state.busyLabel = label;
    updateUI();
}

function parseCreationOptions(optionsJSON) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
        return PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON);
    }

    return {
        ...optionsJSON,
        challenge: base64URLToBuffer(optionsJSON.challenge),
        user: {
            ...optionsJSON.user,
            id: base64URLToBuffer(optionsJSON.user.id),
        },
        excludeCredentials: (optionsJSON.excludeCredentials ?? []).map((credential) => ({
            ...credential,
            id: base64URLToBuffer(credential.id),
        })),
    };
}

function parseRequestOptions(optionsJSON) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
        return PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON);
    }

    return {
        ...optionsJSON,
        challenge: base64URLToBuffer(optionsJSON.challenge),
        allowCredentials: (optionsJSON.allowCredentials ?? []).map((credential) => ({
            ...credential,
            id: base64URLToBuffer(credential.id),
        })),
    };
}

function registrationPayload(credential) {
    const json = credentialJSON(credential);
    return {
        id: json.id,
        rawID: json.rawId ?? json.rawID,
        type: json.type,
        attestationObject: json.response.attestationObject,
        clientDataJSON: json.response.clientDataJSON,
    };
}

function assertionPayload(credential) {
    const json = credentialJSON(credential);
    return {
        id: json.id,
        rawID: json.rawId ?? json.rawID,
        type: json.type,
        authenticatorData: json.response.authenticatorData,
        clientDataJSON: json.response.clientDataJSON,
        signature: json.response.signature,
        userHandle: json.response.userHandle ?? null,
    };
}

function credentialJSON(credential) {
    if (typeof credential.toJSON === "function") {
        return credential.toJSON();
    }

    const response = credential.response;
    const json = {
        id: credential.id,
        rawId: bufferToBase64URL(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bufferToBase64URL(response.clientDataJSON),
        },
    };

    if ("attestationObject" in response) {
        json.response.attestationObject = bufferToBase64URL(response.attestationObject);
    }

    if ("authenticatorData" in response) {
        json.response.authenticatorData = bufferToBase64URL(response.authenticatorData);
    }

    if ("signature" in response) {
        json.response.signature = bufferToBase64URL(response.signature);
    }

    if ("userHandle" in response) {
        json.response.userHandle = response.userHandle ? bufferToBase64URL(response.userHandle) : null;
    }

    return json;
}

function base64URLToBuffer(value) {
    const padded = value
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }

    return bytes.buffer;
}

function bufferToBase64URL(value) {
    const bytes = value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function formatError(error) {
    if (error instanceof Error) {
        if (error.name === "NotAllowedError") {
            return "The passkey request was cancelled or timed out before the browser could finish it.";
        }

        if (error.name === "InvalidStateError") {
            return "This authenticator believes a passkey for the account already exists on this device.";
        }

        if (error.name === "SecurityError") {
            return securityErrorMessage();
        }

        return error.message;
    }

    return String(error);
}

function securityErrorMessage() {
    const origin = window.location.origin;
    const hostname = window.location.hostname;
    return `The browser rejected the passkey request for ${origin}. Set RP_ORIGIN to ${origin} and set RP_ID to ${hostname} (or to a parent domain only if you intentionally want passkeys shared across subdomains). The API base URL can stay on a different host.`;
}

function safeJSONParse(value) {
    try {
        return JSON.parse(value);
    } catch {
        return null;
    }
}

function hasNativeJSONHelpers() {
    return typeof PublicKeyCredential !== "undefined"
        && typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"
        && typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function"
        && typeof PublicKeyCredential.prototype.toJSON === "function";
}

function isValidAbsoluteURL(value) {
    if (!value) {
        return false;
    }

    try {
        const url = new URL(value);
        return url.protocol === "http:" || url.protocol === "https:";
    } catch {
        return false;
    }
}

function readLocalValue(key) {
    try {
        return window.localStorage.getItem(key);
    } catch {
        return null;
    }
}

function writeLocalValue(key, value) {
    try {
        if (value) {
            window.localStorage.setItem(key, value);
        } else {
            window.localStorage.removeItem(key);
        }
    } catch {
        // Ignore storage failures in restricted browsing modes.
    }
}

function readSessionValue(key) {
    try {
        return window.sessionStorage.getItem(key);
    } catch {
        return null;
    }
}

function writeSessionValue(key, value) {
    try {
        if (value) {
            window.sessionStorage.setItem(key, value);
        } else {
            window.sessionStorage.removeItem(key);
        }
    } catch {
        // Ignore storage failures in restricted browsing modes.
    }
}
