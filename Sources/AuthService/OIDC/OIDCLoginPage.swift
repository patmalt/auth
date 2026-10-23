import Foundation

enum OIDCLoginPage {
    static func html(transaction: String, clientID: String, scopes: String, nonce: String) -> String {
        // Only server-generated base64url values enter JavaScript. Client-controlled text is HTML-escaped.
        """
        <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
        <title>Authorize sign-in</title>
        <h1>Sign in with your passkey</h1>
        <p>Authorize <strong>\(escape(clientID))</strong> to access: \(escape(scopes)).</p>
        <p>Continuing grants access to this application. Offline access permits sign-in to be renewed for up to 30 days.</p>
        <label>Username <input id="username" autocomplete="username webauthn"></label>
        <button id="signin">Sign in and authorize</button><p id="message" role="status"></p>
        <script nonce="\(nonce)">
        const transaction = '\(transaction)';
        const decode = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')), c=>c.charCodeAt(0));
        const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
        async function post(path, body) {
          const response = await fetch(path, {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({transaction,...body})});
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || 'Sign-in failed');
          return result;
        }
        document.getElementById('signin').onclick = async () => {
          const button = document.getElementById('signin'); button.disabled = true;
          try {
            const options = await post('/oauth/login/begin', {username:document.getElementById('username').value.trim()});
            options.challenge = decode(options.challenge);
            options.allowCredentials = options.allowCredentials.map(c=>({...c,id:decode(c.id)}));
            const credential = await navigator.credentials.get({publicKey:options});
            const r = credential.response;
            const result = await post('/oauth/login/complete', {credential:{id:credential.id,rawID:encode(credential.rawId),type:credential.type,
              authenticatorData:encode(r.authenticatorData),clientDataJSON:encode(r.clientDataJSON),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null}});
            window.location.assign(result.redirect);
          } catch (error) {
            document.getElementById('message').textContent = error.message + '. Restart sign-in from the application to retry.';
          }
        };
        </script></html>
        """
    }

    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
