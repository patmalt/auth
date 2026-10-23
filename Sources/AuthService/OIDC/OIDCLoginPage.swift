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
        <button id="signin">Sign in and authorize</button><button id="register">Create passkey and authorize</button><p id="message" role="status"></p>
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
        async function authorize(registering) {
          document.getElementById('signin').disabled = true; document.getElementById('register').disabled = true;
          try {
            const options = await post('/oauth/login/begin', {username:document.getElementById('username').value.trim(), mode:registering?'register':'login'});
            options.challenge = decode(options.challenge);
            if (registering) options.user.id = decode(options.user.id);
            else options.allowCredentials = options.allowCredentials.map(c=>({...c,id:decode(c.id)}));
            const credential = registering ? await navigator.credentials.create({publicKey:options}) : await navigator.credentials.get({publicKey:options});
            const r = credential.response;
            const base = {id:credential.id,rawID:encode(credential.rawId),type:credential.type,clientDataJSON:encode(r.clientDataJSON)};
            const proof = registering ? {...base,attestationObject:encode(r.attestationObject)} :
              {...base,authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null};
            const result = await post(registering?'/oauth/register/complete':'/oauth/login/complete', {credential:proof});
            window.location.assign(result.redirect);
          } catch (error) {
            document.getElementById('message').textContent = error.message + '. Restart sign-in from the application to retry.';
          }
        }
        document.getElementById('signin').onclick = () => authorize(false);
        document.getElementById('register').onclick = () => authorize(true);
        </script></html>
        """
    }

    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
