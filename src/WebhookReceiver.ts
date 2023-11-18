import { TokenVerifier } from './AccessToken';
import { WebhookEvent } from './proto/livekit_webhook';

export const authorizeHeader = 'Authorize';

// https://stackoverflow.com/a/11058858
function str2ab(str: string) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function base64FromBytes(arr: Uint8Array): string {
  const bin: string[] = [];
  arr.forEach((byte) => {
    bin.push(globalThis.String.fromCharCode(byte));
  });
  return globalThis.btoa(bin.join(''));
}

async function generateHashDigest(value: string) {
  const buffer = str2ab(value); // Fix
  const hashBytes = await window.crypto.subtle.digest('SHA-256', buffer);
  return base64FromBytes(new Uint8Array(hashBytes));
}

export class WebhookReceiver {
  private verifier: TokenVerifier;

  constructor(apiKey: string, apiSecret: string) {
    this.verifier = new TokenVerifier(apiKey, apiSecret);
  }

  /**
   *
   * @param body string of the posted body
   * @param authHeader `Authorization` header from the request
   * @param skipAuth true to skip auth validation
   * @returns
   */
  async receive(
    body: string,
    authHeader?: string,
    skipAuth: boolean = false,
  ): Promise<WebhookEvent> {
    // verify token
    if (!skipAuth) {
      if (!authHeader) {
        throw new Error('authorization header is empty');
      }
      const claims = await this.verifier.verify(authHeader);
      // confirm sha
      const hash = await generateHashDigest(body);

      if (claims.sha256 !== hash) {
        throw new Error('sha256 checksum of body does not match');
      }
    }

    return WebhookEvent.fromJSON(JSON.parse(body));
  }
}
