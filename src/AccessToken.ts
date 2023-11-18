import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { ClaimGrants, VideoGrant } from './grants';

// 6 hours
const defaultTTL = 6 * 60 * 60;

export interface AccessTokenOptions {
  /**
   * amount of time before expiration
   * expressed in seconds or a string describing a time span zeit/ms.
   * eg: '2 days', '10h', or seconds as numeric value
   */
  ttl?: number | string;

  /**
   * display name for the participant, available as `Participant.name`
   */
  name?: string;

  /**
   * identity of the user, required for room join tokens
   */
  identity?: string;

  /**
   * custom metadata to be passed to participants
   */
  metadata?: string;
}

export class AccessToken {
  private apiKey: string;

  private apiSecret: string;

  private grants: ClaimGrants;

  identity?: string;

  ttl?: number | string;

  /**
   * Creates a new AccessToken
   * @param apiKey API Key, can be set in env LIVEKIT_API_KEY
   * @param apiSecret Secret, can be set in env LIVEKIT_API_SECRET
   */
  constructor(apiKey?: string, apiSecret?: string, options?: AccessTokenOptions) {
    if (!apiKey) {
      // apiKey = process.env.LIVEKIT_API_KEY;
    }
    if (!apiSecret) {
      // apiSecret = process.env.LIVEKIT_API_SECRET;
    }
    if (!apiKey || !apiSecret) {
      throw Error('api-key and api-secret must be set');
    }

    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
    this.grants = {};
    this.identity = options?.identity;
    this.ttl = options?.ttl || defaultTTL;
    if (options?.metadata) {
      this.metadata = options.metadata;
    }
    if (options?.name) {
      this.name = options.name;
    }
  }

  /**
   * Adds a video grant to this token.
   * @param grant
   */
  addGrant(grant: VideoGrant) {
    this.grants.video = { ...(this.grants.video ?? {}), ...grant };
  }

  /**
   * Set metadata to be passed to the Participant, used only when joining the room
   */
  set metadata(md: string) {
    this.grants.metadata = md;
  }

  set name(name: string) {
    this.grants.name = name;
  }

  get sha256(): string | undefined {
    return this.grants.sha256;
  }

  set sha256(sha: string | undefined) {
    this.grants.sha256 = sha;
  }

  /**
   * @returns JWT encoded token
   */
  async toJwt(): Promise<string> {
    // TODO: check for video grant validity

    // seconds since epoch:
    const s = Math.round(new Date().getTime() / 1000);
    const jwt = new SignJWT(this.grants as JWTPayload);
    jwt.setProtectedHeader({ alg: 'HS256' });
    jwt.setExpirationTime(typeof this.ttl === typeof 0 ? s + (this.ttl as number) : (this.ttl as string | Date));
    jwt.setIssuer(this.apiKey);
    jwt.setNotBefore(s);

    if (this.identity) {
      jwt.setSubject(this.identity);
      jwt.setJti(this.identity);
    } else if (this.grants.video?.roomJoin) {
      throw Error('identity is required for join but not set');
    }
    return jwt.sign(new TextEncoder().encode(this.apiSecret));
  }
}

export class TokenVerifier {
  private apiKey: string;

  private apiSecret: string;

  constructor(apiKey: string, apiSecret: string) {
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
  }

  async verify(token: string): Promise<ClaimGrants> {
    const decoded = await jwtVerify(token, new TextEncoder().encode(this.apiSecret), {
      issuer: this.apiKey,
    });

    if (!decoded || !decoded.payload) {
      throw Error('invalid token');
    }

    return decoded.payload as ClaimGrants;
  }
}
