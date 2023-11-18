import { jwtVerify } from 'jose';
import { AccessToken, TokenVerifier } from './AccessToken';

const testApiKey = 'abcdefg';
const testSecret = 'abababa';

describe('encoded tokens are valid', async () => {
  const t = new AccessToken(testApiKey, testSecret, {
    identity: 'me',
    name: 'myname',
  });
  t.addGrant({ room: 'myroom' });
  const token = await t.toJwt();

  const decoded = <any>jwtVerify(token, new TextEncoder().encode(testSecret), { issuer: 'me' });
  it('can be decoded', () => {
    expect(decoded).not.toBe(undefined);
  });

  it('has name set', () => {
    expect(decoded.name).toBe('myname');
  });

  it('has video grants set', () => {
    expect(decoded.video).toBeTruthy();
    expect(decoded.video.room).toEqual('myroom');
  });
});

describe('identity is required for only join grants', () => {
  it('allows empty identity for create', () => {
    const t = new AccessToken(testApiKey, testSecret);
    t.addGrant({ roomCreate: true });

    expect(t.toJwt()).toBeTruthy();
  });
  it('throws error when identity is not provided for join', () => {
    const t = new AccessToken(testApiKey, testSecret);
    t.addGrant({ roomJoin: true });

    expect(() => {
      t.toJwt();
    }).toThrow();
  });
});

describe('verify token is valid', () => {
  it('can decode encoded token', async () => {
    const t = new AccessToken(testApiKey, testSecret);
    t.sha256 = 'abcdefg';
    t.addGrant({ roomCreate: true });

    const v = new TokenVerifier(testApiKey, testSecret);
    const decoded = await v.verify(await t.toJwt());

    expect(decoded).not.toBe(undefined);
    expect(decoded.sha256).toEqual('abcdefg');
    expect(decoded.video?.roomCreate).toBeTruthy();
  });
});

describe('adding grants should not overwrite existing grants', () => {
  it('should not overwrite existing grants', async () => {
    const t = new AccessToken(testApiKey, testSecret, {
      identity: 'me',
      name: 'myname',
    });
    t.addGrant({ roomCreate: true });
    t.addGrant({ roomJoin: true });

    const decoded = <any>(
      jwtVerify(await t.toJwt(), new TextEncoder().encode(testSecret), { issuer: 'me' })
    );
    expect(decoded.video?.roomCreate).toBeTruthy();
    expect(decoded.video?.roomJoin).toBeTruthy();
  });
});
