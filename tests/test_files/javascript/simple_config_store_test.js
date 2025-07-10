// Simple test case to debug CWE-922 configuration store detection

// Test 1: Direct assignment (should work)
const config = store.get('plugins.lastfm');
const token = config.token;
store.set('new.token', token);

// Test 2: Property access in object literal (may not work)
const config2 = store.get('plugins.lastfm');
const newConfig = {
  token: config2.token,
  secret: config2.secret
};
store.set('new.config', newConfig);

// Test 3: Direct property access in store.set (may not work)
const config3 = store.get('plugins.lastfm');
store.set('direct.token', config3.token);

// Test 4: Specific lastfm pattern
const lastfmConfig = store.get('plugins.lastfm');
store.set('scrobbler.token', lastfmConfig.token);
store.set('scrobbler.session_key', lastfmConfig.session_key);
store.set('scrobbler.api_key', lastfmConfig.api_key);
store.set('scrobbler.secret', lastfmConfig.secret);

// Test 5: Inline object construction (user's pattern)
const lastfmConfig2 = store.get('plugins.lastfm');
store.set('plugins.scrobbler', {
  scrobblers: {
    lastfm: {
      token: lastfmConfig2.token,
      sessionKey: lastfmConfig2.session_key,
      apiKey: lastfmConfig2.api_key,
      secret: lastfmConfig2.secret
    }
  }
}); 