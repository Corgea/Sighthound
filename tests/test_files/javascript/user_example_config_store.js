// User's exact example pattern for CWE-922 testing
import { DefaultPresetList } from '@/plugins/downloader/types';

// Configuration store interface (simplified for JS)
// export type IStore = InstanceType<typeof import('conf/dist/source/index').default<Record<string, unknown>>>;

const migrations = {
  '>=3.3.0'(store) {
    const lastfmConfig = store.get('plugins.lastfm');
    if (lastfmConfig) {
      let scrobblerConfig = store.get('plugins.scrobbler');

      if (!scrobblerConfig) {
        scrobblerConfig = {
          enabled: lastfmConfig.enabled,
        };
      }

      if (!scrobblerConfig.scrobblers) {
        scrobblerConfig.scrobblers = {
          lastfm: {
            enabled: lastfmConfig.enabled,
            token: lastfmConfig.token,           // Source: sensitive property
            sessionKey: lastfmConfig.session_key, // Source: sensitive property  
            apiRoot: lastfmConfig.api_root,
            apiKey: lastfmConfig.api_key,        // Source: sensitive property
            secret: lastfmConfig.secret,         // Source: sensitive property
          },
        };
      }

      // Vulnerable: Storing sensitive authentication data in configuration store
      store.set('plugins.scrobbler', scrobblerConfig);  // Sink: store.set with sensitive data
    }
  }
};

// Additional test cases based on the pattern
const configMigration = {
  migrateAuthConfig(store) {
    const authConfig = store.get('auth.legacy');
    if (authConfig) {
      const newAuthConfig = {
        provider: 'oauth',
        credentials: {
          token: authConfig.token,           // Source: sensitive property
          refreshToken: authConfig.refresh_token, // Source: sensitive property
          apiKey: authConfig.api_key,        // Source: sensitive property
          secret: authConfig.secret,         // Source: sensitive property
          sessionKey: authConfig.session_key // Source: sensitive property
        }
      };
      
      // Vulnerable: Storing sensitive data during migration
      store.set('auth.oauth', newAuthConfig);  // Sink: store.set with sensitive data
    }
  }
}; 