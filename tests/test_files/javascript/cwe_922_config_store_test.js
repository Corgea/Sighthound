// Test file for CWE-922: Insecure Storage of Sensitive Information
// Testing configuration store patterns

// Test 1: Direct configuration object with sensitive properties (from user example)
const lastfmConfig = store.get('plugins.lastfm');
if (lastfmConfig) {
  const token = lastfmConfig.token;          // Source: sensitive property
  const session_key = lastfmConfig.session_key;  // Source: sensitive property
  const api_key = lastfmConfig.api_key;      // Source: sensitive property
  const secret = lastfmConfig.secret;        // Source: sensitive property
  
  // Vulnerable: Storing sensitive data in configuration store
  store.set('new_config.token', token);      // Sink: store.set with sensitive data
  store.set('new_config.session_key', session_key);
  store.set('new_config.api_key', api_key);
  store.set('new_config.secret', secret);
}

// Test 2: Configuration migration pattern (similar to user example)
const migrations = {
  '>=3.3.0'(store) {
    const oldConfig = store.get('plugins.lastfm');
    if (oldConfig) {
      let newConfig = store.get('plugins.scrobbler');
      
      if (!newConfig) {
        newConfig = {
          enabled: oldConfig.enabled,
        };
      }
      
      if (!newConfig.scrobblers) {
        newConfig.scrobblers = {
          lastfm: {
            token: oldConfig.token,           // Source: sensitive property
            sessionKey: oldConfig.session_key, // Source: sensitive property
            apiKey: oldConfig.api_key,        // Source: sensitive property
            secret: oldConfig.secret          // Source: sensitive property
          },
        };
      }
      
      // Vulnerable: Storing sensitive data during migration
      store.set('plugins.scrobbler', newConfig);  // Sink: store.set with sensitive data
    }
  }
};

// Test 3: Various configuration store methods
const sensitiveConfig = {
  token: 'abc123',
  session_key: 'session_abc123',
  api_key: 'api_abc123',
  secret: 'secret_abc123'
};

// Different store methods
store.set('config.auth', sensitiveConfig.token);      // Vulnerable
store.setItem('config.session', sensitiveConfig.session_key);  // Vulnerable
store.put('config.api', sensitiveConfig.api_key);     // Vulnerable
config.set('auth.secret', sensitiveConfig.secret);    // Vulnerable

// Test 4: API response to configuration store
fetch('/api/auth')
  .then(response => response.json())
  .then(data => {
    // Vulnerable: API response contains sensitive data stored in config
    store.set('auth.token', data.token);           // Source: API response, Sink: store.set
    store.set('auth.session_key', data.session_key); // Source: API response, Sink: store.set
    store.set('auth.api_key', data.api_key);       // Source: API response, Sink: store.set
    store.set('auth.secret', data.secret);         // Source: API response, Sink: store.set
  });

// Test 5: Form input to configuration store
document.getElementById('saveConfig').addEventListener('click', () => {
  const tokenInput = document.getElementById('token').value;     // Source: form input
  const apiKeyInput = document.getElementById('apiKey').value;   // Source: form input
  const secretInput = document.getElementById('secret').value;   // Source: form input
  
  // Vulnerable: Form input stored in configuration
  store.set('user.token', tokenInput);        // Sink: store.set
  store.set('user.api_key', apiKeyInput);     // Sink: store.set
  store.set('user.secret', secretInput);      // Sink: store.set
});

// Test 6: Environment variables to configuration store
const envConfig = {
  apiKey: process.env.API_KEY,    // Source: environment variable
  secret: process.env.SECRET,     // Source: environment variable
  token: process.env.TOKEN        // Source: environment variable
};

// Vulnerable: Environment variables stored in configuration
store.set('env.config', envConfig);  // Sink: store.set

// Test 7: Configuration object property access
const config = store.get('plugins.auth');
if (config) {
  const userToken = config.token;        // Source: sensitive property
  const userSecret = config.secret;      // Source: sensitive property
  
  // Vulnerable: Re-storing sensitive configuration data
  store.set('backup.token', userToken);   // Sink: store.set
  store.set('backup.secret', userSecret); // Sink: store.set
}

// Test 8: Generic object methods with sensitive data
const authManager = {
  saveCredentials(credentials) {
    // Vulnerable: Generic set method with sensitive data
    this.configStore.set('credentials.token', credentials.token);     // Source: property, Sink: set
    this.configStore.set('credentials.secret', credentials.secret);   // Source: property, Sink: set
  }
};

// Test 9: File system storage (Node.js context)
const fs = require('fs');
const sensitiveData = {
  token: 'file_token_123',
  secret: 'file_secret_123'
};

// Vulnerable: Writing sensitive data to file system
fs.writeFileSync('config.json', JSON.stringify(sensitiveData));  // Sink: fs.writeFileSync
fs.writeFile('backup.json', JSON.stringify(sensitiveData.token), (err) => {});  // Sink: fs.writeFile

// Test 10: Database storage patterns
const db = require('database');
const userCredentials = {
  token: 'db_token_123',
  secret: 'db_secret_123'
};

// Vulnerable: Database storage of sensitive data
db.save('user_config', userCredentials);           // Sink: save
db.insert('credentials', userCredentials.token);   // Sink: insert
db.create('auth_tokens', userCredentials.secret);  // Sink: create
db.update('user_auth', userCredentials);           // Sink: update 