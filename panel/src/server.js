const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const net = require('net');
const { execFile } = require('child_process');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';

const DATA_DIR = process.env.DATA_DIR || '/app/data';
const CLIENTS_FILE = path.join(DATA_DIR, 'clients.json');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

const STACK_DIR = process.env.STACK_DIR || '/opt/stack';
const COMPOSE_FILE = process.env.COMPOSE_FILE || path.join(STACK_DIR, 'docker-compose.yml');
const SECRETS_ENV_FILE = process.env.SECRETS_ENV_FILE || path.join(STACK_DIR, 'proxy', 'mtproxy.env');
const COMPOSE_PROJECT_NAME = process.env.COMPOSE_PROJECT_NAME || 'mtprotouipanel';
const ENABLE_DOCKER_SYNC = (process.env.ENABLE_DOCKER_SYNC || 'true') === 'true';
const PROXY_PUBLIC_HOST = (process.env.PROXY_PUBLIC_HOST || '').trim();
const PROXY_PUBLIC_PORT = Number(process.env.PROXY_PUBLIC_PORT || 3443);
const PUBLIC_IP_REFRESH_SECONDS = Number(process.env.PUBLIC_IP_REFRESH_SECONDS || 900);

const CLEANUP_INTERVAL_SECONDS = Number(process.env.CLEANUP_INTERVAL_SECONDS || 60);
const DEFAULT_FAKE_TLS_HOST = process.env.DEFAULT_FAKE_TLS_HOST || 'google.com';
const MAX_PROXY_SECRETS = Number(process.env.MAX_PROXY_SECRETS || 16);

const syncStatus = {
  inProgress: false,
  lastSyncAt: null,
  lastReason: null,
  lastSyncError: null,
};

let syncQueue = Promise.resolve();
const publicIpState = {
  value: null,
  lastUpdatedAt: null,
  lastError: null,
};

function httpsGetText(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        timeout: 5000,
        headers: {
          'User-Agent': 'mtproto-admin-panel/1.0',
        },
      },
      (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }

        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => resolve(data.trim()));
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', reject);
  });
}

function normalizeIp(value) {
  const text = (value || '').trim();
  if (net.isIP(text)) {
    return text;
  }
  return '';
}

async function detectPublicIp() {
  const endpoints = [
    async () => {
      const body = await httpsGetText('https://api.ipify.org?format=json');
      const parsed = JSON.parse(body);
      return normalizeIp(parsed.ip);
    },
    async () => {
      const body = await httpsGetText('https://ifconfig.me/ip');
      return normalizeIp(body);
    },
    async () => {
      const body = await httpsGetText('https://icanhazip.com');
      return normalizeIp(body);
    },
  ];

  for (const attempt of endpoints) {
    try {
      const ip = await attempt();
      if (ip) {
        publicIpState.value = ip;
        publicIpState.lastUpdatedAt = new Date().toISOString();
        publicIpState.lastError = null;
        return ip;
      }
    } catch {
      // continue to next provider
    }
  }

  throw new Error('Failed to detect public IP');
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) {
    return fallback;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function writeJson(filePath, value) {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function getOrCreateSessionSecret() {
  const fromEnv = (process.env.SESSION_SECRET || '').trim();
  if (fromEnv) {
    return fromEnv;
  }

  ensureDir(DATA_DIR);
  const state = readJson(STATE_FILE, {});
  if (typeof state.sessionSecret === 'string' && state.sessionSecret.length >= 32) {
    return state.sessionSecret;
  }

  state.sessionSecret = crypto.randomBytes(48).toString('hex');
  writeJson(STATE_FILE, state);
  return state.sessionSecret;
}

const SESSION_SECRET = getOrCreateSessionSecret();

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function toHexAscii(text) {
  return Buffer.from(text, 'utf8').toString('hex');
}

function normalizeSecret(secret) {
  return (secret || '').trim().toLowerCase();
}

function validateCustomSecret(secret) {
  const normalized = normalizeSecret(secret);
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error('Custom secret must be a hex string');
  }
  if (normalized.length % 2 !== 0) {
    throw new Error('Custom secret length must be even');
  }
  if (!extractProxySecretFromClientSecret(normalized)) {
    throw new Error('Custom secret must be 32 hex or ee/dd + 32 hex');
  }
  return normalized;
}

function generateSecret(secretMode, fakeTlsHost, customSecret) {
  switch (secretMode) {
    case 'plain':
      return randomHex(16);
    case 'secure':
      return `ee${randomHex(16)}`;
    case 'fake_tls': {
      const host = (fakeTlsHost || DEFAULT_FAKE_TLS_HOST).trim().toLowerCase();
      if (!host) {
        throw new Error('fake TLS host cannot be empty');
      }
      const base = randomHex(16);
      return `dd${base}${toHexAscii(host)}`;
    }
    case 'custom':
      return validateCustomSecret(customSecret);
    default:
      throw new Error('Unknown secret mode');
  }
}

function addMonths(date, months) {
  const next = new Date(date);
  next.setMonth(next.getMonth() + months);
  return next;
}

function computeExpiresAt(expiresPreset, customExpiresAt) {
  const now = new Date();

  switch (expiresPreset) {
    case '7d': {
      const d = new Date(now);
      d.setDate(d.getDate() + 7);
      return d.toISOString();
    }
    case '1m':
      return addMonths(now, 1).toISOString();
    case '3m':
      return addMonths(now, 3).toISOString();
    case '6m':
      return addMonths(now, 6).toISOString();
    case '1y': {
      const d = new Date(now);
      d.setFullYear(d.getFullYear() + 1);
      return d.toISOString();
    }
    case 'custom': {
      if (!customExpiresAt) {
        throw new Error('Custom expiration date is required');
      }
      const customDate = new Date(customExpiresAt);
      if (Number.isNaN(customDate.getTime())) {
        throw new Error('Invalid custom expiration date');
      }
      if (customDate <= now) {
        throw new Error('Custom expiration date must be in the future');
      }
      return customDate.toISOString();
    }
    case 'never':
    default:
      return null;
  }
}

function isExpired(client) {
  if (!client.expiresAt) {
    return false;
  }
  return new Date(client.expiresAt).getTime() <= Date.now();
}

function getClients() {
  return readJson(CLIENTS_FILE, []);
}

function saveClients(clients) {
  writeJson(CLIENTS_FILE, clients);
}

function getState() {
  const state = readJson(STATE_FILE, {});
  if (!state.fallbackProxySecret) {
    const migrated = extractProxySecretFromClientSecret(state.fallbackSecret || '');
    state.fallbackProxySecret = migrated || randomHex(16);
    writeJson(STATE_FILE, state);
  }
  return state;
}

function saveState(state) {
  writeJson(STATE_FILE, state);
}

function extractProxySecretFromClientSecret(secret) {
  const normalized = normalizeSecret(secret);
  if (/^[0-9a-f]{32}$/.test(normalized)) {
    return normalized;
  }

  if (/^(ee|dd)[0-9a-f]{32}/.test(normalized)) {
    return normalized.slice(2, 34);
  }

  return '';
}

function getActiveProxySecrets(clients, fallbackProxySecret) {
  const active = clients.filter((client) => !isExpired(client));
  const unique = [];
  const seen = new Set();

  for (const client of active) {
    const extracted = extractProxySecretFromClientSecret(client.secret);
    if (extracted) {
      if (!seen.has(extracted)) {
        seen.add(extracted);
        unique.push(extracted);
      }
      if (unique.length >= Math.max(1, MAX_PROXY_SECRETS)) {
        break;
      }
    }
  }

  if (unique.length === 0) {
    return [fallbackProxySecret];
  }
  return unique;
}

function dockerComposeUpMtproxy() {
  return new Promise((resolve, reject) => {
    execFile(
      'docker',
      ['compose', '-p', COMPOSE_PROJECT_NAME, '-f', COMPOSE_FILE, 'up', '-d', '--force-recreate', 'mtproxy'],
      { cwd: STACK_DIR, timeout: 120000 },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error((stderr || stdout || error.message || '').trim()));
          return;
        }
        resolve((stdout || '').trim());
      }
    );
  });
}

async function doSyncProxy(reason) {
  syncStatus.inProgress = true;
  syncStatus.lastReason = reason;

  const clients = getClients();
  const state = getState();
  const proxySecrets = getActiveProxySecrets(clients, state.fallbackProxySecret);

  ensureDir(path.dirname(SECRETS_ENV_FILE));
  const envBody = [
    '# Auto-generated by MTProto admin panel',
    '# DO NOT EDIT MANUALLY',
    `SECRET=${proxySecrets.join(',')}`,
    '',
  ].join('\n');

  fs.writeFileSync(SECRETS_ENV_FILE, envBody, 'utf8');

  if (ENABLE_DOCKER_SYNC) {
    await dockerComposeUpMtproxy();
  }

  syncStatus.lastSyncAt = new Date().toISOString();
  syncStatus.lastSyncError = null;
  syncStatus.inProgress = false;
}

function enqueueSync(reason) {
  syncQueue = syncQueue
    .catch(() => {
      // continue processing next sync requests even after previous failure
    })
    .then(() => doSyncProxy(reason))
    .catch((err) => {
      syncStatus.lastSyncError = err.message;
      syncStatus.inProgress = false;
      throw err;
    });

  return syncQueue;
}

function cleanupExpiredClients() {
  const clients = getClients();
  const active = clients.filter((client) => !isExpired(client));

  if (active.length !== clients.length) {
    saveClients(active);
    return {
      removed: clients.length - active.length,
      changed: true,
    };
  }

  return { removed: 0, changed: false };
}

function getPublicProxyEndpoint(req) {
  const hostFromRequest = normalizeIp(req.hostname) || req.hostname || '127.0.0.1';
  const host = PROXY_PUBLIC_HOST || publicIpState.value || hostFromRequest;
  const port = Number.isFinite(PROXY_PUBLIC_PORT) && PROXY_PUBLIC_PORT > 0 ? PROXY_PUBLIC_PORT : 3443;
  return { host, port };
}

function makeProxyLinks(secret, req) {
  const { host, port } = getPublicProxyEndpoint(req);
  const params = new URLSearchParams({
    server: host,
    port: String(port),
    secret: normalizeSecret(secret),
  });

  return {
    proxyLink: `https://t.me/proxy?${params.toString()}`,
    tgLink: `tg://proxy?${params.toString()}`,
  };
}

function toPublicClient(client, req) {
  const links = makeProxyLinks(client.secret, req);
  return {
    ...client,
    expired: isExpired(client),
    ...links,
  };
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/login', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.redirect('/');
    return;
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
});

app.get('/', (req, res) => {
  if (!req.session || !req.session.authenticated) {
    res.redirect('/login');
    return;
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.use('/static', express.static(path.join(__dirname, '..', 'public')));

app.post('/api/login', (req, res) => {
  const { login, password } = req.body || {};

  if (login === ADMIN_LOGIN && password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    res.json({ ok: true });
    return;
  }

  res.status(401).json({ error: 'Invalid login or password' });
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

app.get('/api/status', requireAuth, (_req, res) => {
  const clients = getClients();
  const activeClients = clients.filter((c) => !isExpired(c)).length;

  res.json({
    syncStatus,
    totalClients: clients.length,
    activeClients,
    proxySecretsFile: SECRETS_ENV_FILE,
    dockerSyncEnabled: ENABLE_DOCKER_SYNC,
    publicIp: publicIpState.value,
    publicIpLastUpdatedAt: publicIpState.lastUpdatedAt,
    publicIpLastError: publicIpState.lastError,
  });
});

app.get('/api/clients', requireAuth, (req, res) => {
  const clients = getClients()
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map((client) => toPublicClient(client, req));

  res.json({ clients });
});

app.post('/api/clients', requireAuth, async (req, res) => {
  try {
    const {
      name,
      secretMode = 'secure',
      customSecret,
      fakeTlsHost,
      expiresPreset = '1m',
      customExpiresAt,
    } = req.body || {};

    const clients = getClients();

    const client = {
      id: crypto.randomUUID(),
      name: (name || '').trim() || `client-${clients.length + 1}`,
      secretMode,
      fakeTlsHost: secretMode === 'fake_tls' ? (fakeTlsHost || DEFAULT_FAKE_TLS_HOST).trim() : null,
      secret: generateSecret(secretMode, fakeTlsHost, customSecret),
      expiresAt: computeExpiresAt(expiresPreset, customExpiresAt),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    clients.push(client);
    saveClients(clients);

    await enqueueSync('create client');

    res.status(201).json({ client: toPublicClient(client, req), syncStatus });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      secretMode,
      customSecret,
      fakeTlsHost,
      regenerateSecret,
      expiresPreset,
      customExpiresAt,
    } = req.body || {};

    const clients = getClients();
    const idx = clients.findIndex((c) => c.id === id);

    if (idx === -1) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }

    const current = clients[idx];
    const nextMode = secretMode || current.secretMode;
    const nextHost = nextMode === 'fake_tls' ? (fakeTlsHost || current.fakeTlsHost || DEFAULT_FAKE_TLS_HOST).trim() : null;

    let nextSecret = current.secret;

    if (nextMode === 'custom') {
      nextSecret = validateCustomSecret(customSecret);
    } else {
      const modeChanged = nextMode !== current.secretMode;
      const fakeTlsHostChanged = nextMode === 'fake_tls' && nextHost !== (current.fakeTlsHost || '').trim();
      const mustRegenerate = Boolean(regenerateSecret) || modeChanged || fakeTlsHostChanged;

      if (mustRegenerate) {
        nextSecret = generateSecret(nextMode, nextHost, customSecret);
      }
    }

    let nextExpiresAt = current.expiresAt;
    if (typeof expiresPreset === 'string') {
      nextExpiresAt = computeExpiresAt(expiresPreset, customExpiresAt);
    }

    const updated = {
      ...current,
      name: typeof name === 'string' ? (name.trim() || current.name) : current.name,
      secretMode: nextMode,
      fakeTlsHost: nextHost,
      secret: nextSecret,
      expiresAt: nextExpiresAt,
      updatedAt: new Date().toISOString(),
    };

    clients[idx] = updated;
    saveClients(clients);

    await enqueueSync('update client');

    res.json({ client: toPublicClient(updated, req), syncStatus });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const clients = getClients();
    const nextClients = clients.filter((c) => c.id !== id);

    if (nextClients.length === clients.length) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }

    saveClients(nextClients);
    await enqueueSync('delete client');

    res.json({ ok: true, syncStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sync', requireAuth, async (_req, res) => {
  try {
    await enqueueSync('manual sync');
    res.json({ ok: true, syncStatus });
  } catch (err) {
    res.status(500).json({ error: err.message, syncStatus });
  }
});

app.post('/api/cleanup-expired', requireAuth, async (_req, res) => {
  try {
    const { removed, changed } = cleanupExpiredClients();
    if (changed) {
      await enqueueSync('manual cleanup');
    }
    res.json({ ok: true, removed, syncStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function startupTasks() {
  ensureDir(DATA_DIR);
  ensureDir(path.dirname(SECRETS_ENV_FILE));

  if (!fs.existsSync(CLIENTS_FILE)) {
    writeJson(CLIENTS_FILE, []);
  }

  getState();

  const cleanup = cleanupExpiredClients();
  if (cleanup.changed) {
    // no-op
  }

  try {
    await detectPublicIp();
  } catch (err) {
    publicIpState.lastError = err.message;
  }

  try {
    await enqueueSync('startup');
  } catch {
    // keep app running even if docker compose is not available yet
  }

  setInterval(async () => {
    try {
      const result = cleanupExpiredClients();
      if (result.changed) {
        await enqueueSync('auto cleanup');
      }
    } catch {
      // avoid crashing on background cleanup
    }
  }, Math.max(15, CLEANUP_INTERVAL_SECONDS) * 1000);

  setInterval(async () => {
    try {
      await detectPublicIp();
    } catch (err) {
      publicIpState.lastError = err.message;
    }
  }, Math.max(60, PUBLIC_IP_REFRESH_SECONDS) * 1000);
}

startupTasks().finally(() => {
  app.listen(PORT, '0.0.0.0', () => {
    // eslint-disable-next-line no-console
    console.log(`admin panel listening on ${PORT}`);
  });
});
