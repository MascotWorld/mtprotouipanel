const clientsBody = document.getElementById('clientsBody');
const statusLine = document.getElementById('statusLine');
const clientForm = document.getElementById('clientForm');
const formError = document.getElementById('formError');
const formTitle = document.getElementById('formTitle');
const submitBtn = document.getElementById('submitBtn');
const cancelEditBtn = document.getElementById('cancelEditBtn');
const syncBtn = document.getElementById('syncBtn');
const cleanupBtn = document.getElementById('cleanupBtn');
const logoutBtn = document.getElementById('logoutBtn');

const secretModeNode = document.getElementById('secretMode');
const fakeTlsHostWrap = document.getElementById('fakeTlsHostWrap');
const customSecretWrap = document.getElementById('customSecretWrap');
const customDateWrap = document.getElementById('customDateWrap');
const expiresPresetNode = document.getElementById('expiresPreset');
const regenerateWrap = document.getElementById('regenerateWrap');

let clients = [];

function toLocalDatetimeInputValue(isoString) {
  if (!isoString) return '';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  const yyyy = date.getFullYear();
  const mm = pad(date.getMonth() + 1);
  const dd = pad(date.getDate());
  const hh = pad(date.getHours());
  const mi = pad(date.getMinutes());
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderSecretModeFields() {
  const mode = secretModeNode.value;

  fakeTlsHostWrap.classList.toggle('hidden', mode !== 'fake_tls');
  customSecretWrap.classList.toggle('hidden', mode !== 'custom');

  const isEdit = Boolean(clientForm.clientId.value);
  const hideRegenerate = mode === 'custom' || !isEdit;
  regenerateWrap.classList.toggle('hidden', hideRegenerate);
}

function renderExpiryFields() {
  customDateWrap.classList.toggle('hidden', expiresPresetNode.value !== 'custom');
}

function statusText(client) {
  if (client.expired) return 'Просрочен';
  if (!client.expiresAt) return 'Активен (без срока)';
  return 'Активен';
}

function prettyDate(iso) {
  if (!iso) return 'Никогда';
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return `${dt.toLocaleDateString()} ${dt.toLocaleTimeString()}`;
}

function renderClients() {
  clientsBody.innerHTML = '';

  if (clients.length === 0) {
    clientsBody.innerHTML = '<tr><td colspan="7" class="muted">Клиентов пока нет</td></tr>';
    return;
  }

  for (const client of clients) {
    const proxyLink = client.proxyLink || '';
    const linkHtml = proxyLink
      ? `<div class="proxy-link-cell"><a href="${escapeHtml(proxyLink)}" target="_blank" rel="noreferrer">t.me/proxy</a><button data-action="copy-link" data-link="${escapeHtml(proxyLink)}" class="secondary">Копировать</button></div>`
      : '<span class="muted">—</span>';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(client.name)}</td>
      <td><code>${escapeHtml(client.secret)}</code></td>
      <td>${linkHtml}</td>
      <td>${escapeHtml(client.secretMode)}</td>
      <td>${escapeHtml(prettyDate(client.expiresAt))}</td>
      <td>${escapeHtml(statusText(client))}</td>
      <td class="actions-cell">
        <button data-action="edit" data-id="${escapeHtml(client.id)}" class="secondary">Редактировать</button>
        <button data-action="delete" data-id="${escapeHtml(client.id)}" class="danger">Удалить</button>
      </td>
    `;
    clientsBody.appendChild(tr);
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (response.status === 401) {
    window.location.href = '/login';
    return null;
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }

  return data;
}

async function loadClients() {
  const data = await api('/api/clients');
  if (!data) return;
  clients = data.clients || [];
  renderClients();
}

async function loadStatus() {
  const data = await api('/api/status');
  if (!data) return;

  const sync = data.syncStatus || {};
  const parts = [
    `Всего: ${data.totalClients}`,
    `Активных: ${data.activeClients}`,
  ];

  if (sync.lastSyncAt) {
    parts.push(`Синхронизация: ${prettyDate(sync.lastSyncAt)}`);
  } else {
    parts.push('Синхронизация: пока не выполнялась');
  }

  if (sync.lastSyncError) {
    parts.push(`Ошибка: ${sync.lastSyncError}`);
  }

  if (data.publicIp) {
    parts.push(`Public IP: ${data.publicIp}`);
  } else if (data.publicIpLastError) {
    parts.push(`IP detect: ${data.publicIpLastError}`);
  }

  statusLine.textContent = parts.join(' | ');
}

function resetForm() {
  clientForm.reset();
  clientForm.clientId.value = '';
  formTitle.textContent = 'Создать клиента';
  submitBtn.textContent = 'Создать';
  cancelEditBtn.classList.add('hidden');
  formError.textContent = '';

  secretModeNode.value = 'secure';
  expiresPresetNode.value = '1m';
  renderSecretModeFields();
  renderExpiryFields();
}

function fillEditForm(client) {
  clientForm.clientId.value = client.id;
  clientForm.name.value = client.name;
  clientForm.secretMode.value = client.secretMode;
  clientForm.fakeTlsHost.value = client.fakeTlsHost || '';
  clientForm.customSecret.value = client.secret;

  if (client.expiresAt) {
    clientForm.expiresPreset.value = 'custom';
    clientForm.customExpiresAt.value = toLocalDatetimeInputValue(client.expiresAt);
  } else {
    clientForm.expiresPreset.value = 'never';
    clientForm.customExpiresAt.value = '';
  }

  clientForm.regenerateSecret.checked = false;

  formTitle.textContent = `Редактировать ${client.name}`;
  submitBtn.textContent = 'Сохранить';
  cancelEditBtn.classList.remove('hidden');
  formError.textContent = '';

  renderSecretModeFields();
  renderExpiryFields();
}

function formPayload() {
  const formData = new FormData(clientForm);

  return {
    name: (formData.get('name') || '').toString().trim(),
    secretMode: formData.get('secretMode'),
    fakeTlsHost: (formData.get('fakeTlsHost') || '').toString().trim(),
    customSecret: (formData.get('customSecret') || '').toString().trim(),
    expiresPreset: formData.get('expiresPreset'),
    customExpiresAt: formData.get('customExpiresAt') || null,
    regenerateSecret: formData.get('regenerateSecret') === 'on',
  };
}

clientForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  formError.textContent = '';

  try {
    const clientId = clientForm.clientId.value;
    const payload = formPayload();

    if (!payload.name) {
      throw new Error('Название клиента обязательно');
    }

    if (payload.secretMode === 'custom' && !payload.customSecret) {
      throw new Error('Для custom режима укажите secret');
    }

    if (payload.secretMode === 'fake_tls' && !payload.fakeTlsHost) {
      throw new Error('Для fake TLS укажите host');
    }

    if (payload.expiresPreset === 'custom' && !payload.customExpiresAt) {
      throw new Error('Укажите кастомную дату окончания');
    }

    if (clientId) {
      await api(`/api/clients/${encodeURIComponent(clientId)}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
    } else {
      await api('/api/clients', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    }

    resetForm();
    await Promise.all([loadClients(), loadStatus()]);
  } catch (err) {
    formError.textContent = err.message;
  }
});

clientsBody.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;

  const action = button.dataset.action;
  if (action === 'copy-link') {
    const link = button.dataset.link || '';
    if (!link) return;

    try {
      await navigator.clipboard.writeText(link);
      const prevText = button.textContent;
      button.textContent = 'Скопировано';
      setTimeout(() => {
        button.textContent = prevText || 'Копировать';
      }, 1200);
    } catch {
      window.prompt('Скопируйте ссылку вручную:', link);
    }
    return;
  }

  const id = button.dataset.id;
  const client = clients.find((c) => c.id === id);
  if (!client) return;

  if (action === 'edit') {
    fillEditForm(client);
    return;
  }

  if (action === 'delete') {
    const ok = window.confirm(`Удалить клиента ${client.name}?`);
    if (!ok) return;

    try {
      await api(`/api/clients/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await Promise.all([loadClients(), loadStatus()]);
    } catch (err) {
      alert(err.message);
    }
  }
});

secretModeNode.addEventListener('change', renderSecretModeFields);
expiresPresetNode.addEventListener('change', renderExpiryFields);

cancelEditBtn.addEventListener('click', () => {
  resetForm();
});

syncBtn.addEventListener('click', async () => {
  syncBtn.disabled = true;
  try {
    await api('/api/sync', { method: 'POST', body: '{}' });
    await loadStatus();
  } catch (err) {
    alert(err.message);
  } finally {
    syncBtn.disabled = false;
  }
});

cleanupBtn.addEventListener('click', async () => {
  cleanupBtn.disabled = true;
  try {
    const result = await api('/api/cleanup-expired', { method: 'POST', body: '{}' });
    await Promise.all([loadClients(), loadStatus()]);
    alert(`Удалено просроченных: ${result.removed}`);
  } catch (err) {
    alert(err.message);
  } finally {
    cleanupBtn.disabled = false;
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
  } finally {
    window.location.href = '/login';
  }
});

(async () => {
  await loadClients();
  await loadStatus();
  resetForm();
})();
