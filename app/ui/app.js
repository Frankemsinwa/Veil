/**
 * Veil — Enterprise AI Privacy Gateway
 * Cockpit Frontend Application Logic
 */
(function() {
  'use strict';

  // State Store
  const state = {
    ws: null,
    metrics: {
      total_requests: 0,
      total_redactions: 0,
      total_blocks: 0,
      is_paused: false,
      audit_count: 0
    },
    policy: 'STRICT',
    clients: [],
    activeView: 'dashboard',
    activeFilter: 'all',
    searchQuery: '',
    autostartEnabled: false,
    chartBuckets: Array.from({ length: 30 }, () => ({ clean: 0, redacted: 0, blocked: 0 })),
    eventsLog: [],
    customEntities: [],
    entityFilter: 'all',
    entitySearchQuery: '',
    vectorEntries: [],
    vectorCategoryFilter: 'ALL',
    vectorSearchQuery: '',
    vectorMode: 'single'
  };

  // DOM Elements
  const DOM = {
    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    views: document.querySelectorAll('.view'),
    navClientCount: document.getElementById('nav-client-count'),
    topbarViewTitle: document.getElementById('topbar-view-title'),
    topbarViewCrumb: document.getElementById('topbar-view-crumb'),

    // Gateway status & controls
    gatewayStatusPill: document.getElementById('gateway-status-pill'),
    statusPulseDot: document.getElementById('status-pulse-dot'),
    statusLabel: document.getElementById('status-label'),
    policySegmented: document.getElementById('policy-segmented'),
    policySelect: document.getElementById('policy-select'),
    btnToggleGateway: document.getElementById('btn-toggle-gateway'),
    toggleIcon: document.getElementById('toggle-icon'),
    toggleText: document.getElementById('toggle-text'),
    switchGatewayActive: document.getElementById('switch-gateway-active'),
    overviewHeroCard: document.getElementById('overview-hero-card'),
    activePolicyPill: document.getElementById('active-policy-pill'),

    // Sidebar status
    wsDot: document.getElementById('ws-dot'),
    wsText: document.getElementById('ws-text'),
    sidebarProxyStatus: document.getElementById('sidebar-proxy-status'),
    sidebarProxyAddr: document.getElementById('sidebar-proxy-addr'),
    btnCopyProxy: document.getElementById('btn-copy-proxy'),

    // Dashboard metrics
    statRequests: document.getElementById('stat-total-requests'),
    statRedactions: document.getElementById('stat-total-redactions'),
    statBlocks: document.getElementById('stat-total-blocks'),
    statConnectedClients: document.getElementById('stat-connected-clients'),
    displayAuditCount: document.getElementById('display-audit-count'),
    dashboardMiniFeed: document.getElementById('dashboard-mini-feed'),
    dashboardMiniClients: document.getElementById('dashboard-mini-clients'),
    btnViewAllTelemetry: document.getElementById('btn-view-all-telemetry'),
    btnViewAllClients: document.getElementById('btn-view-all-clients'),

    // Chart
    chartBarsContainer: document.getElementById('chart-bars-container'),
    chartTooltip: document.getElementById('chart-tooltip'),

    // Clients
    clientsContainer: document.getElementById('clients-container'),
    btnRescanClients: document.getElementById('btn-rescan-clients'),

    // Telemetry
    telemetryTerminal: document.getElementById('telemetry-terminal'),
    feedItems: document.getElementById('feed-items'),
    feedFilters: document.getElementById('feed-filters'),
    btnClearFeed: document.getElementById('btn-clear-feed'),
    searchTelemetry: document.getElementById('search-telemetry'),
    logCountSummary: document.getElementById('log-count-summary'),

    // Playground
    sandboxInput: document.getElementById('sandbox-input'),
    inputCharCount: document.getElementById('input-char-count'),
    btnRunSandbox: document.getElementById('btn-run-sandbox'),
    presetSecret: document.getElementById('preset-secret'),
    presetPii: document.getElementById('preset-pii'),
    presetClean: document.getElementById('preset-clean'),
    sandboxVerdictBanner: document.getElementById('sandbox-verdict-banner'),
    sandboxResultBadge: document.getElementById('sandbox-result-badge'),
    sandboxResultSub: document.getElementById('sandbox-result-sub'),
    sandboxResultMeta: document.getElementById('sandbox-result-meta'),
    sandboxResultBody: document.getElementById('sandbox-result-body'),
    sandboxFindingsContainer: document.getElementById('sandbox-findings-container'),
    sandboxViolationsList: document.getElementById('sandbox-violations-list'),

    // Settings
    autostartToggle: document.getElementById('autostart-toggle'),
    btnCopySettingsProxy: document.getElementById('btn-copy-settings-proxy'),
    toastsContainer: document.getElementById('toasts-container'),

    // Custom Entities
    navEntitiesCount: document.getElementById('nav-entities-count'),
    entityRulesList: document.getElementById('entity-rules-list'),
    entityRulesCountPill: document.getElementById('entity-rules-count-pill'),
    formAddEntity: document.getElementById('form-add-entity'),
    entityInputName: document.getElementById('entity-input-name'),
    entityInputPattern: document.getElementById('entity-input-pattern'),
    entityInputPrefix: document.getElementById('entity-input-prefix'),
    entityInputAction: document.getElementById('entity-input-action'),
    entityInputDesc: document.getElementById('entity-input-desc'),
    entityInputRegex: document.getElementById('entity-input-regex'),
    entityInputCase: document.getElementById('entity-input-case'),
    btnSaveEntity: document.getElementById('btn-save-entity'),

    // Entity Presets
    presetEntityProject: document.getElementById('preset-entity-project'),
    presetEntityClient: document.getElementById('preset-entity-client'),
    presetEntityBlocked: document.getElementById('preset-entity-blocked'),
    presetEntityNetwork: document.getElementById('preset-entity-network'),
    presetEntityAccount: document.getElementById('preset-entity-account'),

    // Entity Live Simulator
    entityLiveTestInput: document.getElementById('entity-live-test-input'),
    entityLiveTestOutput: document.getElementById('entity-live-test-output'),

    // Entity Filters & Export/Import
    searchEntityRules: document.getElementById('search-entity-rules'),
    entityFilterSegmented: document.getElementById('entity-filter-segmented'),
    btnExportEntities: document.getElementById('btn-export-entities'),
    btnImportEntities: document.getElementById('btn-import-entities'),
    inputImportEntities: document.getElementById('input-import-entities'),

    // Semantic Vector Vault
    navVectorVault: document.getElementById('nav-vector-vault'),
    navVectorsCount: document.getElementById('nav-vectors-count'),
    vectorHealthPill: document.getElementById('vector-health-pill'),
    vectorHealthDot: document.getElementById('vector-health-dot'),
    vectorHealthLabel: document.getElementById('vector-health-label'),
    statVaultCount: document.getElementById('stat-vault-count'),
    statVaultHits: document.getElementById('stat-vault-hits'),
    vectorModeSegmented: document.getElementById('vector-mode-segmented'),
    btnModeSingle: document.getElementById('btn-mode-single'),
    btnModeDocument: document.getElementById('btn-mode-document'),
    vectorDocOptions: document.getElementById('vector-doc-options'),
    vectorDocWindow: document.getElementById('vector-doc-window'),
    vectorDocStride: document.getElementById('vector-doc-stride'),
    presetVecMa: document.getElementById('preset-vec-ma'),
    presetVecFinancial: document.getElementById('preset-vec-financial'),
    presetVecInfra: document.getElementById('preset-vec-infra'),
    presetVecHr: document.getElementById('preset-vec-hr'),
    formAddVector: document.getElementById('form-add-vector'),
    vectorInputTitle: document.getElementById('vector-input-title'),
    vectorInputCategory: document.getElementById('vector-input-category'),
    vectorInputAction: document.getElementById('vector-input-action'),
    vectorInputThreshold: document.getElementById('vector-input-threshold'),
    vectorThresholdBadge: document.getElementById('vector-threshold-badge'),
    vectorInputText: document.getElementById('vector-input-text'),
    vectorTextCharCount: document.getElementById('vector-text-char-count'),
    btnSaveVector: document.getElementById('btn-save-vector'),
    btnSaveVectorText: document.getElementById('btn-save-vector-text'),
    vectorLiveTestInput: document.getElementById('vector-live-test-input'),
    btnTestVectorSim: document.getElementById('btn-test-vector-sim'),
    vectorLiveTestOutput: document.getElementById('vector-live-test-output'),
    vectorTestVerdictPill: document.getElementById('vector-test-verdict-pill'),
    vectorTestLatencyText: document.getElementById('vector-test-latency-text'),
    vectorTestGaugeBar: document.getElementById('vector-test-gauge-bar'),
    vectorTestDetails: document.getElementById('vector-test-details'),
    vectorCategorySegmented: document.getElementById('vector-category-segmented'),
    searchVectorRules: document.getElementById('search-vector-rules'),
    vectorRulesCountPill: document.getElementById('vector-rules-count-pill'),
    vectorRulesList: document.getElementById('vector-rules-list')
  };

  // Official Brand Logos for AI Clients & Upstream Providers
  const CLIENT_LOGOS = {
    antigravity: '/static/assets/logos/antigravity.png',
    cursor: '/static/assets/logos/cursor.png',
    continue: '/static/assets/logos/continue.png',
    claude_code: '/static/assets/logos/claude_code.png',
    aider: '/static/assets/logos/aider.png',
    system_env: '/static/assets/logos/system_env.png',
    opencode: '/static/assets/logos/opencode.png'
  };

  const PROVIDER_LOGOS = {
    openai: '/static/assets/logos/openai.png',
    anthropic: '/static/assets/logos/anthropic.png',
    ollama: '/static/assets/logos/ollama.png'
  };

  // SVGs for AI Clients (Fallback)
  const CLIENT_ICONS = {
    antigravity: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 22h20L12 2z"></path><circle cx="12" cy="14" r="3"></circle></svg>`,
    cursor: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4l7 17 2.5-6.5L20 12 4 4z"></path></svg>`,
    continue: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    claude_code: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v10M7 12h10"></path></svg>`,
    aider: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"></rect><line x1="8" y1="20" x2="16" y2="20"></line><line x1="12" y1="16" x2="12" y2="20"></line></svg>`,
    system_env: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"></rect><rect x="14" y="3" width="7" height="7" rx="1"></rect><rect x="3" y="14" width="7" height="7" rx="1"></rect><rect x="14" y="14" width="7" height="7" rx="1"></rect></svg>`,
    opencode: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 18l6-6-6-6"></path><path d="M8 6l-6 6 6 6"></path><circle cx="12" cy="12" r="2"></circle></svg>`,
    default: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg>`
  };

  // View metadata configuration
  const VIEW_META = {
    dashboard: {
      title: 'System Overview',
      crumb: 'Local In-Memory Isolation • Zero Cloud Retention'
    },
    clients: {
      title: 'AI Client Environments',
      crumb: 'Autonomous Zero-Corruption Configuration • 1-Click Rollback'
    },
    telemetry: {
      title: 'Live Telemetry & Ledger',
      crumb: 'Real-Time Event Stream • Cryptographic Inspection Receipts'
    },
    playground: {
      title: 'Inspection Sandbox',
      crumb: 'Heuristic & Regex Privacy Simulation Engine'
    },
    entities: {
      title: 'Enterprise Entity Dictionary & Blacklist',
      crumb: 'Custom Codenames, Client Lists & Regex Privacy Rules'
    },
    'vector-vault': {
      title: 'Semantic Guardrails & Knowledge Vault',
      crumb: 'On-Device Quantized ONNX Vector Defense • Zero Cloud Egress'
    },
    billing: {
      title: 'Commercial Plans & Licensing',
      crumb: '3-Tier Protection Matrix • Paystack International Payment Gateway'
    },
    settings: {
      title: 'System Settings',
      crumb: 'Host Integration & Port Management'
    }
  };

  /**
   * App Initialization
   */
  function init() {
    setupNavigation();
    setupEventListeners();
    setupShortcuts();
    renderChart();
    connectWebSocket();
    fetchClients();
    renderProviders();
    fetchMetrics();
    fetchAutostart();
    fetchVectorEntries();
    setupVectorVaultController();
    fetchCustomEntities();
    setupEntityForm();
    setupEntityPresets();
    setupEntitySimulator();
    setupEntityFiltersAndExport();
    setupBillingController();

    // Dynamically advance rolling 1-minute throughput window
    setInterval(() => {
      if (state.chartBuckets && state.chartBuckets.length > 0) {
        state.chartBuckets.shift();
        state.chartBuckets.push({ clean: 0, redacted: 0, blocked: 0 });
        renderChart();
      }
    }, 60000);

    // Heartbeat metrics sync
    setInterval(fetchMetrics, 10000);
  }

  /**
   * View Navigation
   */
  function setupNavigation() {
    DOM.navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const viewId = item.dataset.view;
        switchView(viewId);
      });
    });

    if (DOM.btnViewAllTelemetry) {
      DOM.btnViewAllTelemetry.addEventListener('click', () => switchView('telemetry'));
    }
    if (DOM.btnViewAllClients) {
      DOM.btnViewAllClients.addEventListener('click', () => switchView('clients'));
    }
  }

  function switchView(viewId) {
    if (!viewId) return;
    state.activeView = viewId;

    DOM.navItems.forEach(nav => {
      if (nav.dataset.view === viewId) {
        nav.classList.add('active');
      } else {
        nav.classList.remove('active');
      }
    });

    DOM.views.forEach(v => {
      if (v.id === `view-${viewId}`) {
        v.classList.add('active');
      } else {
        v.classList.remove('active');
      }
    });

    const meta = VIEW_META[viewId] || { title: 'Veil Gateway', crumb: '' };
    DOM.topbarViewTitle.textContent = meta.title;
    DOM.topbarViewCrumb.textContent = meta.crumb;
  }

  /**
   * UI Event Listeners
   */
  function setupEventListeners() {
    // Gateway pause/resume toggles
    DOM.btnToggleGateway.addEventListener('click', toggleGatewayState);
    if (DOM.switchGatewayActive) {
      DOM.switchGatewayActive.addEventListener('click', toggleGatewayState);
    }

    // Policy segmented buttons
    DOM.policySegmented.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        const policy = btn.dataset.policy;
        setPolicy(policy);
      });
    });

    // Copy proxy address
    if (DOM.btnCopyProxy) {
      DOM.btnCopyProxy.addEventListener('click', () => copyToClipboard('http://127.0.0.1:8080/v1', 'Proxy URL copied!'));
    }
    if (DOM.btnCopySettingsProxy) {
      DOM.btnCopySettingsProxy.addEventListener('click', () => copyToClipboard('http://127.0.0.1:8080/v1', 'Proxy URL copied!'));
    }

    // Rescan clients button
    DOM.btnRescanClients.addEventListener('click', () => {
      DOM.btnRescanClients.classList.add('is-loading');
      fetchClients().finally(() => {
        setTimeout(() => DOM.btnRescanClients.classList.remove('is-loading'), 350);
      });
    });

    // Telemetry filters
    DOM.feedFilters.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        DOM.feedFilters.querySelectorAll('button').forEach(b => {
          b.classList.remove('active');
          b.setAttribute('aria-pressed', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-pressed', 'true');
        state.activeFilter = btn.dataset.filter;
        applyFeedFilters();
      });
    });

    // Telemetry clear
    DOM.btnClearFeed.addEventListener('click', () => {
      state.eventsLog = [];
      DOM.feedItems.innerHTML = `
        <div class="empty" id="feed-empty-state">
          <span class="icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
            </svg>
          </span>
          <div class="empty-title">Telemetry Buffer Cleared</div>
          <div class="empty-desc">New outbound requests will stream here live.</div>
        </div>
      `;
      DOM.logCountSummary.textContent = '0 events recorded';
      showToast('Telemetry stream cleared', 'info');
    });

    // Telemetry search input
    DOM.searchTelemetry.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.toLowerCase().trim();
      applyFeedFilters();
    });

    // Playground presets
    DOM.presetSecret.addEventListener('click', () => {
      DOM.sandboxInput.value = 'Deploy to AWS: AccessKey=AKIAIOSFODNN7EXAMPLE Secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in region us-east-1';
      updateInputCharCount();
    });
    DOM.presetPii.addEventListener('click', () => {
      DOM.sandboxInput.value = 'Customer support escalation for Alice Walker (email: alice.walker@enterprise.io, phone: 415-555-0199).';
      updateInputCharCount();
    });
    DOM.presetClean.addEventListener('click', () => {
      DOM.sandboxInput.value = 'def quicksort(arr):\n    if len(arr) <= 1: return arr\n    pivot = arr[len(arr) // 2]\n    return quicksort([x for x in arr if x < pivot]) + [x for x in arr if x == pivot] + quicksort([x for x in arr if x > pivot])';
      updateInputCharCount();
    });

    DOM.sandboxInput.addEventListener('input', updateInputCharCount);
    DOM.btnRunSandbox.addEventListener('click', executeSandboxInspection);

    // Autostart switch
    if (DOM.autostartToggle) {
      DOM.autostartToggle.addEventListener('click', toggleAutostart);
    }
  }

  function updateInputCharCount() {
    const len = DOM.sandboxInput.value.length;
    DOM.inputCharCount.textContent = `${len} char${len === 1 ? '' : 's'}`;
  }

  /**
   * Keyboard shortcuts
   */
  function setupShortcuts() {
    window.addEventListener('keydown', (e) => {
      // Don't intercept when focusing text inputs
      if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && document.activeElement === DOM.sandboxInput) {
          e.preventDefault();
          executeSandboxInspection();
        }
        return;
      }

      if (e.key === '1') switchView('dashboard');
      if (e.key === '2') switchView('clients');
      if (e.key === '3') switchView('telemetry');
      if (e.key === '4') switchView('playground');
      if (e.key === '5') switchView('entities');
      if (e.key === '6') switchView('vector-vault');
      if (e.key === '7') switchView('settings');
    });
  }

  /**
   * Gateway Toggle & Policy Controls
   */
  async function toggleGatewayState() {
    try {
      const res = await fetch('/api/gateway/toggle', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        state.metrics.is_paused = data.is_paused;
        updateGatewayUI();
        showToast(data.is_paused ? 'Gateway Paused (Bypass Mode)' : 'Gateway Resumed (Interception Active)', data.is_paused ? 'bad' : 'ok');
      }
    } catch (err) {
      console.error('Error toggling gateway:', err);
    }
  }

  function updateGatewayUI() {
    const paused = state.metrics.is_paused;

    if (paused) {
      // Topbar status badge
      DOM.gatewayStatusPill.className = 'pill warn';
      DOM.statusPulseDot.className = 'dot warn';
      DOM.statusLabel.textContent = 'GATEWAY PAUSED';

      // Button state
      DOM.btnToggleGateway.className = 'btn btn-sm btn-primary';
      DOM.toggleIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>`;
      DOM.toggleText.textContent = 'Resume Gateway';

      // Sidebar summary
      DOM.sidebarProxyStatus.className = 'pill warn';
      DOM.sidebarProxyStatus.innerHTML = '<span class="dot warn"></span><span>PAUSED</span>';

      // Hero panel
      DOM.overviewHeroCard.classList.add('paused');
      if (DOM.switchGatewayActive) {
        DOM.switchGatewayActive.setAttribute('aria-checked', 'false');
      }
    } else {
      // Topbar status badge
      DOM.gatewayStatusPill.className = 'pill ok';
      DOM.statusPulseDot.className = 'dot ok live';
      DOM.statusLabel.textContent = 'GATEWAY ACTIVE';

      // Button state
      DOM.btnToggleGateway.className = 'btn btn-sm';
      DOM.toggleIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect></svg>`;
      DOM.toggleText.textContent = 'Pause Gateway';

      // Sidebar summary
      DOM.sidebarProxyStatus.className = 'pill ok';
      DOM.sidebarProxyStatus.innerHTML = '<span class="dot ok live"></span><span>ACTIVE</span>';

      // Hero panel
      DOM.overviewHeroCard.classList.remove('paused');
      if (DOM.switchGatewayActive) {
        DOM.switchGatewayActive.setAttribute('aria-checked', 'true');
      }
    }
  }

  async function setPolicy(policy) {
    try {
      const res = await fetch('/api/gateway/policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy: policy })
      });
      if (res.ok) {
        const data = await res.json();
        state.policy = data.policy;
        updatePolicyUI();
        showToast(`Policy Tier: ${data.policy}`, 'ok');
      }
    } catch (err) {
      console.error('Error changing policy:', err);
    }
  }

  function updatePolicyUI() {
    DOM.policySegmented.querySelectorAll('button').forEach(btn => {
      const isSelected = btn.dataset.policy === state.policy;
      btn.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });

    if (DOM.activePolicyPill) {
      DOM.activePolicyPill.textContent = state.policy;
      DOM.activePolicyPill.className = state.policy === 'STRICT' ? 'pill bad' : (state.policy === 'BALANCED' ? 'pill warn' : 'pill info');
    }
    if (DOM.policySelect) {
      DOM.policySelect.value = state.policy;
    }
  }

  /**
   * WebSocket Real-Time Telemetry Stream
   */
  function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    try {
      state.ws = new WebSocket(wsUrl);

      state.ws.onopen = () => {
        DOM.wsDot.className = 'dot ok live';
        DOM.wsText.textContent = 'Live Connected';
      };

      state.ws.onclose = () => {
        DOM.wsDot.className = 'dot warn';
        DOM.wsText.textContent = 'Reconnecting...';
        setTimeout(connectWebSocket, 3000);
      };

      state.ws.onerror = () => {
        DOM.wsDot.className = 'dot bad';
        DOM.wsText.textContent = 'Disconnected';
      };

      state.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          handleWebSocketPayload(payload);
        } catch (e) {
          console.error('WS parse error:', e);
        }
      };
    } catch (e) {
      console.error('WebSocket connection error:', e);
    }
  }

  function handleWebSocketPayload(payload) {
    if (payload.type === 'init') {
      const initData = payload.data || {};
      state.policy = initData.policy || 'STRICT';
      state.metrics.is_paused = !!initData.is_paused;
      if (initData.metrics) {
        state.metrics = { ...state.metrics, ...initData.metrics };
      }
      updateGatewayUI();
      updatePolicyUI();
      updateMetricsDisplay();

      if (initData.clients) {
        state.clients = initData.clients;
        renderClientCards(state.clients);
      }

      if (initData.history && Array.isArray(initData.history)) {
        initData.history.forEach(ev => appendTelemetryEvent(ev, false));
      }
      return;
    }

    // Live Event Dispatch
    const evType = payload.type || payload.event_type;
    const data = payload.data || payload;

    if (evType === 'redaction') {
      state.metrics.total_requests++;
      state.metrics.total_redactions += (data.redaction_count || 1);
      pushChartEvent('redacted');
      appendTelemetryEvent({ type: 'redaction', timestamp: Date.now() / 1000, data });
    } else if (evType === 'blocked') {
      state.metrics.total_requests++;
      state.metrics.total_blocks++;
      pushChartEvent('blocked');
      appendTelemetryEvent({ type: 'blocked', timestamp: Date.now() / 1000, data });
    } else if (evType === 'clean_pass') {
      state.metrics.total_requests++;
      pushChartEvent('clean');
      appendTelemetryEvent({ type: 'clean_pass', timestamp: Date.now() / 1000, data });
    } else if (evType === 'client_status') {
      appendTelemetryEvent({ type: 'client_status', timestamp: Date.now() / 1000, data });
      fetchClients();
    } else if (evType === 'metric') {
      if (data.is_paused !== undefined) {
        state.metrics.is_paused = data.is_paused;
        updateGatewayUI();
      }
      if (data.policy) {
        state.policy = data.policy;
        updatePolicyUI();
      }
    }

    updateMetricsDisplay();
  }

  /**
   * Metrics Fetch & Display
   */
  async function fetchMetrics() {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        if (data.metrics) {
          state.metrics = { ...state.metrics, ...data.metrics };
        }
        if (data.policy) state.policy = data.policy;
        if (data.audit_count !== undefined) state.metrics.audit_count = data.audit_count;
        if (data.recent_buckets && Array.isArray(data.recent_buckets) && data.recent_buckets.length === 30) {
          state.chartBuckets = data.recent_buckets;
          renderChart();
        }
        if (data.recent_events && Array.isArray(data.recent_events) && data.recent_events.length > 0) {
          data.recent_events.slice().reverse().forEach(ev => {
            updateDashboardMiniFeed(ev);
          });
        }
        updateMetricsDisplay();
        updateGatewayUI();
        updatePolicyUI();
      }
    } catch (e) {
      console.error('Fetch metrics error:', e);
    }
  }

  function updateMetricsDisplay() {
    DOM.statRequests.textContent = formatNumber(state.metrics.total_requests || 0);
    DOM.statRedactions.textContent = formatNumber(state.metrics.total_redactions || 0);
    DOM.statBlocks.textContent = formatNumber(state.metrics.total_blocks || 0);

    const connectedCount = state.clients.filter(c => c.status === 'CONNECTED').length;
    DOM.statConnectedClients.textContent = connectedCount;
    DOM.navClientCount.textContent = `${connectedCount}/${state.clients.length || 7}`;

    if (DOM.displayAuditCount) {
      DOM.displayAuditCount.textContent = `${formatNumber(state.metrics.total_requests || 0)} cryptographically sealed`;
    }
  }

  /**
   * AI Clients Rendering & Actions
   */
  async function fetchClients() {
    try {
      const res = await fetch('/api/clients');
      if (res.ok) {
        const data = await res.json();
        state.clients = Array.isArray(data) ? data : (data.clients || []);
        renderClientCards(state.clients);
        updateMetricsDisplay();
      }
    } catch (err) {
      console.error('Error fetching clients:', err);
      DOM.clientsContainer.innerHTML = `
        <div class="empty">
          <div class="empty-title" style="color: var(--rose);">Client Discovery Error</div>
          <div class="empty-desc">Failed to reach the local client management API.</div>
        </div>
      `;
    }
  }

  /**
   * Renders the client cards into DOM.
   * Kept named `renderClientCards` as verified by test_ui.py
   */
  function renderClientCards(clients) {
    if (!clients || clients.length === 0) {
      DOM.clientsContainer.innerHTML = `
        <div class="empty">
          <div class="empty-title">No AI Clients Detected</div>
          <div class="empty-desc">Install an AI code editor or configure environment variables.</div>
        </div>
      `;
      return;
    }

    let html = '';
    const installed = clients.filter(c => c.status === 'CONNECTED' || c.status === 'DETECTED');
    const notInstalled = clients.filter(c => c.status !== 'CONNECTED' && c.status !== 'DETECTED');

    if (installed.length > 0) {
      html += `<div class="client-group-label"><span>INSTALLED & CONFIGURED</span><span>${installed.length} DETECTED</span></div>`;
      installed.forEach(c => { html += buildClientRowHtml(c); });
    }

    if (notInstalled.length > 0) {
      html += `<div class="client-group-label"><span>AVAILABLE CLIENTS (NOT DETECTED)</span><span>${notInstalled.length}</span></div>`;
      notInstalled.forEach(c => { html += buildClientRowHtml(c); });
    }

    DOM.clientsContainer.innerHTML = html;
    attachClientRowActions();
    renderMiniDashboardClients(clients);
  }

  function buildClientRowHtml(client) {
    const isConnected = client.status === 'CONNECTED';
    const isDetected = client.status === 'DETECTED';
    const isError = client.status === 'ERROR';
    const isMissing = client.status === 'NOT_INSTALLED';

    let badge = '';
    let actionBtn = '';

    if (isConnected) {
      badge = `<span class="pill ok"><span class="dot ok live"></span>CONNECTED</span>`;
      actionBtn = `
        <button class="btn btn-sm btn-danger btn-client-disconnect" data-id="${escapeHtml(client.id)}">
          <span class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></span>
          <span>Disconnect</span>
        </button>
      `;
    } else if (isDetected) {
      badge = `<span class="pill warn"><span class="dot warn"></span>DETECTED</span>`;
      actionBtn = `
        <button class="btn btn-sm btn-primary btn-client-connect" data-id="${escapeHtml(client.id)}">
          <span class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Connect</span>
        </button>
      `;
    } else if (isError) {
      badge = `<span class="pill bad"><span class="dot bad"></span>ERROR</span>`;
      actionBtn = `<button class="btn btn-sm" disabled>Invalid Config</button>`;
    } else {
      badge = `<span class="pill"><span class="dot"></span>NOT INSTALLED</span>`;
      actionBtn = `<button class="btn btn-sm" disabled>Not Found</button>`;
    }

    const logoSrc = CLIENT_LOGOS[client.id];
    const logoMarkup = logoSrc
      ? `<img src="${logoSrc}" alt="${escapeHtml(client.name)}" class="client-brand-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';"><span class="icon" style="display: none;">${CLIENT_ICONS[client.id] || CLIENT_ICONS.default}</span>`
      : (CLIENT_ICONS[client.id] || CLIENT_ICONS.default);
    const pathText = client.config_path || 'Managed via System Environment';

    return `
      <div class="client-row ${isMissing ? 'is-missing' : ''}" data-id="${escapeHtml(client.id)}">
        <div class="client-logo">
          ${logoMarkup}
        </div>
        <div>
          <div class="client-name">
            <span>${escapeHtml(client.name)}</span>
            ${badge}
          </div>
          <div class="client-desc">${escapeHtml(client.description)}</div>
          <div class="client-path btn-copy-path" data-path="${escapeHtml(pathText)}" title="Click to copy configuration path">
            <span>${escapeHtml(pathText)}</span>
            <span class="icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </span>
          </div>
        </div>
        <div class="client-actions">
          ${actionBtn}
        </div>
      </div>
    `;
  }

  function attachClientRowActions() {
    // Connect Buttons
    DOM.clientsContainer.querySelectorAll('.btn-client-connect').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = btn.dataset.id;
        btn.classList.add('is-loading');
        try {
          const res = await fetch(`/api/clients/${id}/connect`, { method: 'POST' });
          const data = await res.json();
          if (data.success) {
            showToast(`Connected ${id} to Veil gateway!`, 'ok');
          } else {
            showToast(`Connection failed: ${data.message}`, 'bad');
          }
        } catch (err) {
          showToast(`Network error connecting ${id}`, 'bad');
        } finally {
          btn.classList.remove('is-loading');
          fetchClients();
        }
      });
    });

    // Disconnect Buttons
    DOM.clientsContainer.querySelectorAll('.btn-client-disconnect').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = btn.dataset.id;
        btn.classList.add('is-loading');
        try {
          const res = await fetch(`/api/clients/${id}/disconnect`, { method: 'POST' });
          const data = await res.json();
          if (data.success) {
            showToast(`Disconnected ${id}. Configuration restored from backup.`, 'ok');
          } else {
            showToast(`Disconnect failed: ${data.message}`, 'bad');
          }
        } catch (err) {
          showToast(`Network error disconnecting ${id}`, 'bad');
        } finally {
          btn.classList.remove('is-loading');
          fetchClients();
        }
      });
    });

    // Copy Path click
    DOM.clientsContainer.querySelectorAll('.btn-copy-path').forEach(el => {
      el.addEventListener('click', () => {
        const path = el.dataset.path;
        if (path) copyToClipboard(path, 'Configuration path copied!');
      });
    });
  }

  function renderMiniDashboardClients(clients) {
    if (!DOM.dashboardMiniClients) return;
    let html = '';
    const sorted = [...clients].sort((a, b) => {
      const score = (s) => (s === 'CONNECTED' ? 3 : s === 'DETECTED' ? 2 : 1);
      return score(b.status) - score(a.status);
    });

    sorted.slice(0, 4).forEach(c => {
      const isConnected = c.status === 'CONNECTED';
      const isDetected = c.status === 'DETECTED';
      const statusPill = isConnected
        ? `<span class="pill ok"><span class="dot ok live"></span>Connected</span>`
        : (isDetected ? `<span class="pill warn">Detected</span>` : `<span class="pill">Inactive</span>`);

      const logoSrc = CLIENT_LOGOS[c.id];
      const iconMarkup = logoSrc
        ? `<img src="${logoSrc}" alt="${escapeHtml(c.name)}" class="client-mini-img">`
        : (CLIENT_ICONS[c.id] || CLIENT_ICONS.default);

      html += `
        <li>
          <span class="ev-icon client-brand ${isConnected ? 'ok' : ''}">
            ${iconMarkup}
          </span>
          <span class="name">${escapeHtml(c.name)}</span>
          ${statusPill}
        </li>
      `;
    });
    DOM.dashboardMiniClients.innerHTML = html;
  }

  function renderProviders() {
    const container = document.getElementById('providers-container');
    if (!container) return;

    const providers = [
      {
        id: 'openai',
        name: 'OpenAI (GPT-4o, o1, Text Embeddings)',
        description: 'Target: https://api.openai.com/v1 • Primary upstream foundation model API',
        url: 'https://api.openai.com/v1',
        status: 'ACTIVE'
      },
      {
        id: 'anthropic',
        name: 'Anthropic (Claude 3.5 Sonnet / Opus)',
        description: 'Target: https://api.anthropic.com/v1 • High-reasoning enterprise agent API',
        url: 'https://api.anthropic.com/v1',
        status: 'ACTIVE'
      },
      {
        id: 'ollama',
        name: 'Ollama (Local Models: Llama 3, Qwen, DeepSeek)',
        description: 'Target: http://127.0.0.1:11434 • Zero-egress local offline runtime',
        url: 'http://127.0.0.1:11434',
        status: 'LOCAL'
      }
    ];

    container.innerHTML = providers.map(p => {
      const isLocal = p.status === 'LOCAL';
      const badge = `<span class="pill ${isLocal ? 'info' : 'ok'}"><span class="dot ${isLocal ? 'info' : 'ok live'}"></span>${p.status}</span>`;
      return `
        <div class="client-row" data-id="${p.id}">
          <div class="client-logo">
            <img src="${PROVIDER_LOGOS[p.id]}" alt="${p.name}" class="client-brand-img">
          </div>
          <div>
            <div class="client-name">
              <span>${escapeHtml(p.name)}</span>
              ${badge}
            </div>
            <div class="client-desc">${escapeHtml(p.description)}</div>
            <div class="client-path btn-copy-path" data-path="${escapeHtml(p.url)}" title="Click to copy endpoint URL">
              <span>${escapeHtml(p.url)}</span>
              <span class="icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </span>
            </div>
          </div>
          <div class="client-actions">
            <span class="pill muted" style="font-size: 11px;">AUTO-ROUTED</span>
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('.btn-copy-path').forEach(el => {
      el.addEventListener('click', () => {
        const path = el.dataset.path;
        if (path) copyToClipboard(path, 'Endpoint URL copied!');
      });
    });
  }

  /**
   * Telemetry Feed & Table
   */
  function appendTelemetryEvent(event, prepend = true) {
    state.eventsLog.push(event);
    if (state.eventsLog.length > 200) {
      state.eventsLog.shift();
    }

    const rowHtml = buildTelemetryRowHtml(event);

    const empty = document.getElementById('feed-empty-state');
    if (empty) empty.remove();

    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = rowHtml.trim();
    const rowEl = tempDiv.firstElementChild;

    // Attach expandable click
    rowEl.addEventListener('click', () => {
      rowEl.classList.toggle('open');
    });

    if (prepend && DOM.feedItems.firstChild) {
      DOM.feedItems.insertBefore(rowEl, DOM.feedItems.firstChild);
    } else {
      DOM.feedItems.appendChild(rowEl);
    }

    DOM.logCountSummary.textContent = `${state.eventsLog.length} event${state.eventsLog.length === 1 ? '' : 's'} recorded`;

    // Also update Dashboard mini feed
    updateDashboardMiniFeed(event);
  }

  function buildTelemetryRowHtml(ev) {
    const date = new Date((ev.timestamp || Date.now() / 1000) * 1000);
    const timeStr = date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const data = ev.data || {};

    let badge = '';
    let details = '';
    let category = 'other';
    const model = data.model || 'direct';
    const latency = data.latency_ms !== undefined ? `${data.latency_ms.toFixed(1)}ms` : '--';

    if (ev.type === 'redaction') {
      category = 'redaction';
      badge = `<span class="pill ok"><span class="dot ok"></span>REDACTED</span>`;
      details = `Sanitized <b>${data.redaction_count || 1} sensitive tokens</b> from prompt`;
    } else if (ev.type === 'blocked') {
      category = 'blocked';
      badge = `<span class="pill bad"><span class="dot bad"></span>BLOCKED</span>`;
      const viols = (data.violations || []).map(v => `<span class="tag">${escapeHtml(v)}</span>`).join('');
      details = `Blocked leak: ${data.reason || 'Credentials'} ${viols}`;
    } else if (ev.type === 'clean_pass') {
      category = 'clean';
      badge = `<span class="pill"><span class="dot"></span>CLEAN</span>`;
      details = `Prompt verified safe; forwarded directly`;
    } else if (ev.type === 'client_status') {
      category = 'client';
      badge = `<span class="pill info"><span class="dot"></span>CLIENT</span>`;
      details = `Client ${data.client_id} status updated to <b>${data.status}</b>`;
    } else {
      badge = `<span class="pill">${escapeHtml(ev.type || 'EVENT')}</span>`;
      details = JSON.stringify(data);
    }

    return `
      <div class="log-row is-new" data-category="${category}" data-search="${escapeHtml((details + ' ' + model).toLowerCase())}">
        <div class="t">${timeStr}</div>
        <div>${badge}</div>
        <div class="msg">${details}</div>
        <div class="model">${escapeHtml(model)}</div>
        <div class="lat r">${latency}</div>
        <div class="log-detail">
          <pre>${escapeHtml(JSON.stringify(ev, null, 2))}</pre>
        </div>
      </div>
    `;
  }

  function applyFeedFilters() {
    const rows = DOM.feedItems.querySelectorAll('.log-row');
    rows.forEach(row => {
      const cat = row.dataset.category;
      const search = row.dataset.search || '';

      const matchesFilter = state.activeFilter === 'all' || cat === state.activeFilter;
      const matchesSearch = !state.searchQuery || search.includes(state.searchQuery);

      if (matchesFilter && matchesSearch) {
        row.style.display = 'grid';
      } else {
        row.style.display = 'none';
      }
    });
  }

  function updateDashboardMiniFeed(ev) {
    if (!DOM.dashboardMiniFeed) return;
    const placeholder = DOM.dashboardMiniFeed.querySelector('.empty-feed-placeholder');
    if (placeholder) placeholder.remove();

    const data = ev.data || {};
    const date = new Date((ev.timestamp || Date.now() / 1000) * 1000);
    const timeStr = date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });

    let iconClass = 'system';
    let title = 'Gateway Event';
    let sub = '';

    if (ev.type === 'redaction') {
      iconClass = 'redaction';
      title = `Prompt Sanitized (${data.redaction_count || 1} tokens)`;
      sub = `Replaced with reversible session placeholders`;
    } else if (ev.type === 'blocked') {
      iconClass = 'blocked';
      title = `Exfiltration Blocked`;
      sub = data.reason || 'Prohibited credential patterns detected';
    } else if (ev.type === 'clean_pass') {
      iconClass = 'clean';
      title = `Prompt Forwarded (Clean)`;
      sub = data.reason || 'Verified safe • Zero sensitive entities detected';
    } else if (ev.type === 'client_status') {
      iconClass = 'client';
      title = `Client ${data.client_id}`;
      sub = `Status updated to ${data.status}`;
    }

    const dotClass = iconClass === 'redaction' ? 'ok' : (iconClass === 'blocked' ? 'bad' : (iconClass === 'clean' ? '' : 'warn'));

    const li = document.createElement('li');
    li.innerHTML = `
      <span class="ev-icon ${iconClass}">
        <span class="dot ${dotClass}"></span>
      </span>
      <div>
        <div class="ev-title">${escapeHtml(title)}</div>
        <div class="ev-sub">${escapeHtml(sub)}</div>
      </div>
      <span class="ev-time">${timeStr}</span>
    `;

    DOM.dashboardMiniFeed.insertBefore(li, DOM.dashboardMiniFeed.firstChild);
    if (DOM.dashboardMiniFeed.children.length > 5) {
      DOM.dashboardMiniFeed.removeChild(DOM.dashboardMiniFeed.lastChild);
    }
  }

  /**
   * Interactive Throughput Chart
   */
  function pushChartEvent(kind) {
    const lastBucket = state.chartBuckets[state.chartBuckets.length - 1];
    if (kind === 'redacted') lastBucket.redacted++;
    else if (kind === 'blocked') lastBucket.blocked++;
    else lastBucket.clean++;
    renderChart();
  }

  function renderChart() {
    if (!DOM.chartBarsContainer) return;
    DOM.chartBarsContainer.innerHTML = '';

    const maxTotal = Math.max(
      1,
      ...state.chartBuckets.map(b => b.clean + b.redacted + b.blocked)
    );

    state.chartBuckets.forEach((bucket, idx) => {
      const total = bucket.clean + bucket.redacted + bucket.blocked;
      const isNow = idx === state.chartBuckets.length - 1;
      const bar = document.createElement('div');
      bar.className = `chart-bar ${total === 0 ? 'empty' : ''} ${isNow ? 'is-current' : ''}`;

      if (total > 0) {
        const hClean = (bucket.clean / maxTotal) * 100;
        const hRedacted = (bucket.redacted / maxTotal) * 100;
        const hBlocked = (bucket.blocked / maxTotal) * 100;

        bar.innerHTML = `
          ${hBlocked > 0 ? `<div class="seg blocked" style="height: ${hBlocked}%"></div>` : ''}
          ${hRedacted > 0 ? `<div class="seg redacted" style="height: ${hRedacted}%"></div>` : ''}
          ${hClean > 0 ? `<div class="seg clean" style="height: ${hClean}%"></div>` : ''}
        `;
      }

      // Tooltip hover
      bar.addEventListener('mouseenter', (e) => {
        const timeLabel = isNow ? 'Current Minute (Now)' : `${30 - idx}m ago`;
        DOM.chartTooltip.innerHTML = `
          <div class="chart-tip-time">${timeLabel}</div>
          <div class="chart-tip-row"><span><i style="background:var(--emerald);"></i>Redacted</span><b>${bucket.redacted}</b></div>
          <div class="chart-tip-row"><span><i style="background:var(--rose);"></i>Blocked</span><b>${bucket.blocked}</b></div>
          <div class="chart-tip-row"><span><i style="background:#4a4a56;"></i>Clean</span><b>${bucket.clean}</b></div>
        `;
        DOM.chartTooltip.classList.add('show');
        const rect = bar.getBoundingClientRect();
        const containerRect = DOM.chartBarsContainer.getBoundingClientRect();
        DOM.chartTooltip.style.left = `${rect.left - containerRect.left - 40}px`;
        DOM.chartTooltip.style.bottom = `40px`;
      });

      bar.addEventListener('mouseleave', () => {
        DOM.chartTooltip.classList.remove('show');
      });

      DOM.chartBarsContainer.appendChild(bar);
    });
  }

  /**
   * Playground / Sandbox Inspection
   */
  async function executeSandboxInspection() {
    const text = DOM.sandboxInput.value.trim();
    if (!text) {
      showToast('Enter text to inspect', 'info');
      return;
    }

    DOM.btnRunSandbox.classList.add('is-loading');
    const startTime = performance.now();

    try {
      const res = await fetch('/api/test/sanitize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
      });

      const latencyMs = performance.now() - startTime;
      DOM.sandboxResultMeta.textContent = `${latencyMs.toFixed(1)}ms`;

      if (res.ok) {
        const data = await res.json();
        renderSandboxVerdict(data);
        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
          if (data.blocked) {
            pushChartEvent('blocked');
            updateDashboardMiniFeed({ type: 'blocked', timestamp: Date.now() / 1000, data: { reason: 'Test blocked in sandbox' } });
          } else if (data.redaction_count > 0) {
            pushChartEvent('redacted');
            updateDashboardMiniFeed({ type: 'redaction', timestamp: Date.now() / 1000, data: { redaction_count: data.redaction_count } });
          } else {
            pushChartEvent('clean');
            updateDashboardMiniFeed({ type: 'clean_pass', timestamp: Date.now() / 1000, data: { reason: 'Verified safe prompt' } });
          }
        }
        fetchMetrics();
      } else {
        const err = await res.json();
        renderSandboxVerdict({ blocked: true, violations: [{ entity_type: err.detail || 'Exception' }] });
      }
    } catch (e) {
      console.error('Sandbox error:', e);
      showToast('Sandbox inspection request failed', 'bad');
    } finally {
      DOM.btnRunSandbox.classList.remove('is-loading');
    }
  }

  function renderSandboxVerdict(result) {
    DOM.sandboxVerdictBanner.className = 'verdict';

    if (result.blocked) {
      DOM.sandboxVerdictBanner.classList.add('blocked');
      DOM.sandboxResultBadge.textContent = 'FAIL-CLOSED: BLOCKED';
      DOM.sandboxResultSub.textContent = 'Prohibited secret credentials detected. Prompt halted before dispatch.';

      DOM.sandboxResultBody.innerHTML = `
        <span class="output-label">RAW PROMPT REJECTED:</span>
        <div style="color: var(--rose); margin-bottom: 8px;">[BLOCKED BY VEIL GATEWAY POLICY]</div>
        <div>${escapeHtml(result.original_text || DOM.sandboxInput.value)}</div>
      `;

      if (result.violations && result.violations.length > 0) {
        DOM.sandboxFindingsContainer.style.display = 'flex';
        DOM.sandboxViolationsList.innerHTML = result.violations.map(v => {
          const type = typeof v === 'object' ? v.entity_type : v;
          return `<span class="pill bad"><span class="dot bad"></span>${escapeHtml(type)}</span>`;
        }).join(' ');
      } else {
        DOM.sandboxFindingsContainer.style.display = 'none';
      }
    } else if (result.redaction_count > 0) {
      DOM.sandboxVerdictBanner.classList.add('redacted');
      DOM.sandboxResultBadge.textContent = 'SANITIZED: REDACTED';
      DOM.sandboxResultSub.textContent = `${result.redaction_count} sensitive tokens replaced with session placeholders.`;

      // Highlight placeholders
      let outputText = escapeHtml(result.sanitized_text || '');
      outputText = outputText.replace(/(\[[A-Z_]+_\d+\])/g, '<mark>$1</mark>');

      DOM.sandboxResultBody.innerHTML = `
        <span class="output-label">SANITIZED OUTBOUND PROMPT:</span>
        <div>${outputText}</div>
      `;

      DOM.sandboxFindingsContainer.style.display = 'flex';
      DOM.sandboxViolationsList.innerHTML = `<span class="pill ok"><span class="dot ok"></span>${result.redaction_count} PII Redacted</span>`;
    } else {
      DOM.sandboxVerdictBanner.classList.add('clean');
      DOM.sandboxResultBadge.textContent = 'CLEAN PASS: ALLOWED';
      DOM.sandboxResultSub.textContent = 'No secrets or sensitive entities detected. Clean pass-through.';

      DOM.sandboxResultBody.innerHTML = `
        <span class="output-label">VERIFIED PAYLOAD:</span>
        <div>${escapeHtml(result.sanitized_text || result.original_text || '')}</div>
      `;
      DOM.sandboxFindingsContainer.style.display = 'none';
    }
  }

  /**
   * Enterprise Custom Entity Dictionary
   */
  async function fetchCustomEntities() {
    try {
      const res = await fetch('/api/custom-entities');
      if (res.ok) {
        const data = await res.json();
        state.customEntities = data.rules || [];
        if (DOM.navEntitiesCount) {
          DOM.navEntitiesCount.textContent = state.customEntities.length;
        }
        if (DOM.entityRulesCountPill) {
          DOM.entityRulesCountPill.textContent = `${state.customEntities.length} Rule${state.customEntities.length === 1 ? '' : 's'}`;
        }
        renderCustomEntities(state.customEntities);
      }
    } catch (err) {
      console.error('Error fetching custom entities:', err);
    }
  }

  function renderCustomEntities(rules) {
    if (!DOM.entityRulesList) return;

    let filtered = rules || [];

    // Filter by action/status
    if (state.entityFilter === 'redact') {
      filtered = filtered.filter(r => r.action === 'REDACT');
    } else if (state.entityFilter === 'block') {
      filtered = filtered.filter(r => r.action === 'BLOCK');
    } else if (state.entityFilter === 'active') {
      filtered = filtered.filter(r => r.enabled);
    }

    // Filter by search query
    if (state.entitySearchQuery) {
      const q = state.entitySearchQuery.toLowerCase();
      filtered = filtered.filter(r =>
        (r.name && r.name.toLowerCase().includes(q)) ||
        (r.pattern && r.pattern.toLowerCase().includes(q)) ||
        (r.placeholder_prefix && r.placeholder_prefix.toLowerCase().includes(q)) ||
        (r.description && r.description.toLowerCase().includes(q))
      );
    }

    if (!filtered || filtered.length === 0) {
      const isFiltered = (rules && rules.length > 0);
      DOM.entityRulesList.innerHTML = `
        <div class="empty">
          <span class="icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
              <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
            </svg>
          </span>
          <div class="empty-title">${isFiltered ? 'No Rules Match Filter' : 'No Custom Entities Configured'}</div>
          <div class="empty-desc">${isFiltered ? 'Try clearing your search query or changing the filter tab above.' : 'Add codenames, client names, or sensitive terms above to automatically scrub them from AI prompts.'}</div>
        </div>
      `;
      return;
    }

    let html = '<div class="entity-items-container" style="display: flex; flex-direction: column; gap: 10px; padding: 16px;">';
    filtered.forEach(rule => {
      const isRedact = rule.action === 'REDACT';
      const actionBadge = isRedact
        ? `<span class="pill ok" style="font-size: 11px;"><span class="dot ok"></span>REDACT [${escapeHtml(rule.placeholder_prefix || 'CONFIDENTIAL')}_00X]</span>`
        : `<span class="pill bad" style="font-size: 11px;"><span class="dot bad"></span>BLOCK (FAIL-CLOSED)</span>`;

      const typeBadge = rule.is_regex
        ? `<span class="pill warn" style="font-size: 10.5px;">REGEX</span>`
        : `<span class="pill" style="font-size: 10.5px;">LITERAL</span>`;

      const caseBadge = rule.case_sensitive
        ? `<span class="pill" style="font-size: 10px; color: var(--amber); border-color: rgba(245, 166, 35, 0.3);">Aa Case Sensitive</span>`
        : `<span class="pill" style="font-size: 10px; opacity: 0.7;">Case Insensitive</span>`;

      const hitBadge = `<span class="pill info" style="font-size: 10.5px;">${rule.hit_count || 0} hit${rule.hit_count === 1 ? '' : 's'}</span>`;

      html += `
        <div class="entity-rule-row ${rule.enabled ? '' : 'is-disabled'}" data-id="${escapeHtml(rule.id)}" style="display: flex; align-items: flex-start; justify-content: space-between; padding: 14px 16px; background: var(--bg-surface-2, rgba(255,255,255,0.02)); border: 1px solid var(--border-subtle, rgba(255,255,255,0.07)); border-radius: 8px; gap: 16px; transition: all 0.2s ease;">
          <div style="display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 0;">
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <span style="font-size: 13.5px; font-weight: 600; color: var(--text-1);">${escapeHtml(rule.name)}</span>
              ${typeBadge}
              ${actionBadge}
              ${caseBadge}
              ${hitBadge}
            </div>
            ${rule.description ? `<div style="font-size: 12px; color: var(--text-3); font-style: italic;">${escapeHtml(rule.description)}</div>` : ''}
            <div style="display: flex; align-items: center; gap: 8px; margin-top: 2px;">
              <span style="font-size: 11px; color: var(--text-3); text-transform: uppercase; font-weight: 600; letter-spacing: 0.03em;">Pattern:</span>
              <code style="font-family: var(--font-mono, monospace); font-size: 12px; background: rgba(0,0,0,0.35); padding: 3px 8px; border-radius: 4px; color: var(--accent, #64d2ff); border: 1px solid rgba(255,255,255,0.06);">${escapeHtml(rule.pattern)}</code>
              <button type="button" class="btn btn-sm btn-copy-pattern" data-pattern="${escapeHtml(rule.pattern)}" title="Copy pattern" style="padding: 2px 6px; height: 22px; font-size: 10.5px;">
                <span class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 12px; height: 12px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></span>
                <span>Copy</span>
              </button>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px; align-self: center;">
            <button class="btn btn-sm btn-toggle-entity ${rule.enabled ? 'btn-primary' : ''}" data-id="${escapeHtml(rule.id)}" title="${rule.enabled ? 'Click to disable' : 'Click to enable'}" style="padding: 5px 12px; font-size: 11.5px;">
              <span>${rule.enabled ? 'Active' : 'Disabled'}</span>
            </button>
            <button class="btn btn-sm btn-danger btn-delete-entity" data-id="${escapeHtml(rule.id)}" data-name="${escapeHtml(rule.name)}" title="Delete rule" style="padding: 5px 9px;">
              <span class="icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
              </span>
            </button>
          </div>
        </div>
      `;
    });
    html += '</div>';

    DOM.entityRulesList.innerHTML = html;
    attachEntityActions();
  }

  function attachEntityActions() {
    if (!DOM.entityRulesList) return;

    // Copy pattern
    DOM.entityRulesList.querySelectorAll('.btn-copy-pattern').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const pattern = btn.dataset.pattern;
        copyToClipboard(pattern, `Pattern "${pattern}" copied!`);
      });
    });

    // Toggle rule
    DOM.entityRulesList.querySelectorAll('.btn-toggle-entity').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        try {
          const res = await fetch(`/api/custom-entities/${id}/toggle`, { method: 'POST' });
          if (res.ok) {
            const data = await res.json();
            showToast(data.enabled ? 'Entity rule enabled' : 'Entity rule disabled', 'ok');
            fetchCustomEntities();
          }
        } catch (e) {
          showToast('Failed to toggle rule', 'bad');
        }
      });
    });

    // Delete rule
    DOM.entityRulesList.querySelectorAll('.btn-delete-entity').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const name = btn.dataset.name || 'Rule';
        if (!confirm(`Delete rule "${name}"?`)) return;

        try {
          const res = await fetch(`/api/custom-entities/${id}`, { method: 'DELETE' });
          if (res.ok) {
            showToast(`Deleted rule "${name}"`, 'info');
            fetchCustomEntities();
          }
        } catch (e) {
          showToast('Failed to delete rule', 'bad');
        }
      });
    });
  }

  function setupEntityForm() {
    if (!DOM.formAddEntity) return;

    DOM.formAddEntity.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = DOM.entityInputName.value.trim();
      const pattern = DOM.entityInputPattern.value.trim();
      const prefix = (DOM.entityInputPrefix.value.trim() || 'CONFIDENTIAL').toUpperCase();
      const action = DOM.entityInputAction.value;
      const desc = DOM.entityInputDesc ? DOM.entityInputDesc.value.trim() : '';
      const isRegex = DOM.entityInputRegex ? DOM.entityInputRegex.checked : false;
      const isCase = DOM.entityInputCase ? DOM.entityInputCase.checked : false;

      if (!name || !pattern) {
        showToast('Display Name and Match Word/Phrase are required', 'warn');
        return;
      }

      DOM.btnSaveEntity.classList.add('is-loading');
      try {
        const res = await fetch('/api/custom-entities', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name,
            pattern,
            placeholder_prefix: prefix,
            action,
            description: desc,
            is_regex: isRegex,
            case_sensitive: isCase,
            enabled: true
          })
        });

        if (res.ok) {
          DOM.formAddEntity.reset();
          if (DOM.entityInputPrefix) DOM.entityInputPrefix.value = 'PROJECT';
          showToast(`Rule "${name}" registered successfully!`, 'ok');
          if (DOM.entityLiveTestInput) DOM.entityLiveTestInput.value = '';
          updateLiveEntitySimulator();
          fetchCustomEntities();
        } else {
          const err = await res.json();
          showToast(`Error: ${err.detail || 'Could not save rule'}`, 'bad');
        }
      } catch (err) {
        showToast('Failed to create custom entity', 'bad');
      } finally {
        DOM.btnSaveEntity.classList.remove('is-loading');
      }
    });
  }

  /**
   * One-Click Quick Presets for Entity Rules
   */
  function setupEntityPresets() {
    const presets = [
      {
        btn: DOM.presetEntityProject,
        name: 'Project Titan',
        pattern: 'Project Titan',
        prefix: 'PROJECT',
        action: 'REDACT',
        isRegex: false,
        isCase: false,
        desc: 'Unreleased Next-Gen Architecture Initiative'
      },
      {
        btn: DOM.presetEntityClient,
        name: 'Acme Health & Enterprise',
        pattern: 'Acme Health|Acme Corp|Acme Systems',
        prefix: 'CLIENT',
        action: 'REDACT',
        isRegex: true,
        isCase: false,
        desc: 'Healthcare partner NDA protected client terms'
      },
      {
        btn: DOM.presetEntityBlocked,
        name: 'Root Credential Secret',
        pattern: 'PROD_MASTER_KEY|ROOT_SSH_BYPASS|SUPERADMIN_SECRET',
        prefix: 'BLOCKED',
        action: 'BLOCK',
        isRegex: true,
        isCase: true,
        desc: 'Strict fail-closed root credential leakage prevention'
      },
      {
        btn: DOM.presetEntityNetwork,
        name: 'Internal Network & Hostnames',
        pattern: 'corp\\.internal|internal-db|10\\.240\\.\\d+\\.\\d+',
        prefix: 'INTERNAL_NET',
        action: 'REDACT',
        isRegex: true,
        isCase: false,
        desc: 'Internal VPC CIDR blocks and cluster hostnames'
      },
      {
        btn: DOM.presetEntityAccount,
        name: 'Customer Account ID Format',
        pattern: 'ACC-[0-9]{6,10}',
        prefix: 'ACCOUNT_ID',
        action: 'REDACT',
        isRegex: true,
        isCase: false,
        desc: 'Customer PII financial account identifier regex'
      }
    ];

    presets.forEach(p => {
      if (!p.btn) return;
      p.btn.addEventListener('click', () => {
        if (DOM.entityInputName) DOM.entityInputName.value = p.name;
        if (DOM.entityInputPattern) DOM.entityInputPattern.value = p.pattern;
        if (DOM.entityInputPrefix) DOM.entityInputPrefix.value = p.prefix;
        if (DOM.entityInputAction) DOM.entityInputAction.value = p.action;
        if (DOM.entityInputDesc) DOM.entityInputDesc.value = p.desc;
        if (DOM.entityInputRegex) DOM.entityInputRegex.checked = p.isRegex;
        if (DOM.entityInputCase) DOM.entityInputCase.checked = p.isCase;

        if (DOM.entityLiveTestInput) {
          DOM.entityLiveTestInput.value = `Testing security filter for ${p.name.split(' ')[0]} and related assets.`;
        }

        updateLiveEntitySimulator();
        showToast(`Loaded "${p.name}" preset template!`, 'info');
      });
    });
  }

  /**
   * Real-Time Live Entity Rule Simulator
   */
  function setupEntitySimulator() {
    if (!DOM.entityLiveTestInput) return;

    const watched = [
      DOM.entityLiveTestInput,
      DOM.entityInputPattern,
      DOM.entityInputPrefix,
      DOM.entityInputAction,
      DOM.entityInputRegex,
      DOM.entityInputCase
    ];

    watched.forEach(el => {
      if (!el) return;
      el.addEventListener('input', updateLiveEntitySimulator);
      el.addEventListener('change', updateLiveEntitySimulator);
    });
  }

  function updateLiveEntitySimulator() {
    if (!DOM.entityLiveTestOutput) return;

    const testText = DOM.entityLiveTestInput ? DOM.entityLiveTestInput.value.trim() : '';
    const pattern = DOM.entityInputPattern ? DOM.entityInputPattern.value.trim() : '';
    const prefix = DOM.entityInputPrefix ? (DOM.entityInputPrefix.value.trim() || 'CONFIDENTIAL').toUpperCase() : 'CONFIDENTIAL';
    const action = DOM.entityInputAction ? DOM.entityInputAction.value : 'REDACT';
    const isRegex = DOM.entityInputRegex ? DOM.entityInputRegex.checked : false;
    const isCase = DOM.entityInputCase ? DOM.entityInputCase.checked : false;

    if (!testText) {
      DOM.entityLiveTestOutput.innerHTML = `<span class="muted">Enter text above to preview live tokenization or blocking verdict.</span>`;
      return;
    }

    if (!pattern) {
      DOM.entityLiveTestOutput.innerHTML = `<span class="muted">Enter a Match Word / Phrase above to begin simulation.</span>`;
      return;
    }

    try {
      let reg;
      const flags = isCase ? 'g' : 'gi';
      if (isRegex) {
        reg = new RegExp(pattern, flags);
      } else {
        const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        reg = new RegExp('\\b' + escaped + '\\b', flags);
      }

      const matches = testText.match(reg);

      if (matches && matches.length > 0) {
        if (action === 'BLOCK') {
          DOM.entityLiveTestOutput.innerHTML = `
            <span class="pill bad"><span class="dot bad"></span>FAIL-CLOSED BLOCK</span>
            <span style="color: var(--rose);">Outbound prompt will be halted immediately. Detected: <strong>"${escapeHtml(matches[0])}"</strong></span>
          `;
        } else {
          let tokenIndex = 1;
          const sanitized = testText.replace(reg, () => `[${prefix}_00${tokenIndex++}]`);
          DOM.entityLiveTestOutput.innerHTML = `
            <span class="pill ok"><span class="dot ok"></span>REDACTED ON WIRE</span>
            <span style="color: var(--emerald);">Outbound will be sent as: <code style="color: var(--accent); font-weight: 600;">${escapeHtml(sanitized)}</code></span>
          `;
        }
      } else {
        DOM.entityLiveTestOutput.innerHTML = `
          <span class="pill info">NO MATCH</span>
          <span class="muted">Clean prompt. No sensitive entities triggered.</span>
        `;
      }
    } catch (err) {
      DOM.entityLiveTestOutput.innerHTML = `
        <span class="pill bad">INVALID PATTERN</span>
        <span style="color: var(--rose);">${escapeHtml(err.message)}</span>
      `;
    }
  }

  /**
   * Filter, Search, and Export/Import Rules
   */
  function setupEntityFiltersAndExport() {
    // Search input
    if (DOM.searchEntityRules) {
      DOM.searchEntityRules.addEventListener('input', (e) => {
        state.entitySearchQuery = e.target.value.trim();
        renderCustomEntities(state.customEntities);
      });
    }

    // Filter segmented buttons
    if (DOM.entityFilterSegmented) {
      DOM.entityFilterSegmented.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => {
          DOM.entityFilterSegmented.querySelectorAll('button').forEach(b => {
            b.classList.remove('active');
            b.setAttribute('aria-pressed', 'false');
          });
          btn.classList.add('active');
          btn.setAttribute('aria-pressed', 'true');
          state.entityFilter = btn.dataset.filter;
          renderCustomEntities(state.customEntities);
        });
      });
    }

    // Export JSON
    if (DOM.btnExportEntities) {
      DOM.btnExportEntities.addEventListener('click', () => {
        if (!state.customEntities || state.customEntities.length === 0) {
          showToast('No rules to export', 'warn');
          return;
        }
        const jsonStr = JSON.stringify(state.customEntities, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `veil_custom_entities_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Exported custom entity rules to JSON', 'ok');
      });
    }

    // Import JSON
    if (DOM.btnImportEntities && DOM.inputImportEntities) {
      DOM.btnImportEntities.addEventListener('click', () => {
        DOM.inputImportEntities.click();
      });

      DOM.inputImportEntities.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (evt) => {
          try {
            const parsed = JSON.parse(evt.target.result);
            const rules = Array.isArray(parsed) ? parsed : (parsed.rules || []);
            if (!Array.isArray(rules) || rules.length === 0) {
              showToast('Invalid JSON: expected array of rules', 'bad');
              return;
            }

            let importedCount = 0;
            for (const r of rules) {
              if (r.name && r.pattern) {
                await fetch('/api/custom-entities', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(r)
                });
                importedCount++;
              }
            }

            showToast(`Imported ${importedCount} entity rules successfully!`, 'ok');
            DOM.inputImportEntities.value = '';
            fetchCustomEntities();
          } catch (err) {
            showToast('Failed to import JSON file', 'bad');
          }
        };
        reader.readAsText(file);
      });
    }
  }

  /**
   * System Autostart
   */
  async function fetchAutostart() {
    try {
      const res = await fetch('/api/system/autostart');
      if (res.ok) {
        const data = await res.json();
        state.autostartEnabled = !!data.enabled;
        if (DOM.autostartToggle) {
          DOM.autostartToggle.setAttribute('aria-checked', state.autostartEnabled ? 'true' : 'false');
        }
      }
    } catch (e) {
      console.error('Fetch autostart error:', e);
    }
  }

  async function toggleAutostart() {
    const newState = !state.autostartEnabled;
    try {
      const res = await fetch('/api/system/autostart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
      });
      if (res.ok) {
        const data = await res.json();
        state.autostartEnabled = !!data.enabled;
        DOM.autostartToggle.setAttribute('aria-checked', state.autostartEnabled ? 'true' : 'false');
        showToast(state.autostartEnabled ? 'Autostart enabled on Windows login' : 'Autostart disabled', 'ok');
      }
    } catch (e) {
      showToast('Failed to toggle autostart', 'bad');
    }
  }

  /**
   * ==========================================================================
   * Semantic Knowledge Vector Vault Controller (Phase 4)
   * ==========================================================================
   */
  async function fetchVectorEntries() {
    try {
      const res = await fetch('/api/knowledge-vault');
      if (res.ok) {
        const data = await res.json();
        state.vectorEntries = data.entries || [];
        updateVectorVaultUI(data);
      }
    } catch (err) {
      console.error('Error fetching knowledge vector entries:', err);
    }
  }

  function updateVectorVaultUI(meta = {}) {
    const total = state.vectorEntries.length;
    const activeCount = state.vectorEntries.filter(e => e.enabled).length;
    const totalHits = state.vectorEntries.reduce((acc, e) => acc + (e.hit_count || 0), 0);

    if (DOM.navVectorsCount) {
      DOM.navVectorsCount.textContent = total;
    }
    if (DOM.vectorRulesCountPill) {
      DOM.vectorRulesCountPill.textContent = `${total} Entr${total === 1 ? 'y' : 'ies'}`;
    }
    if (DOM.statVaultCount) {
      DOM.statVaultCount.textContent = `${activeCount} item${activeCount === 1 ? '' : 's'}`;
    }
    if (DOM.statVaultHits) {
      DOM.statVaultHits.textContent = `${totalHits} Breach${totalHits === 1 ? '' : 'es'} Blocked`;
    }

    renderVectorEntries();
  }

  function renderVectorEntries() {
    if (!DOM.vectorRulesList) return;

    let filtered = [...state.vectorEntries];

    // Filter by Category
    if (state.vectorCategoryFilter && state.vectorCategoryFilter !== 'ALL') {
      filtered = filtered.filter(e => (e.category || '').toUpperCase() === state.vectorCategoryFilter);
    }

    // Filter by Search Query
    if (state.vectorSearchQuery) {
      const q = state.vectorSearchQuery.toLowerCase();
      filtered = filtered.filter(e =>
        (e.title || '').toLowerCase().includes(q) ||
        (e.text || '').toLowerCase().includes(q) ||
        (e.category || '').toLowerCase().includes(q)
      );
    }

    if (filtered.length === 0) {
      DOM.vectorRulesList.innerHTML = `
        <div class="empty">
          <span class="icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
              <polyline points="2 17 12 22 22 17"></polyline>
              <polyline points="2 12 12 17 22 12"></polyline>
            </svg>
          </span>
          <div class="empty-title">${state.vectorEntries.length === 0 ? 'No Knowledge Vectors Registered' : 'No Matching Vectors'}</div>
          <div class="empty-desc">${state.vectorEntries.length === 0 ? 'Ingest sensitive documents or secrets above to guard against unauthorized leakage or AI training extraction.' : 'Try adjusting your search or category filter.'}</div>
        </div>
      `;
      return;
    }

    const html = filtered.map(entry => {
      const isBlock = entry.action === 'BLOCK';
      const actionPill = isBlock
        ? `<span class="pill bad" style="font-size: 10.5px;">BLOCK</span>`
        : `<span class="pill warn" style="font-size: 10.5px;">REDACT</span>`;

      const thresholdVal = entry.threshold_override ? entry.threshold_override.toFixed(2) : 'Default (0.75)';
      const dateStr = entry.created_at ? new Date(entry.created_at * 1000).toLocaleDateString() : 'Active';

      return `
        <div class="vector-rule-row" data-id="${escapeHtml(entry.id)}">
          <div class="vector-rule-main">
            <div class="vector-rule-title-row">
              <span class="vector-rule-title">${escapeHtml(entry.title)}</span>
              <span class="tag">${escapeHtml(entry.category)}</span>
              ${actionPill}
              ${entry.hit_count > 0 ? `<span class="pill info" style="font-size: 10.5px;">${entry.hit_count} Hit${entry.hit_count === 1 ? '' : 's'}</span>` : ''}
            </div>
            <div class="vector-rule-text">${escapeHtml(entry.text)}</div>
            <div class="vector-rule-meta">
              <span>Threshold: <b style="color: var(--text);">${thresholdVal}</b></span>
              <span>Ingested: ${dateStr}</span>
              <span>ID: <code style="font-size: 10.5px;">${escapeHtml(entry.id.substring(0, 8))}</code></span>
            </div>
          </div>
          <div class="vector-rule-actions">
            <button type="button" class="switch vector-toggle-switch" role="switch" aria-checked="${entry.enabled ? 'true' : 'false'}" data-id="${escapeHtml(entry.id)}" title="${entry.enabled ? 'Deactivate rule' : 'Activate rule'}" aria-label="Toggle ${escapeHtml(entry.title)}"></button>
            <button class="btn btn-ghost btn-sm btn-icon btn-test-vector-item" data-id="${escapeHtml(entry.id)}" title="Simulate Prompt Against This Vector">
              <span class="icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polygon points="5 3 19 12 5 21 5 3"></polygon>
                </svg>
              </span>
            </button>
            <button class="btn btn-ghost btn-sm btn-icon btn-delete-vector-item" data-id="${escapeHtml(entry.id)}" title="Delete Knowledge Vector">
              <span class="icon" style="color: var(--rose);">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
              </span>
            </button>
          </div>
        </div>
      `;
    }).join('');

    DOM.vectorRulesList.innerHTML = html;

    // Attach row event listeners
    DOM.vectorRulesList.querySelectorAll('.vector-toggle-switch').forEach(sw => {
      sw.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const id = sw.dataset.id;
        toggleVectorEntry(id);
      });
    });

    DOM.vectorRulesList.querySelectorAll('.btn-delete-vector-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.id;
        deleteVectorEntry(id);
      });
    });

    DOM.vectorRulesList.querySelectorAll('.btn-test-vector-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.id;
        const entry = state.vectorEntries.find(e => e.id === id);
        if (entry && DOM.vectorLiveTestInput) {
          DOM.vectorLiveTestInput.value = entry.text.substring(0, 120);
          testVectorSimilarity();
        }
      });
    });
  }

  async function toggleVectorEntry(id) {
    const entry = state.vectorEntries.find(e => e.id === id);
    if (!entry) return;

    try {
      const res = await fetch(`/api/knowledge-vault/${id}/toggle`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        const idx = state.vectorEntries.findIndex(e => e.id === id);
        if (idx !== -1) {
          if (data.entry) {
            state.vectorEntries[idx] = data.entry;
          } else if (typeof data.enabled === 'boolean') {
            state.vectorEntries[idx].enabled = data.enabled;
          } else {
            state.vectorEntries[idx].enabled = !entry.enabled;
          }
        }
        updateVectorVaultUI();
        const isEnabled = data.entry ? data.entry.enabled : (data.enabled ?? !entry.enabled);
        showToast(`Rule ${isEnabled ? 'activated' : 'deactivated'}`, 'ok');
      } else {
        showToast('Failed to toggle vector rule', 'bad');
      }
    } catch (err) {
      console.error('Toggle vector entry error:', err);
      showToast('Failed to toggle vector rule', 'bad');
    }
  }

  async function deleteVectorEntry(id) {
    if (!confirm('Are you sure you want to delete this protected vector entry?')) return;
    try {
      const res = await fetch(`/api/knowledge-vault/${id}`, { method: 'DELETE' });
      if (res.ok) {
        state.vectorEntries = state.vectorEntries.filter(e => e.id !== id);
        updateVectorVaultUI();
        showToast('Knowledge vector removed from vault', 'ok');
      }
    } catch (err) {
      showToast('Failed to delete knowledge vector', 'bad');
    }
  }

  function setupVectorVaultController() {
    // Mode Switch (Single vs Document)
    if (DOM.btnModeSingle && DOM.btnModeDocument) {
      DOM.btnModeSingle.addEventListener('click', () => {
        DOM.btnModeSingle.classList.add('active');
        DOM.btnModeSingle.setAttribute('aria-pressed', 'true');
        DOM.btnModeDocument.classList.remove('active');
        DOM.btnModeDocument.setAttribute('aria-pressed', 'false');
        state.vectorMode = 'single';
        if (DOM.vectorDocOptions) DOM.vectorDocOptions.style.display = 'none';
        if (DOM.btnSaveVectorText) DOM.btnSaveVectorText.textContent = 'Ingest Into Vector Vault';
      });

      DOM.btnModeDocument.addEventListener('click', () => {
        DOM.btnModeDocument.classList.add('active');
        DOM.btnModeDocument.setAttribute('aria-pressed', 'true');
        DOM.btnModeSingle.classList.remove('active');
        DOM.btnModeSingle.setAttribute('aria-pressed', 'false');
        state.vectorMode = 'document';
        if (DOM.vectorDocOptions) DOM.vectorDocOptions.style.display = 'block';
        if (DOM.btnSaveVectorText) DOM.btnSaveVectorText.textContent = 'Chunk & Ingest Document Memos';
      });
    }

    // Threshold Slider update
    if (DOM.vectorInputThreshold && DOM.vectorThresholdBadge) {
      DOM.vectorInputThreshold.addEventListener('input', (e) => {
        DOM.vectorThresholdBadge.textContent = parseFloat(e.target.value).toFixed(2);
      });
    }

    // Char count update
    if (DOM.vectorInputText && DOM.vectorTextCharCount) {
      DOM.vectorInputText.addEventListener('input', () => {
        const len = DOM.vectorInputText.value.length;
        DOM.vectorTextCharCount.textContent = `${len} char${len === 1 ? '' : 's'}`;
      });
    }

    // Presets
    setupVectorPresets();

    // Form Submit
    if (DOM.formAddVector) {
      DOM.formAddVector.addEventListener('submit', async (e) => {
        e.preventDefault();
        const title = DOM.vectorInputTitle.value.trim();
        const category = DOM.vectorInputCategory.value;
        const action = DOM.vectorInputAction.value;
        const text = DOM.vectorInputText.value.trim();
        const threshold = parseFloat(DOM.vectorInputThreshold.value);

        if (!title || !text) return;

        DOM.btnSaveVector.classList.add('is-loading');

        try {
          if (state.vectorMode === 'document') {
            const windowSize = parseInt(DOM.vectorDocWindow ? DOM.vectorDocWindow.value : '2', 10);
            const stride = parseInt(DOM.vectorDocStride ? DOM.vectorDocStride.value : '1', 10);
            const res = await fetch('/api/knowledge-vault/embed-document', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                title,
                document_text: text,
                category,
                action,
                threshold_override: threshold,
                window_size_sentences: windowSize,
                stride
              })
            });
            if (res.ok) {
              const data = await res.json();
              showToast(`Ingested document into ${data.created_count} sliding vector chunks!`, 'ok');
              DOM.vectorInputText.value = '';
              DOM.vectorInputTitle.value = '';
              fetchVectorEntries();
            } else {
              const err = await res.json();
              showToast(`Error: ${err.detail || 'Failed to embed document'}`, 'bad');
            }
          } else {
            const res = await fetch('/api/knowledge-vault/entry', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                title,
                text,
                category,
                action,
                threshold_override: threshold
              })
            });
            if (res.ok) {
              const data = await res.json();
              showToast(`Ingested "${title}" into vector vault!`, 'ok');
              DOM.vectorInputText.value = '';
              DOM.vectorInputTitle.value = '';
              fetchVectorEntries();
            } else {
              const err = await res.json();
              showToast(`Error: ${err.detail || 'Failed to add entry'}`, 'bad');
            }
          }
        } catch (err) {
          showToast('Failed to communicate with vector vault API', 'bad');
        } finally {
          DOM.btnSaveVector.classList.remove('is-loading');
        }
      });
    }

    // Similarity Sandbox Test Button
    if (DOM.btnTestVectorSim) {
      DOM.btnTestVectorSim.addEventListener('click', testVectorSimilarity);
    }
    if (DOM.vectorLiveTestInput) {
      DOM.vectorLiveTestInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          testVectorSimilarity();
        }
      });
    }

    // Category Segmented Filter
    if (DOM.vectorCategorySegmented) {
      DOM.vectorCategorySegmented.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => {
          DOM.vectorCategorySegmented.querySelectorAll('button').forEach(b => {
            b.classList.remove('active');
            b.setAttribute('aria-pressed', 'false');
          });
          btn.classList.add('active');
          btn.setAttribute('aria-pressed', 'true');
          state.vectorCategoryFilter = btn.dataset.cat;
          renderVectorEntries();
        });
      });
    }

    // Search Input
    if (DOM.searchVectorRules) {
      DOM.searchVectorRules.addEventListener('input', (e) => {
        state.vectorSearchQuery = e.target.value.toLowerCase().trim();
        renderVectorEntries();
      });
    }
  }

  function setupVectorPresets() {
    const presets = [
      {
        btn: DOM.presetVecMa,
        title: 'Project Apex Buyout Terms',
        category: 'PROPRIETARY',
        action: 'BLOCK',
        threshold: 0.70,
        text: 'Confidential buyout discussions with Apex Corporation valuing the entity at $4.2 billion with 30 days exclusivity.'
      },
      {
        btn: DOM.presetVecFinancial,
        title: 'Unreleased Q3 Margin Compression',
        category: 'FINANCIAL',
        action: 'BLOCK',
        threshold: 0.65,
        text: 'Internal board forecast projects Q3 operating margin compression of 400 basis points due to APAC component supply delays.'
      },
      {
        btn: DOM.presetVecInfra,
        title: 'Production Database Cluster Spec',
        category: 'INFRASTRUCTURE',
        action: 'REDACT',
        threshold: 0.75,
        text: 'The primary PostgreSQL cluster master is reachable on internal subnet 10.240.12.4 on port 9443 without mTLS.'
      },
      {
        btn: DOM.presetVecHr,
        title: 'Executive Restructuring Plan Q4',
        category: 'HR',
        action: 'BLOCK',
        threshold: 0.65,
        text: 'Phase 2 workforce reduction plan eliminating 14% of mid-level engineering positions across EMEA and LATAM teams.'
      }
    ];

    presets.forEach(p => {
      if (!p.btn) return;
      p.btn.addEventListener('click', () => {
        if (DOM.vectorInputTitle) DOM.vectorInputTitle.value = p.title;
        if (DOM.vectorInputCategory) DOM.vectorInputCategory.value = p.category;
        if (DOM.vectorInputAction) DOM.vectorInputAction.value = p.action;
        if (DOM.vectorInputThreshold) {
          DOM.vectorInputThreshold.value = p.threshold;
          if (DOM.vectorThresholdBadge) DOM.vectorThresholdBadge.textContent = p.threshold.toFixed(2);
        }
        if (DOM.vectorInputText) {
          DOM.vectorInputText.value = p.text;
          if (DOM.vectorTextCharCount) DOM.vectorTextCharCount.textContent = `${p.text.length} chars`;
        }
        showToast(`Loaded preset "${p.title}"!`, 'info');
      });
    });
  }

  async function testVectorSimilarity() {
    if (!DOM.vectorLiveTestInput) return;
    const text = DOM.vectorLiveTestInput.value.trim();
    if (!text) {
      showToast('Enter a test prompt first', 'info');
      return;
    }

    if (DOM.btnTestVectorSim) DOM.btnTestVectorSim.classList.add('is-loading');

    try {
      const res = await fetch('/api/knowledge-vault/test-similarity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, top_k: 5, min_threshold: 0.0 })
      });

      if (res.ok) {
        const data = await res.json();
        renderVectorSimilarityResult(data);
      } else {
        showToast('Similarity query failed', 'bad');
      }
    } catch (err) {
      showToast('Error testing vector similarity', 'bad');
    } finally {
      if (DOM.btnTestVectorSim) DOM.btnTestVectorSim.classList.remove('is-loading');
    }
  }

  function renderVectorSimilarityResult(data) {
    if (!DOM.vectorLiveTestOutput) return;
    DOM.vectorLiveTestOutput.style.display = 'block';

    if (DOM.vectorTestLatencyText) {
      DOM.vectorTestLatencyText.textContent = `${data.search_latency_ms.toFixed(1)}ms CPU search`;
    }

    const matches = data.matches || [];
    const topMatch = matches.length > 0 ? matches[0] : null;

    if (!topMatch || topMatch.similarity < 0.20) {
      if (DOM.vectorTestVerdictPill) {
        DOM.vectorTestVerdictPill.className = 'pill ok';
        DOM.vectorTestVerdictPill.textContent = 'CLEAN PASS (No Confidential Match)';
      }
      if (DOM.vectorTestGaugeBar) {
        DOM.vectorTestGaugeBar.style.width = '10%';
        DOM.vectorTestGaugeBar.className = 'vector-similarity-bar';
      }
      if (DOM.vectorTestDetails) {
        DOM.vectorTestDetails.innerHTML = `<span>Prompt evaluated cleanly with no semantic proximity to registered confidential knowledge.</span>`;
      }
      return;
    }

    const percent = Math.min(100, Math.round(topMatch.similarity * 100));
    const isBreach = topMatch.is_breach;

    if (DOM.vectorTestGaugeBar) {
      DOM.vectorTestGaugeBar.style.width = `${percent}%`;
      if (isBreach) {
        DOM.vectorTestGaugeBar.className = topMatch.action === 'BLOCK' ? 'vector-similarity-bar breach' : 'vector-similarity-bar warn';
      } else {
        DOM.vectorTestGaugeBar.className = 'vector-similarity-bar';
      }
    }

    if (DOM.vectorTestVerdictPill) {
      if (isBreach) {
        if (topMatch.action === 'BLOCK') {
          DOM.vectorTestVerdictPill.className = 'pill bad';
          DOM.vectorTestVerdictPill.textContent = `OUTBOUND BLOCKED (${percent}% Cosine Match)`;
        } else {
          DOM.vectorTestVerdictPill.className = 'pill warn';
          DOM.vectorTestVerdictPill.textContent = `REDACTED [CONFIDENTIAL_CONTEXT] (${percent}% Match)`;
        }
      } else {
        DOM.vectorTestVerdictPill.className = 'pill info';
        DOM.vectorTestVerdictPill.textContent = `SUB-THRESHOLD MATCH (${percent}% < Threshold)`;
      }
    }

    if (DOM.vectorTestDetails) {
      DOM.vectorTestDetails.innerHTML = `
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
          <span>Matched Knowledge: <b style="color: var(--text);">${escapeHtml(topMatch.title)}</b> (${escapeHtml(topMatch.category)})</span>
          <span style="font-family: var(--mono); color: var(--emerald);">${topMatch.similarity.toFixed(4)} similarity</span>
        </div>
        <div style="font-style: italic; color: var(--text-3); font-size: 11.5px;">"${escapeHtml(topMatch.text_snippet)}"</div>
      `;
    }
  }

  /**
   * Utilities
   */
  function copyToClipboard(text, message = 'Copied to clipboard!') {
    navigator.clipboard.writeText(text).then(() => {
      showToast(message, 'ok');
    }).catch(() => {
      showToast('Could not copy to clipboard', 'bad');
    });
  }

  function showToast(title, type = 'info', description = '') {
    if (!DOM.toastsContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    if (type === 'ok') {
      iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    } else if (type === 'bad') {
      iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
    }

    toast.innerHTML = `
      <span class="icon">${iconSvg}</span>
      <div>
        <div class="toast-title">${escapeHtml(title)}</div>
        ${description ? `<div class="toast-desc">${escapeHtml(description)}</div>` : ''}
      </div>
    `;

    DOM.toastsContainer.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('out');
      setTimeout(() => toast.remove(), 250);
    }, 3200);
  }

  function formatNumber(num) {
    return Number(num).toLocaleString();
  }

  function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
      .toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Billing & Licensing Controller
   */
  function setupBillingController() {
    let currentCurrency = 'NGN';
    let currentBillingStatus = null;

    const elBtnCurrencyNgn = document.getElementById('btn-currency-ngn');
    const elBtnCurrencyUsd = document.getElementById('btn-currency-usd');
    const elProPrice = document.getElementById('pro-price-display');
    const elEntPrice = document.getElementById('ent-price-display');
    const elProPeriod = document.getElementById('pro-period-display');
    const elEntPeriod = document.getElementById('ent-period-display');
    const elBtnUpgradePro = document.getElementById('btn-upgrade-pro');
    const elBtnContactEnt = document.getElementById('btn-contact-enterprise');
    const elBtnPlanFree = document.getElementById('btn-plan-free');
    const elTierBadge = document.getElementById('billing-tier-badge');
    const elStatusSub = document.getElementById('billing-status-sub');
    const elCustomerEmail = document.getElementById('billing-customer-email');
    const elLicenseId = document.getElementById('billing-license-id');
    const elNavTierBadge = document.getElementById('nav-plan-tier-badge');
    const elInputKey = document.getElementById('input-license-key');
    const elBtnSubmitKey = document.getElementById('btn-submit-license-key');
    const elKeyFeedback = document.getElementById('license-key-feedback');
    const elBtnOpenBox = document.getElementById('btn-open-activate-box');

    function updateCurrencyDisplay() {
      if (currentCurrency === 'NGN') {
        if (elProPrice) elProPrice.innerText = '₦30,000';
        if (elEntPrice) elEntPrice.innerText = '₦90,000';
        if (elProPeriod) elProPeriod.innerText = '/ month';
        if (elEntPeriod) elEntPeriod.innerText = '/ seat / month';
        if (elBtnCurrencyNgn) elBtnCurrencyNgn.classList.add('active');
        if (elBtnCurrencyUsd) elBtnCurrencyUsd.classList.remove('active');
      } else {
        if (elProPrice) elProPrice.innerText = '$20';
        if (elEntPrice) elEntPrice.innerText = '$60';
        if (elProPeriod) elProPeriod.innerText = '/ month';
        if (elEntPeriod) elEntPeriod.innerText = '/ seat / month';
        if (elBtnCurrencyNgn) elBtnCurrencyNgn.classList.remove('active');
        if (elBtnCurrencyUsd) elBtnCurrencyUsd.classList.add('active');
      }
    }

    if (elBtnCurrencyNgn) {
      elBtnCurrencyNgn.addEventListener('click', () => {
        currentCurrency = 'NGN';
        updateCurrencyDisplay();
      });
    }
    if (elBtnCurrencyUsd) {
      elBtnCurrencyUsd.addEventListener('click', () => {
        currentCurrency = 'USD';
        updateCurrencyDisplay();
      });
    }

    if (elBtnOpenBox) {
      elBtnOpenBox.addEventListener('click', () => {
        const box = document.getElementById('box-activate-key');
        if (box) {
          box.scrollIntoView({ behavior: 'smooth' });
          if (elInputKey) elInputKey.focus();
        }
      });
    }

    async function fetchBillingStatus() {
      try {
        const res = await fetch('/api/billing/status');
        if (!res.ok) return;
        const data = await res.json();
        currentBillingStatus = data;

        const tier = data.tier || 'FREE';
        if (elNavTierBadge) {
          elNavTierBadge.innerText = tier;
          if (tier === 'PRO') {
            elNavTierBadge.style.background = 'rgba(61, 214, 140, 0.2)';
            elNavTierBadge.style.color = '#3dd68c';
          } else if (tier === 'ENTERPRISE') {
            elNavTierBadge.style.background = 'rgba(168, 85, 247, 0.2)';
            elNavTierBadge.style.color = '#c084fc';
          } else {
            elNavTierBadge.style.background = 'rgba(14, 165, 233, 0.2)';
            elNavTierBadge.style.color = '#38bdf8';
          }
        }

        if (elTierBadge) {
          elTierBadge.innerText = tier === 'FREE' ? 'SOLO / COMMUNITY' : `${tier} TIER`;
          elTierBadge.className = tier === 'FREE' ? 'pill' : 'pill ok';
        }
        if (elStatusSub) {
          if (data.is_expired) {
            elStatusSub.innerText = 'License Expired (Falling back to Free)';
            elStatusSub.style.color = '#f2555a';
          } else if (data.expires_at) {
            const expDate = new Date(data.expires_at * 1000).toLocaleDateString();
            elStatusSub.innerText = `Active License (Renews ${expDate})`;
            elStatusSub.style.color = '#3dd68c';
          } else {
            elStatusSub.innerText = 'Active Community License';
            elStatusSub.style.color = 'var(--text-2)';
          }
        }
        if (elCustomerEmail) elCustomerEmail.innerText = data.customer_email || 'developer@community.veil';
        if (elLicenseId) elLicenseId.innerText = data.license_id || 'VL-FREE-COMMUNITY';

        // Update action buttons based on active tier
        if (elBtnPlanFree) {
          if (tier === 'FREE') {
            elBtnPlanFree.disabled = true;
            elBtnPlanFree.innerText = 'Active Plan';
            elBtnPlanFree.className = 'btn btn-secondary plan-btn';
          } else {
            elBtnPlanFree.disabled = true;
            elBtnPlanFree.innerText = 'Included';
            elBtnPlanFree.className = 'btn btn-secondary plan-btn';
          }
        }

        if (elBtnUpgradePro) {
          if (tier === 'PRO') {
            elBtnUpgradePro.disabled = true;
            elBtnUpgradePro.innerText = 'Active Plan ✓';
            elBtnUpgradePro.className = 'btn btn-secondary plan-btn';
          } else {
            elBtnUpgradePro.disabled = false;
            elBtnUpgradePro.innerText = 'Upgrade with Paystack';
            elBtnUpgradePro.className = 'btn btn-primary plan-btn';
          }
        }

        if (elBtnContactEnt) {
          if (tier === 'ENTERPRISE') {
            elBtnContactEnt.disabled = true;
            elBtnContactEnt.innerText = 'Active Plan ✓';
          } else {
            elBtnContactEnt.disabled = false;
            elBtnContactEnt.innerText = 'Contact Enterprise Sales';
          }
        }
      } catch (err) {
        console.error('Failed to load billing status:', err);
      }
    }

    if (elBtnUpgradePro) {
      elBtnUpgradePro.addEventListener('click', async () => {
        const defaultEmail = (currentBillingStatus && currentBillingStatus.customer_email && !currentBillingStatus.customer_email.includes('.veil')) 
          ? currentBillingStatus.customer_email 
          : '';
        const email = prompt('Enter your email address for the Paystack payment & license issuance:', defaultEmail);
        if (!email || !email.includes('@')) {
          if (email !== null) showToast('Invalid Email', 'Please provide a valid email address for your license receipt.', 'warning');
          return;
        }

        elBtnUpgradePro.disabled = true;
        elBtnUpgradePro.innerText = 'Connecting to Paystack...';

        try {
          const res = await fetch('/api/billing/checkout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tier: 'PRO',
              email: email.trim(),
              currency: currentCurrency
            })
          });

          const data = await res.json();
          if (res.ok && data.authorization_url) {
            showToast('Paystack Checkout Initialized', `Opening ${data.amount_formatted} payment session for ${email}...`, 'info');
            window.open(data.authorization_url, '_blank');
          } else {
            showToast('Checkout Error', data.detail || 'Could not initiate checkout session.', 'error');
          }
        } catch (err) {
          showToast('Network Error', err.message, 'error');
        } finally {
          elBtnUpgradePro.disabled = false;
          elBtnUpgradePro.innerText = 'Upgrade with Paystack';
          fetchBillingStatus();
        }
      });
    }

    if (elBtnSubmitKey && elInputKey) {
      elBtnSubmitKey.addEventListener('click', async () => {
        const key = elInputKey.value.trim();
        if (!key) {
          if (elKeyFeedback) {
            elKeyFeedback.style.color = '#f2555a';
            elKeyFeedback.innerText = 'Please enter a license key string.';
          }
          return;
        }

        elBtnSubmitKey.disabled = true;
        elBtnSubmitKey.innerText = 'Activating...';
        if (elKeyFeedback) elKeyFeedback.innerText = '';

        try {
          const res = await fetch('/api/billing/activate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ license_key: key })
          });

          const data = await res.json();
          if (res.ok) {
            if (elKeyFeedback) {
              elKeyFeedback.style.color = '#3dd68c';
              elKeyFeedback.innerText = `✓ ${data.message} (${data.tier} Tier unlocked)`;
            }
            showToast('License Activated', `Successfully unlocked ${data.tier} features!`, 'success');
            elInputKey.value = '';
            fetchBillingStatus();
          } else {
            if (elKeyFeedback) {
              elKeyFeedback.style.color = '#f2555a';
              elKeyFeedback.innerText = `✕ Error: ${data.detail || 'License verification failed'}`;
            }
            showToast('Activation Failed', data.detail || 'Invalid or tampered license key.', 'error');
          }
        } catch (err) {
          if (elKeyFeedback) {
            elKeyFeedback.style.color = '#f2555a';
            elKeyFeedback.innerText = `✕ Network error: ${err.message}`;
          }
        } finally {
          elBtnSubmitKey.disabled = false;
          elBtnSubmitKey.innerText = 'Activate Key';
        }
      });
    }

    if (elBtnContactEnt) {
      elBtnContactEnt.addEventListener('click', () => {
        alert('For Enterprise Fleet licensing, centralized policy sync, and silent MSI Intune deployment, please email: frankemesinwa@gmail.com');
      });
    }

    // ------------------ Phase 1: Transparent Proxy & Root CA UI ------------------
    const switchSystemProxy = document.getElementById('switch-system-proxy');
    const settingsProxyToggle = document.getElementById('settings-proxy-toggle');
    const settingsCaPill = document.getElementById('settings-ca-pill');
    const btnToggleCa = document.getElementById('btn-toggle-ca');
    const systemProxyHint = document.getElementById('system-proxy-hint');

    let currentProxyStatus = {
      system_proxy_enabled: false,
      ca_installed: false,
      host: '127.0.0.1',
      port: 8888
    };

    function updateProxyUI(data) {
      currentProxyStatus = data;
      const isEnabled = Boolean(data.system_proxy_enabled);
      const isCaInstalled = Boolean(data.ca_installed);

      [switchSystemProxy, settingsProxyToggle].forEach(sw => {
        if (!sw) return;
        sw.setAttribute('aria-checked', isEnabled ? 'true' : 'false');
        if (isEnabled) {
          sw.classList.add('active');
        } else {
          sw.classList.remove('active');
        }
      });

      if (systemProxyHint) {
        if (isEnabled) {
          systemProxyHint.innerHTML = `<span style="color: var(--emerald);">● Active:</span> Intercepting AI traffic on <b>${data.host}:${data.port}</b>.`;
        } else {
          systemProxyHint.innerHTML = `Transparent AI interception on <b>${data.host}:${data.port}</b> (OpenAI, Anthropic, Gemini, Cursor).`;
        }
      }

      if (settingsCaPill) {
        if (isCaInstalled) {
          settingsCaPill.textContent = 'TRUSTED';
          settingsCaPill.className = 'pill ok';
        } else {
          settingsCaPill.textContent = 'NOT INSTALLED';
          settingsCaPill.className = 'pill bad';
        }
      }

      if (btnToggleCa) {
        btnToggleCa.textContent = isCaInstalled ? 'Uninstall CA' : 'Install CA';
        btnToggleCa.className = isCaInstalled ? 'btn btn-secondary btn-sm' : 'btn btn-primary btn-sm';
      }
    }

    async function fetchProxyStatus() {
      try {
        const res = await fetch('/api/proxy/status');
        if (res.ok) {
          const data = await res.json();
          updateProxyUI(data);
        }
      } catch (err) {
        console.debug('Failed to fetch proxy status:', err);
      }
    }

    async function toggleSystemProxy() {
      [switchSystemProxy, settingsProxyToggle].forEach(sw => {
        if (sw) sw.disabled = true;
      });

      try {
        const res = await fetch('/api/proxy/toggle', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          showToast(
            data.enabled ? 'System Proxy Activated' : 'System Proxy Deactivated',
            data.enabled ? 'ok' : 'info',
            data.message
          );
          fetchProxyStatus();
        } else {
          showToast('Proxy Error', 'bad', data.detail || 'Could not toggle system proxy.');
        }
      } catch (err) {
        showToast('Network Error', 'bad', err.message);
      } finally {
        [switchSystemProxy, settingsProxyToggle].forEach(sw => {
          if (sw) sw.disabled = false;
        });
      }
    }

    if (switchSystemProxy) {
      switchSystemProxy.addEventListener('click', toggleSystemProxy);
    }
    if (settingsProxyToggle) {
      settingsProxyToggle.addEventListener('click', toggleSystemProxy);
    }

    if (btnToggleCa) {
      btnToggleCa.addEventListener('click', async () => {
        btnToggleCa.disabled = true;
        const action = currentProxyStatus.ca_installed ? 'uninstall' : 'install';
        try {
          const res = await fetch(`/api/proxy/ca/${action}`, { method: 'POST' });
          const data = await res.json();
          if (res.ok && data.success) {
            showToast(
              action === 'install' ? 'Root CA Installed' : 'Root CA Removed',
              'ok',
              data.message
            );
          } else {
            showToast('CA Operation Note', 'warn', data.message || 'Operation did not complete.');
          }
        } catch (err) {
          showToast('CA Error', 'bad', err.message);
        } finally {
          btnToggleCa.disabled = false;
          fetchProxyStatus();
        }
      });
    }

    fetchProxyStatus();

    updateCurrencyDisplay();
    fetchBillingStatus();
  }

  // Boot on DOM ready
  window.addEventListener('DOMContentLoaded', init);
})();
