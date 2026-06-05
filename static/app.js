/* ============================
 *  工具函数
 * ============================ */

function showToast(message, type = 'info') {
  const colors = {
    success: 'bg-emerald-500',
    error: 'bg-red-500',
    warning: 'bg-amber-500',
    info: 'bg-blue-500'
  };
  const icons = {
    success: 'fa-circle-check',
    error: 'fa-circle-xmark',
    warning: 'fa-triangle-exclamation',
    info: 'fa-circle-info'
  };
  const toast = document.createElement('div');
  toast.className = `toast flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg text-white ${colors[type]} min-w-[260px]`;
  toast.innerHTML = `<i class="fas ${icons[type]}"></i><span>${message}</span>`;
  document.getElementById('toastContainer').appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s, transform 0.3s';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 2800);
}

function formatDate(dtStr) {
  if (!dtStr) return '-';
  try {
    const d = new Date(dtStr);
    if (isNaN(d.getTime())) return dtStr;
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  } catch { return dtStr; }
}

function severityClass(severity) {
  const map = { critical: 'text-white bg-red-600', high: 'text-white bg-orange-500', medium: 'text-white bg-amber-500', low: 'text-slate-700 bg-yellow-300' };
  return map[severity] || 'bg-slate-300';
}

function severityLabel(severity) {
  const map = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
  return map[severity] || severity;
}

function severityBadge(severity) {
  return `<span class="inline-block px-2 py-0.5 rounded text-xs font-medium ${severityClass(severity)}">${severityLabel(severity)}</span>`;
}

function statusBadge(status, type = 'vuln') {
  const maps = {
    vuln: { active: ['活跃', 'bg-blue-100 text-blue-700'], mitigated: ['已缓解', 'bg-amber-100 text-amber-700'], fixed: ['已修复', 'bg-emerald-100 text-emerald-700'], closed: ['已关闭', 'bg-slate-100 text-slate-600'], pending: ['待修复', 'bg-slate-100 text-slate-600'], verifying: ['验证中', 'bg-purple-100 text-purple-700'] },
    wo: { pending: ['待修复', 'bg-slate-100 text-slate-600'], fixing: ['修复中', 'bg-blue-100 text-blue-700'], fixed: ['已修复', 'bg-amber-100 text-amber-700'], verifying: ['验证中', 'bg-purple-100 text-purple-700'], closed: ['已关闭', 'bg-emerald-100 text-emerald-700'] },
    inc: { open: ['待处理', 'bg-red-100 text-red-700'], investigating: ['调查中', 'bg-blue-100 text-blue-700'], contained: ['已遏制', 'bg-amber-100 text-amber-700'], eradicated: ['已根除', 'bg-purple-100 text-purple-700'], recovered: ['已恢复', 'bg-cyan-100 text-cyan-700'], closed: ['已关闭', 'bg-slate-100 text-slate-600'], mitigating: ['已遏制', 'bg-amber-100 text-amber-700'], resolving: ['已修复', 'bg-emerald-100 text-emerald-700'] },
    rp: { created: ['已创建', 'bg-slate-100 text-slate-600'], confirmed: ['已确认', 'bg-blue-100 text-blue-700'], executing: ['执行中', 'bg-amber-100 text-amber-700'], completed: ['已完成', 'bg-emerald-100 text-emerald-700'], closed: ['已关闭', 'bg-slate-100 text-slate-600'] },
    rt: { pending_analysis: ['待分析', 'bg-slate-100 text-slate-600'], in_analysis: ['分析中', 'bg-blue-100 text-blue-700'], completed: ['已完成', 'bg-emerald-100 text-emerald-700'], confirmed: ['已确认', 'bg-purple-100 text-purple-700'] }
  };
  const m = maps[type] || {};
  const s = m[status] || [status, 'bg-slate-100 text-slate-600'];
  return `<span class="inline-block px-2 py-0.5 rounded text-xs font-medium ${s[1]}">${s[0]}</span>`;
}

function stars(n, max = 5) {
  const full = Math.round(n / 2);
  let html = '';
  for (let i = 0; i < max; i++) {
    html += `<i class="fas fa-star ${i < full ? 'text-yellow-400' : 'text-slate-300'}"></i>`;
  }
  return html;
}

function renderPagination(containerId, total, page, pageSize, onPage) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const container = document.getElementById(containerId);
  if (!container) return;
  const btns = [];
  const start = Math.max(1, page - 2);
  const end = Math.min(totalPages, page + 2);
  btns.push(`<button class="px-3 py-1 rounded border text-sm ${page === 1 ? 'text-slate-300 border-slate-200 cursor-not-allowed' : 'hover:bg-slate-100 border-slate-300'}" ${page === 1 ? 'disabled' : ''} data-p="${page - 1}"><i class="fas fa-chevron-left"></i></button>`);
  for (let i = start; i <= end; i++) {
    btns.push(`<button class="px-3 py-1 rounded border text-sm ${i === page ? 'bg-blue-600 text-white border-blue-600' : 'hover:bg-slate-100 border-slate-300'}" data-p="${i}">${i}</button>`);
  }
  btns.push(`<button class="px-3 py-1 rounded border text-sm ${page === totalPages ? 'text-slate-300 border-slate-200 cursor-not-allowed' : 'hover:bg-slate-100 border-slate-300'}" ${page === totalPages ? 'disabled' : ''} data-p="${page + 1}"><i class="fas fa-chevron-right"></i></button>`);
  container.innerHTML = `<span class="text-sm text-slate-500">共 ${total} 条，第 ${page}/${totalPages} 页</span><div class="flex gap-1">${btns.join('')}</div>`;
  container.querySelectorAll('button[data-p]').forEach(b => {
    b.addEventListener('click', () => {
      if (b.disabled) return;
      onPage(parseInt(b.dataset.p));
    });
  });
}

function showModal(title, bodyHtml, footerHtml = '', size = 'md') {
  const sizes = { sm: 'max-w-md', md: 'max-w-2xl', lg: 'max-w-4xl', xl: 'max-w-6xl' };
  const container = document.getElementById('modalContainer');
  const id = 'modal_' + Date.now();
  container.innerHTML = `
    <div id="${id}" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div class="bg-white rounded-xl shadow-2xl w-full ${sizes[size]} max-h-[90vh] flex flex-col">
        <div class="px-6 py-4 border-b border-slate-200 flex items-center justify-between shrink-0">
          <h3 class="font-semibold text-lg">${title}</h3>
          <button class="modal-close p-1 hover:bg-slate-100 rounded"><i class="fas fa-xmark"></i></button>
        </div>
        <div class="px-6 py-4 overflow-auto flex-1">${bodyHtml}</div>
        ${footerHtml ? `<div class="px-6 py-3 border-t border-slate-200 flex justify-end gap-2 shrink-0">${footerHtml}</div>` : ''}
      </div>
    </div>`;
  const close = () => document.getElementById(id)?.remove();
  document.getElementById(id).addEventListener('click', e => { if (e.target.id === id) close(); });
  document.getElementById(id).querySelectorAll('.modal-close').forEach(b => b.addEventListener('click', close));
  return { el: document.getElementById(id), close };
}

/* ============================
 *  API 客户端
 * ============================ */

const apiClient = {
  async request(url, options = {}) {
    const token = localStorage.getItem('auth_token');
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    try {
      const res = await fetch(url, { ...options, headers });
      const data = await res.json().catch(() => ({ code: -1, message: '响应解析失败' }));
      if (res.status === 401) {
        localStorage.removeItem('auth_token');
        location.reload();
        return data;
      }
      return data;
    } catch (e) {
      showToast('网络错误: ' + e.message, 'error');
      return { code: -1, message: e.message };
    }
  },
  get: (url, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return apiClient.request(url + (qs ? '?' + qs : ''));
  },
  post: (url, body = {}) => apiClient.request(url, { method: 'POST', body: JSON.stringify(body) }),
  put: (url, body = {}) => apiClient.request(url, { method: 'PUT', body: JSON.stringify(body) }),
  delete: (url) => apiClient.request(url, { method: 'DELETE' })
};

function requireSuccess(data, successMsg) {
  if (data.code === 0) {
    if (successMsg) showToast(successMsg, 'success');
    return true;
  }
  showToast(data.message || '操作失败', 'error');
  return false;
}

/* ============================
 *  认证
 * ============================ */

function checkAuth() {
  return !!localStorage.getItem('auth_token');
}

async function doLogin(username, password) {
  const data = await apiClient.post('/api/auth/login', { username, password });
  if (data.code === 0 && data.data && data.data.token) {
    localStorage.setItem('auth_token', data.data.token);
    localStorage.setItem('auth_user', data.data.username || username);
    return true;
  }
  showToast(data.message || '登录失败', 'error');
  return false;
}

function doLogout() {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_user');
  location.reload();
}

function showLoginModal() {
  const body = `
    <div class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">用户名</label>
        <input id="loginUser" type="text" value="admin" class="w-full px-3 py-2 border border-slate-300 rounded focus:outline-none focus:border-blue-500">
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">密码</label>
        <input id="loginPass" type="password" value="admin" class="w-full px-3 py-2 border border-slate-300 rounded focus:outline-none focus:border-blue-500">
      </div>
      <p class="text-sm text-slate-500">默认账号: admin / admin</p>
    </div>`;
  const m = showModal('登录', body, `<button id="loginBtn" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">登录</button>`, 'sm');
  m.el.querySelector('#loginBtn').addEventListener('click', async () => {
    const u = m.el.querySelector('#loginUser').value;
    const p = m.el.querySelector('#loginPass').value;
    const ok = await doLogin(u, p);
    if (ok) { m.close(); showToast('登录成功', 'success'); initApp(); }
  });
  m.el.addEventListener('keydown', e => { if (e.key === 'Enter') m.el.querySelector('#loginBtn').click(); });
}

/* ============================
 *  导航
 * ============================ */

let currentView = 'dashboard';

function switchView(view) {
  currentView = view;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  document.querySelectorAll('section.view').forEach(el => el.classList.toggle('hidden', el.id !== 'view-' + view));
  const loader = {
    dashboard: loadDashboard,
    vulnerabilities: loadVulnerabilities,
    'work-orders': loadWorkOrders,
    assets: loadAssets,
    incidents: loadIncidents,
    'response-plans': loadResponsePlans,
    'review-tasks': loadReviewTasks,
    reports: loadReports
  };
  (loader[view] || loadDashboard)();
}

/* ============================
 *  仪表盘
 * ============================ */

let dashboardCharts = {};

async function loadDashboard() {
  const summary = await apiClient.get('/api/dashboard/summary');
  if (summary.code === 0 && summary.data) {
    const d = summary.data;
    document.getElementById('kpiTotal').textContent = d.total_vulns ?? 0;
    document.getElementById('kpiPending').textContent = d.pending_vulns ?? 0;
    document.getElementById('kpiFixRate').textContent = ((d.fix_rate ?? 0) * 100).toFixed(1) + '%';
    document.getElementById('kpiOverdue').textContent = d.overdue_work_orders ?? 0;
    document.getElementById('kpiToday').textContent = d.today_new ?? 0;
    document.getElementById('kpiAvgFix').textContent = (d.avg_fix_hours ?? 0).toFixed(1) + 'h';
  }
  const sevDist = await apiClient.get('/api/dashboard/severity-distribution');
  if (sevDist.code === 0) renderPieChart('chartSeverity', sevDist.data || []);
  const trend = await apiClient.get('/api/dashboard/trend');
  if (trend.code === 0) renderTrendChart('chartTrend', trend.data || []);
  const dept = await apiClient.get('/api/dashboard/department-stats');
  if (dept.code === 0) renderBarChart('chartDept', dept.data || []);
  const woStage = await apiClient.get('/api/dashboard/workorder-stage');
  if (woStage.code === 0) renderDoughnutChart('chartWO', woStage.data || []);
}

function renderPieChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (dashboardCharts[canvasId]) dashboardCharts[canvasId].destroy();
  const labels = data.map(x => severityLabel(x.name) || x.name);
  const values = data.map(x => x.value);
  const colors = { critical: '#dc2626', high: '#f97316', medium: '#f59e0b', low: '#fde047' };
  dashboardCharts[canvasId] = new Chart(ctx, {
    type: 'pie',
    data: { labels, datasets: [{ data: values, backgroundColor: data.map(x => colors[x.name] || '#94a3b8') }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
  });
}

function renderDoughnutChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (dashboardCharts[canvasId]) dashboardCharts[canvasId].destroy();
  const statusLabels = { pending: '待修复', fixing: '修复中', fixed: '已修复', verifying: '验证中', closed: '已关闭' };
  const labels = data.map(x => statusLabels[x.name] || x.name);
  const values = data.map(x => x.value);
  dashboardCharts[canvasId] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: values, backgroundColor: ['#64748b', '#3b82f6', '#f59e0b', '#a855f7', '#10b981'] }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
  });
}

function renderTrendChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (dashboardCharts[canvasId]) dashboardCharts[canvasId].destroy();
  const labels = data.map(x => x.date);
  dashboardCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: '新增', data: data.map(x => x.new || 0), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.3 },
        { label: '修复', data: data.map(x => x.fixed || 0), borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.3 }
      ]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
  });
}

function renderBarChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (dashboardCharts[canvasId]) dashboardCharts[canvasId].destroy();
  const labels = data.map(x => x.department || x.name);
  const values = data.map(x => ((x.fix_rate ?? 0) * 100).toFixed(1));
  dashboardCharts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: '修复率 %', data: values, backgroundColor: '#3b82f6' }] },
    options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, max: 100 } } }
  });
}

/* ============================
 *  漏洞管理
 * ============================ */

const vulnState = { page: 1, pageSize: 20, total: 0, filters: {} };

async function loadVulnerabilities() {
  const params = { page: vulnState.page, page_size: vulnState.pageSize, ...vulnState.filters };
  const data = await apiClient.get('/api/vulnerabilities', params);
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-vulnerabilities tbody');
  tbody.innerHTML = items.map(v => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">${v.id}</td>
      <td class="px-3 py-2 text-sm">${v.cve_id || '-'}</td>
      <td class="px-3 py-2 text-sm max-w-[260px] truncate">${v.title || (v.vulnerability && v.vulnerability.title) || '-'}</td>
      <td class="px-3 py-2">${severityBadge(v.severity || (v.vulnerability && v.vulnerability.severity))}</td>
      <td class="px-3 py-2 text-sm text-center font-semibold">${v.risk_score ?? '-'}</td>
      <td class="px-3 py-2 text-sm">${v.asset_name || (v.asset && v.asset.name) || '-'}</td>
      <td class="px-3 py-2 text-sm">${v.asset_ip || (v.asset && v.asset.ip) || '-'}</td>
      <td class="px-3 py-2">${statusBadge(v.fix_status || v.status, 'vuln')}</td>
      <td class="px-3 py-2 text-sm">${formatDate(v.fix_deadline || v.discovered_at)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="view" data-id="${v.id}">查看</button>
        <button class="text-emerald-600 hover:underline mr-2" data-act="scan" data-id="${v.id}">扫描</button>
        <button class="text-red-600 hover:underline" data-act="del" data-id="${v.id}">删除</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="10" class="text-center py-8 text-slate-400">暂无数据</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', () => handleVulnAction(b.dataset.act, b.dataset.id)));
  vulnState.total = data.data.total || 0;
  renderPagination('vulnPagination', vulnState.total, vulnState.page, vulnState.pageSize, p => { vulnState.page = p; loadVulnerabilities(); });
}

function handleVulnFilters() {
  vulnState.filters = {
    keyword: document.getElementById('vulnFKeyword').value,
    severity: document.getElementById('vulnFSeverity').value,
    status: document.getElementById('vulnFStatus').value
  };
  vulnState.page = 1;
  loadVulnerabilities();
}

async function handleVulnAction(act, id) {
  if (act === 'del') {
    if (!confirm('确认删除该漏洞？')) return;
    const r = await apiClient.delete(`/api/vulnerabilities/${id}`);
    if (requireSuccess(r, '删除成功')) loadVulnerabilities();
  } else if (act === 'scan') {
    const r = await apiClient.post(`/api/vulnerabilities/${id}/trigger-scan`);
    requireSuccess(r, '已触发重新扫描');
  } else if (act === 'view') {
    const data = await apiClient.get(`/api/vulnerabilities/${id}`);
    if (data.code !== 0) return;
    const v = data.data;
    const vuln = v.vulnerability || {};
    const asset = v.asset || {};
    showModal('漏洞详情', `
      <div class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div><b>ID:</b> ${v.id}</div>
          <div><b>CVE:</b> ${v.cve_id || vuln.cve_id || '-'}</div>
          <div class="col-span-2"><b>标题:</b> ${v.title || vuln.title || '-'}</div>
          <div><b>严重等级:</b> ${severityBadge(v.severity || vuln.severity)}</div>
          <div><b>风险分:</b> ${v.risk_score ?? '-'}</div>
          <div><b>资产:</b> ${asset.name || v.asset_name || '-'}</div>
          <div><b>IP:</b> ${asset.ip || v.asset_ip || '-'}</div>
          <div><b>状态:</b> ${statusBadge(v.fix_status || v.status, 'vuln')}</div>
          <div><b>修复截止:</b> ${formatDate(v.fix_deadline)}</div>
          <div class="col-span-2"><b>描述:</b> ${v.description || vuln.description || '-'}</div>
        </div>
      </div>`, '', 'lg');
  }
}

/* ============================
 *  工单管理
 * ============================ */

const woState = { page: 1, pageSize: 20, total: 0, filters: {} };

async function loadWorkOrders() {
  const params = { page: woState.page, page_size: woState.pageSize, ...woState.filters };
  const data = await apiClient.get('/api/work-orders', params);
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-work-orders tbody');
  tbody.innerHTML = items.map(w => `
    <tr class="border-b hover:bg-slate-50 ${w.is_overdue || w.is_timeout ? 'bg-red-50' : ''}">
      <td class="px-3 py-2 text-sm font-mono">#${w.id}</td>
      <td class="px-3 py-2 text-sm max-w-[260px] truncate">${w.vuln_title || (w.vuln_instance && w.vuln_instance.vulnerability && w.vuln_instance.vulnerability.title) || '-'}</td>
      <td class="px-3 py-2 text-sm">${w.asset_name || (w.vuln_instance && w.vuln_instance.asset && w.vuln_instance.asset.name) || '-'}</td>
      <td class="px-3 py-2">${severityBadge(w.severity || (w.vuln_instance && w.vuln_instance.severity))}</td>
      <td class="px-3 py-2 text-sm">${w.assignee || '-'}</td>
      <td class="px-3 py-2">${statusBadge(w.status, 'wo')}</td>
      <td class="px-3 py-2 text-sm">${formatDate(w.created_at)}</td>
      <td class="px-3 py-2 text-sm">${formatDate(w.deadline)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="view" data-id="${w.id}">查看</button>
        <button class="text-emerald-600 hover:underline mr-2" data-act="status" data-id="${w.id}">流转</button>
        <button class="text-amber-600 hover:underline" data-act="assign" data-id="${w.id}">分配</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="9" class="text-center py-8 text-slate-400">暂无数据</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', () => handleWOAction(b.dataset.act, b.dataset.id)));
  woState.total = data.data.total || 0;
  renderPagination('woPagination', woState.total, woState.page, woState.pageSize, p => { woState.page = p; loadWorkOrders(); });
}

function handleWOFilters() {
  woState.filters = {
    status: document.getElementById('woFStatus').value,
    assignee: document.getElementById('woFAssignee').value,
    department: document.getElementById('woFDept').value,
    severity: document.getElementById('woFSeverity').value,
    overdue: document.getElementById('woFOverdue').checked ? '1' : ''
  };
  woState.page = 1;
  loadWorkOrders();
}

async function handleWOAction(act, id) {
  if (act === 'view') {
    const data = await apiClient.get(`/api/work-orders/${id}`);
    if (data.code !== 0) return;
    const w = data.data;
    const vi = w.vuln_instance || {};
    const v = vi.vulnerability || {};
    showModal(`工单 #${id} 详情`, `
      <div class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div><b>工单ID:</b> #${w.id}</div>
          <div><b>状态:</b> ${statusBadge(w.status, 'wo')}</div>
          <div class="col-span-2"><b>漏洞:</b> ${v.title || vi.title || '-'}</div>
          <div><b>严重等级:</b> ${severityBadge(w.severity || vi.severity || v.severity)}</div>
          <div><b>风险分:</b> ${vi.risk_score ?? '-'}</div>
          <div><b>负责人:</b> ${w.assignee || '-'}</div>
          <div><b>升级等级:</b> ${w.escalation_level || 0}</div>
          <div><b>创建时间:</b> ${formatDate(w.created_at)}</div>
          <div><b>截止时间:</b> ${formatDate(w.deadline)}</div>
          <div><b>修复时间:</b> ${formatDate(w.fixed_at)}</div>
          <div><b>关闭时间:</b> ${formatDate(w.closed_at)}</div>
        </div>
      </div>`, '', 'lg');
  } else if (act === 'status') {
    const r = await apiClient.get(`/api/work-orders/${id}`);
    if (r.code !== 0) return;
    const cur = r.data.status;
    const vs = await apiClient.get(`/api/work-orders/valid-statuses/${cur}`);
    const nextList = (vs.code === 0 && vs.data) ? vs.data : [];
    const body = `
      <div class="space-y-3">
        <div class="text-sm text-slate-600">当前状态: <b>${cur}</b></div>
        <div>
          <label class="block text-sm font-medium mb-1">目标状态</label>
          <select id="woNewStatus" class="w-full px-3 py-2 border border-slate-300 rounded">
            ${nextList.map(s => `<option value="${s}">${s}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">变更理由</label>
          <input id="woReason" type="text" class="w-full px-3 py-2 border border-slate-300 rounded" placeholder="可选">
        </div>
      </div>`;
    const m = showModal('工单状态流转', body, `<button id="woStatusOk" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">确认</button>`, 'sm');
    m.el.querySelector('#woStatusOk').addEventListener('click', async () => {
      const ns = m.el.querySelector('#woNewStatus').value;
      const reason = m.el.querySelector('#woReason').value;
      const r2 = await apiClient.post(`/api/work-orders/${id}/status`, { new_status: ns, operator: 'admin', reason });
      if (requireSuccess(r2, '状态已更新')) { m.close(); loadWorkOrders(); }
    });
  } else if (act === 'assign') {
    const body = `
      <div class="space-y-3">
        <div>
          <label class="block text-sm font-medium mb-1">新负责人</label>
          <input id="woNewAssignee" type="text" class="w-full px-3 py-2 border border-slate-300 rounded" placeholder="输入用户名">
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">分配理由</label>
          <input id="woAssignReason" type="text" class="w-full px-3 py-2 border border-slate-300 rounded" placeholder="可选">
        </div>
      </div>`;
    const m = showModal('重新分配工单', body, `<button id="woAssignOk" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">确认</button>`, 'sm');
    m.el.querySelector('#woAssignOk').addEventListener('click', async () => {
      const assignee = m.el.querySelector('#woNewAssignee').value;
      const reason = m.el.querySelector('#woAssignReason').value;
      if (!assignee) { showToast('请输入负责人', 'warning'); return; }
      const r2 = await apiClient.post(`/api/work-orders/${id}/assign`, { assignee, operator: 'admin', reason });
      if (requireSuccess(r2, '已重新分配')) { m.close(); loadWorkOrders(); }
    });
  }
}

/* ============================
 *  资产管理
 * ============================ */

const assetState = { page: 1, pageSize: 20, total: 0, filters: {} };

async function loadAssets() {
  const params = { page: assetState.page, page_size: assetState.pageSize, ...assetState.filters };
  const data = await apiClient.get('/api/assets', params);
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-assets tbody');
  tbody.innerHTML = items.map(a => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">${a.id}</td>
      <td class="px-3 py-2 text-sm font-medium">${a.name}</td>
      <td class="px-3 py-2 text-sm font-mono">${a.ip || '-'}</td>
      <td class="px-3 py-2 text-sm">${a.type || '-'}</td>
      <td class="px-3 py-2 text-sm">${stars(a.importance || 0)}</td>
      <td class="px-3 py-2 text-sm">${a.owner || '-'}</td>
      <td class="px-3 py-2 text-sm">${a.department || '-'}</td>
      <td class="px-3 py-2 text-sm text-center font-semibold ${(a.vuln_count || 0) > 5 ? 'text-red-600' : ''}">${a.vuln_count || 0}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="edit" data-id="${a.id}">编辑</button>
        <button class="text-red-600 hover:underline" data-act="del" data-id="${a.id}">删除</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="9" class="text-center py-8 text-slate-400">暂无数据</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', () => handleAssetAction(b.dataset.act, b.dataset.id)));
  assetState.total = data.data.total || 0;
  renderPagination('assetPagination', assetState.total, assetState.page, assetState.pageSize, p => { assetState.page = p; loadAssets(); });
}

function handleAssetFilters() {
  assetState.filters = {
    keyword: document.getElementById('assetFKeyword').value,
    type: document.getElementById('assetFType').value,
    importance: document.getElementById('assetFImportance').value,
    department: document.getElementById('assetFDept').value
  };
  assetState.page = 1;
  loadAssets();
}

async function showAssetForm(asset = null) {
  const body = `
    <div class="space-y-3">
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-sm font-medium mb-1">资产名称 *</label>
          <input id="aName" type="text" value="${asset?.name || ''}" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">IP地址</label>
          <input id="aIp" type="text" value="${asset?.ip || ''}" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">资产类型</label>
          <select id="aType" class="w-full px-3 py-2 border border-slate-300 rounded">
            ${['web_server', 'database', 'application', 'middleware', 'network', 'storage', 'other'].map(t => `<option value="${t}" ${asset?.type === t ? 'selected' : ''}>${t}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">重要性 (1-10)</label>
          <input id="aImp" type="number" min="1" max="10" value="${asset?.importance || 5}" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">负责人</label>
          <input id="aOwner" type="text" value="${asset?.owner || ''}" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">所属部门</label>
          <input id="aDept" type="text" value="${asset?.department || ''}" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">描述</label>
        <textarea id="aDesc" class="w-full px-3 py-2 border border-slate-300 rounded" rows="3">${asset?.description || ''}</textarea>
      </div>
    </div>`;
  const m = showModal(asset ? '编辑资产' : '新增资产', body, `<button id="aSave" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">保存</button>`, 'lg');
  m.el.querySelector('#aSave').addEventListener('click', async () => {
    const payload = {
      name: m.el.querySelector('#aName').value,
      ip: m.el.querySelector('#aIp').value,
      type: m.el.querySelector('#aType').value,
      importance: parseInt(m.el.querySelector('#aImp').value) || 5,
      owner: m.el.querySelector('#aOwner').value,
      department: m.el.querySelector('#aDept').value,
      description: m.el.querySelector('#aDesc').value
    };
    if (!payload.name) { showToast('请填写资产名称', 'warning'); return; }
    const r = asset ? await apiClient.put(`/api/assets/${asset.id}`, payload) : await apiClient.post('/api/assets', payload);
    if (requireSuccess(r, asset ? '已更新' : '已创建')) { m.close(); loadAssets(); }
  });
}

async function handleAssetAction(act, id) {
  if (act === 'del') {
    if (!confirm('确认删除该资产？')) return;
    const r = await apiClient.delete(`/api/assets/${id}`);
    if (requireSuccess(r, '删除成功')) loadAssets();
  } else if (act === 'edit') {
    const r = await apiClient.get(`/api/assets/${id}`);
    if (r.code === 0) showAssetForm(r.data);
  }
}

/* ============================
 *  安全事件
 * ============================ */

const incState = { page: 1, pageSize: 20, total: 0, filters: {} };

async function loadIncidents() {
  const params = { page: incState.page, page_size: incState.pageSize, ...incState.filters };
  const data = await apiClient.get('/api/incidents', params);
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-incidents tbody');
  tbody.innerHTML = items.map(i => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">#${i.id}</td>
      <td class="px-3 py-2 text-sm font-medium">${i.title}</td>
      <td class="px-3 py-2 text-sm">${i.type || '-'}</td>
      <td class="px-3 py-2">${severityBadge(i.severity)}</td>
      <td class="px-3 py-2">${statusBadge(i.status, 'inc')}</td>
      <td class="px-3 py-2 text-sm text-center">${(i.assets_affected || []).length || i.affected_assets_count || 0}</td>
      <td class="px-3 py-2 text-sm">${formatDate(i.created_at)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="view" data-id="${i.id}">查看</button>
        <button class="text-emerald-600 hover:underline mr-2" data-act="status" data-id="${i.id}">状态</button>
        <button class="text-red-600 hover:underline" data-act="del" data-id="${i.id}">删除</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="8" class="text-center py-8 text-slate-400">暂无数据</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', () => handleIncAction(b.dataset.act, b.dataset.id)));
  incState.total = data.data.total || 0;
  renderPagination('incPagination', incState.total, incState.page, incState.pageSize, p => { incState.page = p; loadIncidents(); });
}

function handleIncFilters() {
  incState.filters = {
    type: document.getElementById('incFType').value,
    severity: document.getElementById('incFSeverity').value,
    status: document.getElementById('incFStatus').value
  };
  incState.page = 1;
  loadIncidents();
}

async function showIncForm() {
  const body = `
    <div class="space-y-3">
      <div>
        <label class="block text-sm font-medium mb-1">事件标题 *</label>
        <input id="iTitle" type="text" class="w-full px-3 py-2 border border-slate-300 rounded">
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div>
          <label class="block text-sm font-medium mb-1">类型</label>
          <select id="iType" class="w-full px-3 py-2 border border-slate-300 rounded">
            ${['data_breach', 'intrusion', 'ransomware', 'ddos', 'compliance_violation', 'other'].map(t => `<option value="${t}">${t}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">严重等级</label>
          <select id="iSev" class="w-full px-3 py-2 border border-slate-300 rounded">
            <option value="low">低危</option><option value="medium">中危</option><option value="high">高危</option><option value="critical">严重</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">负责人</label>
          <input id="iAs" type="text" value="admin" class="w-full px-3 py-2 border border-slate-300 rounded">
        </div>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1">描述</label>
        <textarea id="iDesc" rows="4" class="w-full px-3 py-2 border border-slate-300 rounded"></textarea>
      </div>
    </div>`;
  const m = showModal('创建安全事件', body, `<button id="iSave" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">创建</button>`, 'lg');
  m.el.querySelector('#iSave').addEventListener('click', async () => {
    const payload = {
      title: m.el.querySelector('#iTitle').value,
      type: m.el.querySelector('#iType').value,
      severity: m.el.querySelector('#iSev').value,
      assigned_to: m.el.querySelector('#iAs').value,
      description: m.el.querySelector('#iDesc').value,
      created_by: 'admin',
      assets_affected: []
    };
    if (!payload.title) { showToast('请填写标题', 'warning'); return; }
    const r = await apiClient.post('/api/incidents', payload);
    if (requireSuccess(r, '事件已创建')) { m.close(); loadIncidents(); }
  });
}

async function handleIncAction(act, id) {
  if (act === 'del') {
    if (!confirm('确认删除该事件？')) return;
    const r = await apiClient.delete(`/api/incidents/${id}`);
    if (requireSuccess(r, '删除成功')) loadIncidents();
  } else if (act === 'view') {
    const r = await apiClient.get(`/api/incidents/${id}`);
    if (r.code !== 0) return;
    const i = r.data;
    const tl = i.timeline || [];
    showModal(`事件详情 #${id}`, `
      <div class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div><b>标题:</b> ${i.title}</div>
          <div><b>类型:</b> ${i.type}</div>
          <div><b>严重等级:</b> ${severityBadge(i.severity)}</div>
          <div><b>状态:</b> ${statusBadge(i.status, 'inc')}</div>
          <div><b>创建人:</b> ${i.created_by || '-'}</div>
          <div><b>负责人:</b> ${i.assigned_to || '-'}</div>
          <div class="col-span-2"><b>描述:</b> ${i.description || '-'}</div>
        </div>
        <div>
          <h4 class="font-medium mb-2">时间线</h4>
          <div class="space-y-2 border-l-2 border-slate-200 pl-4">
            ${tl.map(t => `
              <div class="relative">
                <div class="absolute -left-[21px] top-1 w-3 h-3 rounded-full bg-blue-500"></div>
                <div class="text-xs text-slate-500">${formatDate(t.created_at)} · ${t.event_type} · ${t.operator || '-'}</div>
                <div class="text-sm">${t.description}</div>
              </div>
            `).join('') || '<div class="text-slate-400 text-sm">暂无记录</div>'}
          </div>
        </div>
      </div>`, '', 'lg');
  } else if (act === 'status') {
    const statusList = ['open', 'investigating', 'mitigating', 'resolving', 'closed'];
    const body = `
      <div>
        <label class="block text-sm font-medium mb-1">目标状态</label>
        <select id="iNewStatus" class="w-full px-3 py-2 border border-slate-300 rounded">
          ${statusList.map(s => `<option value="${s}">${s}</option>`).join('')}
        </select>
      </div>`;
    const m = showModal('更新事件状态', body, `<button id="iStatusOk" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">确认</button>`, 'sm');
    m.el.querySelector('#iStatusOk').addEventListener('click', async () => {
      const ns = m.el.querySelector('#iNewStatus').value;
      const r2 = await apiClient.post(`/api/incidents/${id}/status`, { new_status: ns, operator: 'admin' });
      if (requireSuccess(r2, '状态已更新')) { m.close(); loadIncidents(); }
    });
  }
}

/* ============================
 *  应急预案 & 复盘任务 & 报表
 * ============================ */

const rpState = { page: 1, pageSize: 20, total: 0 };
const rtState = { page: 1, pageSize: 20, total: 0 };

async function loadResponsePlans() {
  const data = await apiClient.get('/api/response-plans', { page: rpState.page, page_size: rpState.pageSize });
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-response-plans tbody');
  tbody.innerHTML = items.map(p => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">#${p.id}</td>
      <td class="px-3 py-2 text-sm">${p.vuln_type || '-'}</td>
      <td class="px-3 py-2">${statusBadge(p.status, 'rp')}</td>
      <td class="px-3 py-2 text-sm">${formatDate(p.created_at)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="view" data-id="${p.id}">查看</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="5" class="text-center py-8 text-slate-400">暂无应急预案</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', async () => {
    const r = await apiClient.get(`/api/response-plans/${b.dataset.id}`);
    if (r.code !== 0) return;
    const p = r.data;
    showModal(`应急预案 #${p.id}`, `
      <div class="space-y-3 text-sm">
        <div class="grid grid-cols-2 gap-3">
          <div><b>ID:</b> #${p.id}</div>
          <div><b>状态:</b> ${statusBadge(p.status, 'rp')}</div>
          <div><b>漏洞类型:</b> ${p.vuln_type || '-'}</div>
          <div><b>触发原因:</b> ${p.trigger_reason || '-'}</div>
        </div>
        <div>
          <b>隔离建议:</b>
          <ul class="list-disc pl-5 mt-1 space-y-1">${(p.isolation_measures || []).map((m,i) => `<li>${m.content || m.description || m}${m.completed ? ' ✅' : ''}</li>`).join('') || '<li class="text-slate-400">-</li>'}</ul>
        </div>
        <div>
          <b>临时缓解措施:</b>
          <ul class="list-disc pl-5 mt-1 space-y-1">${(p.mitigation_measures || []).map((m,i) => `<li>${m.content || m.description || m}${m.completed ? ' ✅' : ''}</li>`).join('') || '<li class="text-slate-400">-</li>'}</ul>
        </div>
        <div class="col-span-2"><b>根本修复方案:</b><p class="mt-1 text-slate-600">${p.root_fix_plan || '-'}</p></div>
      </div>`, '', 'lg');
  }));
  rpState.total = data.data.total || 0;
  renderPagination('rpPagination', rpState.total, rpState.page, rpState.pageSize, p => { rpState.page = p; loadResponsePlans(); });
}

async function loadReviewTasks() {
  const data = await apiClient.get('/api/review-tasks', { page: rtState.page, page_size: rtState.pageSize });
  if (data.code !== 0) return;
  const items = data.data.items || [];
  const tbody = document.querySelector('#view-review-tasks tbody');
  tbody.innerHTML = items.map(t => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">#${t.id}</td>
      <td class="px-3 py-2 text-sm">${t.reason || '-'}</td>
      <td class="px-3 py-2">${statusBadge(t.status, 'rt')}</td>
      <td class="px-3 py-2 text-sm">${formatDate(t.deadline)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        <button class="text-blue-600 hover:underline mr-2" data-act="edit" data-id="${t.id}">编辑</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="5" class="text-center py-8 text-slate-400">暂无复盘任务</td></tr>';
  tbody.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', async () => {
    const r = await apiClient.get(`/api/review-tasks/${b.dataset.id}`);
    if (r.code !== 0) return;
    const t = r.data;
    const body = `
      <div class="space-y-3">
        <div>
          <label class="block text-sm font-medium mb-1">根本原因</label>
          <textarea id="rtRoot" rows="3" class="w-full px-3 py-2 border border-slate-300 rounded">${t.root_cause || ''}</textarea>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">改进措施</label>
          <textarea id="rtImp" rows="3" class="w-full px-3 py-2 border border-slate-300 rounded">${t.improvement_measures || ''}</textarea>
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">状态</label>
          <select id="rtStatus" class="w-full px-3 py-2 border border-slate-300 rounded">
            ${['pending_analysis', 'in_analysis', 'completed', 'confirmed'].map(s => `<option value="${s}" ${t.status === s ? 'selected' : ''}>${s}</option>`).join('')}
          </select>
        </div>
      </div>`;
    const m = showModal('编辑复盘任务', body, `<button id="rtSave" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">保存</button>`, 'lg');
    m.el.querySelector('#rtSave').addEventListener('click', async () => {
      const payload = {
        root_cause: m.el.querySelector('#rtRoot').value,
        improvement_measures: m.el.querySelector('#rtImp').value,
        status: m.el.querySelector('#rtStatus').value
      };
      const r2 = await apiClient.put(`/api/review-tasks/${t.id}`, payload);
      if (requireSuccess(r2, '已保存')) { m.close(); loadReviewTasks(); }
    });
  }));
  rtState.total = data.data.total || 0;
  renderPagination('rtPagination', rtState.total, rtState.page, rtState.pageSize, p => { rtState.page = p; loadReviewTasks(); });
}

async function loadReports() {
  const data = await apiClient.get('/api/reports', { page_size: 50 });
  if (data.code !== 0) return;
  const items = data.data.items || data.data || [];
  const tbody = document.querySelector('#view-reports tbody');
  tbody.innerHTML = (Array.isArray(items) ? items : []).map(r => `
    <tr class="border-b hover:bg-slate-50">
      <td class="px-3 py-2 text-sm">#${r.id}</td>
      <td class="px-3 py-2 text-sm">${r.type === 'daily' ? '日报' : r.type === 'weekly' ? '周报' : r.type}</td>
      <td class="px-3 py-2 text-sm">${formatDate(r.period_start)} ~ ${formatDate(r.period_end)}</td>
      <td class="px-3 py-2 text-sm">${formatDate(r.generated_at)}</td>
      <td class="px-3 py-2 text-sm whitespace-nowrap">
        ${r.file_path_pdf ? `<a class="text-red-600 hover:underline mr-2" href="/api/reports/${r.id}/download?type=pdf" target="_blank">PDF</a>` : ''}
        ${r.file_path_excel ? `<a class="text-emerald-600 hover:underline" href="/api/reports/${r.id}/download?type=excel" target="_blank">Excel</a>` : ''}
      </td>
    </tr>
  `).join('') || '<tr><td colspan="5" class="text-center py-8 text-slate-400">暂无报表</td></tr>';
}

async function genReport(type) {
  const r = await apiClient.get(`/api/reports/generate?type=${type}`);
  if (requireSuccess(r, `报表生成任务已触发`)) loadReports();
}

/* ============================
 *  应用初始化
 * ============================ */

function initNav() {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', () => switchView(el.dataset.view));
  });
  // 过滤器
  document.getElementById('vulnFSearch')?.addEventListener('click', handleVulnFilters);
  document.getElementById('woFSearch')?.addEventListener('click', handleWOFilters);
  document.getElementById('assetFSearch')?.addEventListener('click', handleAssetFilters);
  document.getElementById('incFSearch')?.addEventListener('click', handleIncFilters);
  // 新增按钮
  document.getElementById('assetAddBtn')?.addEventListener('click', () => showAssetForm());
  document.getElementById('incAddBtn')?.addEventListener('click', () => showIncForm());
  document.getElementById('btnGenDaily')?.addEventListener('click', () => genReport('daily'));
  document.getElementById('btnGenWeekly')?.addEventListener('click', () => genReport('weekly'));
  document.getElementById('refreshBtn')?.addEventListener('click', () => switchView(currentView));
  document.getElementById('logoutBtn')?.addEventListener('click', doLogout);
  document.getElementById('userMenuBtn')?.addEventListener('click', () => {
    document.getElementById('userMenu').classList.toggle('hidden');
  });
  document.addEventListener('click', e => {
    const userBtn = document.getElementById('userMenuBtn');
    const userMenu = document.getElementById('userMenu');
    if (userMenu && userBtn && !userBtn.contains(e.target) && !userMenu.contains(e.target)) {
      userMenu.classList.add('hidden');
    }
  });
  // 主题
  document.getElementById('themeToggle')?.addEventListener('click', () => {
    document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  });
  if (localStorage.getItem('theme') === 'dark') document.documentElement.classList.add('dark');
  // 用户显示
  const user = localStorage.getItem('auth_user') || 'admin';
  document.getElementById('currentUser').textContent = user;
}

function initApp() {
  initNav();
  switchView('dashboard');
}

document.addEventListener('DOMContentLoaded', () => {
  if (!checkAuth()) {
    showLoginModal();
  } else {
    initApp();
  }
});
