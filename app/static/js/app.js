const appConfig = window.APP_CONFIG || {};
let currentInvestigation = null;
let selectedRow = null;
let selectedTab = "overview";
let selectedPacketIndex = 0;
let packetSearchQuery = "";
let packetProtocolFilter = "";

const emptySummary = {
  total_destination_ips: 0,
  unique_asns: 0,
  countries_contacted: 0,
  threat_indicators: 0,
  total_connections: 0,
  total_bytes: 0,
  top_telecom_providers: [],
  top_ports: [],
  top_services: [],
  total_hosts: 0,
  total_sessions: 0,
  bidirectional_sessions: 0
};

document.addEventListener("DOMContentLoaded", () => {
  renderSummary(emptySummary);
  bindEvents();
});

function bindEvents() {
  document.getElementById("uploadBtn").addEventListener("click", () => {
    document.getElementById("evidenceFile").click();
  });

  document.getElementById("evidenceFile").addEventListener("change", (event) => {
    updateSelectedFiles(event.target.files);
  });

  document.getElementById("uploadForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const files = [...document.getElementById("evidenceFile").files];
    if (!files.length) return setMessage("Select evidence files first.", "warn");
    const form = new FormData();
    files.forEach((file) => form.append("files", file));
    setMessage(`Analyzing ${files.length} evidence file${files.length === 1 ? "" : "s"}...`);
    const response = await fetch(apiUrl("/api/upload"), { method: "POST", body: form });
    await handleAnalysisResponse(response);
  });

  const toolbar = document.getElementById("uploadForm");
  ["dragenter", "dragover"].forEach((eventName) => {
    toolbar.addEventListener(eventName, (event) => {
      event.preventDefault();
      toolbar.classList.add("drag-over");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    toolbar.addEventListener(eventName, (event) => {
      event.preventDefault();
      toolbar.classList.remove("drag-over");
    });
  });
  toolbar.addEventListener("drop", (event) => {
    const input = document.getElementById("evidenceFile");
    input.files = event.dataTransfer.files;
    updateSelectedFiles(input.files);
  });

  ["searchInput", "scopeFilter", "roleFilter", "serviceFilter", "threatFilter", "portFilter"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderRows);
    document.getElementById(id).addEventListener("change", renderRows);
  });

  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      selectedTab = button.dataset.tab;
      document.body.classList.toggle("packet-workspace", selectedTab === "flows" || selectedTab === "packets");
      document.querySelectorAll(".tab-button").forEach((item) => item.classList.toggle("active", item === button));
      if (selectedRow) renderDetailPanel(selectedRow);
    });
  });
}

async function handleAnalysisResponse(response) {
  const payload = await response.json();
  if (!response.ok) {
    setMessage(formatApiError(payload), "bad");
    return;
  }

  currentInvestigation = payload;
  selectedRow = payload.rows[0] || null;
  document.getElementById("scopeFilter").value = payload.session_focus?.primary_destination_ip ? "session" : "all";
  selectedPacketIndex = 0;
  packetSearchQuery = "";
  packetProtocolFilter = "";
  document.body.classList.toggle("packet-workspace", selectedTab === "flows" || selectedTab === "packets");
  const caseName = payload.filename || `Case ${payload.id.slice(0, 8)}`;
  document.getElementById("caseStatus").textContent = `Case ${payload.id.slice(0, 8)}`;
  document.getElementById("caseTitle").textContent = caseName;
  const correlated = payload.correlation?.case_summary?.correlated_events || 0;
  const confidence = payload.correlation?.case_summary?.confidence_label || "No correlation";
  const matchedSessions = payload.correlation?.case_summary?.matched_sessions || 0;
  const totalPackets = payload.raw_packet_count || payload.summary?.total_packets || 0;
  const totalHosts = payload.summary?.total_hosts || payload.hosts?.length || 0;
  const totalSessions = payload.summary?.total_sessions || payload.sessions?.length || 0;
  const primaryPeer = payload.session_focus?.primary_destination_ip;
  const sessionHosts = primaryPeer ? (payload.hosts || []).filter((host) => host.session_relevant).length : totalHosts;
  const sessionDestinations = primaryPeer ? (payload.rows || []).filter((row) => row.session_relevant).length : payload.rows.length;
  const focusText = primaryPeer
    ? ` Primary direct peer: ${primaryPeer}. ${sessionDestinations} session destinations and ${sessionHosts} session hosts; ${payload.rows.length} captured destinations and ${totalHosts} captured hosts total.`
    : "";
  document.getElementById("caseSubtitle").textContent = `${payload.raw_connection_count} network records, ${totalPackets} packets, ${totalSessions} sessions, ${correlated} correlated events, ${matchedSessions} matched sessions.${focusText} ${confidence}.`;
  renderCustody(payload.evidence_files || []);
  setMessage("Analysis complete.");
  renderCaseAnalytics(payload);
  hydrateFilters(payload.rows);
  renderSummary(payload.summary);
  renderRows();
  updateExports(payload.id);
  if (selectedRow) showDetails(selectedRow);
}

function setMessage(message, tone = "info") {
  const element = document.getElementById("uploadMessage");
  element.textContent = message;
  element.className = `toolbar-message ${tone === "bad" ? "threat-bad" : tone === "warn" ? "threat-warn" : "muted"}`;
}

function formatApiError(payload) {
  const detail = payload?.detail;
  if (!detail) return "Analysis failed.";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item?.msg || item?.message || JSON.stringify(item)).join("; ");
  }
  if (typeof detail === "object") {
    return detail.message || JSON.stringify(detail);
  }
  return String(detail);
}

function hydrateFilters(rows) {
  const roleSelect = document.getElementById("roleFilter");
  const roleCurrent = roleSelect.value;
  const select = document.getElementById("serviceFilter");
  const current = select.value;
  const services = [...new Set(rows.map((row) => row.category).filter(Boolean))].sort();
  const roles = [...new Set(rows.map((row) => row.role).filter(Boolean))].sort();
  roleSelect.innerHTML = '<option value="">All roles</option>' + roles.map((item) => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`).join("");
  roleSelect.value = roleCurrent;
  select.innerHTML = '<option value="">All services</option>' + services.map((item) => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`).join("");
  select.value = current;
}

function renderSummary(summary) {
  const hasPrimaryPeer = Boolean(summary.primary_destination_ip);
  const cards = [
    ["Connections", summary.total_connections],
    ["Packets", summary.total_packets || 0],
    [hasPrimaryPeer ? "Session Dests" : "Destinations", hasPrimaryPeer ? summary.session_destination_count : summary.total_destination_ips],
    ["Primary Peer", summary.primary_destination_ip || "n/a"],
    ["Hosts", summary.total_hosts || 0],
    ["Sessions", summary.total_sessions || 0],
    ["Threats", summary.threat_indicators],
    ["Traffic", formatBytes(summary.total_bytes)]
  ];
  document.getElementById("summaryCards").innerHTML = cards.map(([label, value]) => `
    <div class="summary-card">
      <span class="label">${label}</span>
      <span class="value">${escapeHtml(String(value))}</span>
    </div>
  `).join("");
}

function updateSelectedFiles(files) {
  const list = [...files];
  if (!list.length) {
    document.getElementById("fileName").textContent = "No file selected";
    return;
  }
  document.getElementById("fileName").textContent = list.length === 1 ? list[0].name : `${list.length} files selected`;
}

function renderCustody(files) {
  const target = document.getElementById("custodySummary");
  target.innerHTML = files.slice(0, 4).map((file) => `
    <div class="custody-item">
      <strong>${escapeHtml(file.filename)}</strong>
      <span>${escapeHtml(file.evidence_type.toUpperCase())} | ${formatBytes(file.size_bytes)} | SHA-256 ${escapeHtml(file.sha256.slice(0, 16))}...</span>
    </div>
  `).join("");
}

function renderCaseAnalytics(payload) {
  const allHosts = payload.hosts || [];
  const allSessions = payload.sessions || [];
  const hasSessionFocus = Boolean(payload.session_focus?.primary_destination_ip);
  const hosts = hasSessionFocus ? allHosts.filter((host) => host.session_relevant) : allHosts;
  const sessions = hasSessionFocus ? allSessions.filter((session) => session.session_relevant) : allSessions;
  const timeline = payload.timeline || [];
  const protocols = payload.protocol_summary || [];
  const voip = payload.voip_analysis || [];

  document.getElementById("hostSummaryBadge").textContent = `${hosts.length} host${hosts.length === 1 ? "" : "s"}`;
  document.getElementById("sessionSummaryBadge").textContent = `${sessions.length} session${sessions.length === 1 ? "" : "s"}`;
  document.getElementById("flowSummaryBadge").textContent = `${(payload.flow_diagram?.edges || []).length} path${(payload.flow_diagram?.edges || []).length === 1 ? "" : "s"}`;
  document.getElementById("voipSummaryBadge").textContent = `${voip.length} VoIP session${voip.length === 1 ? "" : "s"}`;

  renderHostInventory(hosts);
  renderSessionInventory(sessions);
  renderFlowDiagram(payload.flow_diagram || {});
  renderProtocolSummary(protocols);
  renderVoipSummary(voip);
  renderTimelineSummary(timeline);
}

function renderHostInventory(hosts) {
  const target = document.getElementById("hostInventoryList");
  if (!hosts.length) {
    target.innerHTML = `<div class="compact-empty">No hosts identified yet.</div>`;
    return;
  }
  target.innerHTML = hosts.slice(0, 8).map((host) => `
    <div class="compact-row">
      <div class="compact-primary">
        <strong>${escapeHtml(host.ip)}${host.is_primary_destination ? ' <span class="primary-destination-mark">PRIMARY</span>' : ""}</strong>
        <span class="secondary-line">${escapeHtml(host.role || "client device")} | ${escapeHtml(host.asn)} | ${escapeHtml(host.country || "Unknown")}</span>
      </div>
      <div class="compact-meta">
        <span class="role-pill">${escapeHtml(host.role || "client device")}</span>
        <span class="secondary-line">${escapeHtml(String(host.role_confidence || 0))}% confidence</span>
        <span class="secondary-line">${(host.peer_ips || []).length} peers</span>
      </div>
    </div>
  `).join("");
}

function renderSessionInventory(sessions) {
  const target = document.getElementById("sessionInventoryList");
  if (!sessions.length) {
    target.innerHTML = `<div class="compact-empty">No sessions reconstructed yet.</div>`;
    return;
  }
  target.innerHTML = sessions.slice(0, 8).map((session) => `
    <div class="compact-row">
      <div class="compact-primary">
        <strong>${escapeHtml(session.client_ip)} <span class="arrow">-></span> ${escapeHtml(session.server_ip)}</strong>
        <span class="secondary-line">${escapeHtml(session.service || "Unknown")} | ${escapeHtml(session.protocol || "UNKNOWN")} | ${escapeHtml(shortDate(session.start_time))}</span>
      </div>
      <div class="compact-meta">
        <span class="service-pill">${escapeHtml(session.confidence || 0)}% confidence</span>
        <span class="secondary-line">${escapeHtml(String(session.duration_seconds || 0))}s</span>
        <span class="secondary-line">${formatBytes(session.bytes_transferred || 0)}</span>
      </div>
    </div>
  `).join("");
}

function renderFlowDiagram(flow) {
  const target = document.getElementById("flowDiagram");
  const nodes = flow.nodes || [];
  const edges = flow.edges || [];
  if (!nodes.length || !edges.length) {
    target.innerHTML = `<div class="compact-empty">No flow diagram could be reconstructed.</div>`;
    return;
  }
  const lane = nodes.slice(0, 10).map((node, index) => `
    <div class="flow-node">
      <span class="flow-index">${index + 1}</span>
      <div>
        <strong>${escapeHtml(node.label || node.id)}</strong>
        <span class="secondary-line">${escapeHtml(node.role || "endpoint")} | ${escapeHtml(node.country || "Unknown")}</span>
      </div>
    </div>
  `).join("");
  const edgeList = edges.slice(0, 8).map((edge) => `
    <div class="flow-edge">
      <strong>${escapeHtml(edge.source)} <span class="arrow">→</span> ${escapeHtml(edge.target)}</strong>
      <span class="secondary-line">${escapeHtml(edge.protocol || "UNKNOWN")} | ${escapeHtml(edge.label || "")}</span>
    </div>
  `).join("");
  target.innerHTML = `
    <div class="flow-column">
      <div class="flow-lane">${lane}</div>
    </div>
    <div class="flow-column">
      ${edgeList}
    </div>
  `;
}

function renderProtocolSummary(protocols) {
  const target = document.getElementById("protocolSummaryList");
  if (!protocols.length) {
    target.innerHTML = `<div class="compact-empty">No protocol distribution available.</div>`;
    return;
  }
  const total = protocols.reduce((sum, item) => sum + Number(item.count || 0), 0) || 1;
  target.innerHTML = protocols.slice(0, 8).map((item) => {
    const percent = Math.round((Number(item.count || 0) / total) * 100);
    return `
      <div class="compact-row">
        <div class="compact-primary">
          <strong>${escapeHtml(item.protocol || "UNKNOWN")}</strong>
          <span class="secondary-line">${escapeHtml(String(item.count || 0))} records</span>
        </div>
        <div class="compact-meta">
          <span class="service-pill">${escapeHtml(String(percent))}%</span>
        </div>
      </div>
    `;
  }).join("");
}

function renderVoipSummary(voip) {
  const target = document.getElementById("voipAnalysisList");
  if (!voip.length) {
    target.innerHTML = `<div class="compact-empty">No SIP, RTP, STUN, TURN, ICE, or WebRTC sessions were identified.</div>`;
    return;
  }
  target.innerHTML = voip.slice(0, 6).map((call) => {
    const shorten = (ip) => {
      if (!ip) return "";
      if (ip.includes(":")) {
        const parts = ip.split(":");
        if (parts.length > 3) {
          return parts[0] + ":" + parts[1] + ":::" + parts[parts.length - 1];
        }
      }
      return ip;
    };
    let routeHtml = "";
    if (call.route && call.route.length) {
      routeHtml = `
        <div class="voip-route-hops" style="margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.05); font-size: 10px; color: #94a3b8;">
          <div style="font-size: 8px; text-transform: uppercase; color: #64748b; font-weight: bold; margin-bottom: 4px;">Reconstructed Route Hops:</div>
          <div style="padding-left: 8px; border-left: 1px solid #00d2ff; display: flex; flex-direction: column; gap: 4px;">
            ${call.route.map((hop, idx) => {
              const arrow = idx > 0 ? '<span style="color: #475569; margin-right: 4px;">↓</span>' : '';
              const roleColor = (hop.role === 'caller' || hop.role === 'receiver') ? '#ff9900' : (hop.role === 'relay' ? '#a78bfa' : '#00d2ff');
              return `
                <div style="text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                  ${arrow}<span style="color: ${roleColor}; font-weight: bold;">[${escapeHtml(hop.role || 'Hop')}]</span>
                  <span style="color: #f8fafc; font-family: monospace; user-select: all;">${escapeHtml(shorten(hop.ip))}${hop.port ? `:${hop.port}` : ""}</span>
                  ${hop.name ? `<span style="color: #64748b;">(${escapeHtml(hop.name)})</span>` : ""}
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    }
    return `
      <div class="compact-row" style="flex-direction: column; align-items: stretch; gap: 4px;">
        <div style="display: flex; justify-content: space-between; width: 100%;">
          <div class="compact-primary">
            <strong>${escapeHtml(call.call_type || "VoIP")}</strong>
            <span class="secondary-line">${escapeHtml(shorten(call.caller))} <span class="arrow">-></span> ${escapeHtml(shorten(call.remote_peer))} | ${escapeHtml(call.media_ports || "n/a")}</span>
          </div>
          <div class="compact-meta" style="text-align: right;">
            <span class="role-pill">${escapeHtml(String(call.confidence || 0))}%</span>
            <span class="secondary-line">MOS ${escapeHtml(String(call.mos_estimate ?? "n/a"))}</span>
          </div>
        </div>
        ${routeHtml}
      </div>
    `;
  }).join("");
}

function renderTimelineSummary(timeline) {
  const target = document.getElementById("timelineList");
  if (!timeline.length) {
    target.innerHTML = `<div class="compact-empty">No timeline events were generated.</div>`;
    return;
  }
  target.innerHTML = timeline.slice(0, 8).map((event) => `
    <div class="compact-row">
      <div class="compact-primary">
        <strong>${escapeHtml(shortDate(event.timestamp))}</strong>
        <span class="secondary-line">${escapeHtml(event.event || "Event")} | ${escapeHtml(event.protocol || "UNKNOWN")}</span>
      </div>
      <div class="compact-meta">
        <span class="secondary-line">${escapeHtml(event.source_ip || "")} ${event.destination_ip ? `→ ${escapeHtml(event.destination_ip)}` : ""}</span>
      </div>
    </div>
  `).join("");
}

function filteredRows() {
  if (!currentInvestigation) return [];
  const text = document.getElementById("searchInput").value.toLowerCase().trim();
  const scope = document.getElementById("scopeFilter").value;
  const role = document.getElementById("roleFilter").value;
  const service = document.getElementById("serviceFilter").value;
  const threat = document.getElementById("threatFilter").value;
  const port = document.getElementById("portFilter").value.trim();

  return currentInvestigation.rows.filter((row) => {
    const haystack = [
      row.destination_ip,
      row.source_ip,
      row.asn,
      row.asn_org,
      row.isp,
      row.country,
      row.role,
      row.category,
      row.service,
      row.hostname
    ].join(" ").toLowerCase();
    const textOk = !text || haystack.includes(text);
    const scopeOk = scope === "all" || row.session_relevant !== false;
    const roleOk = !role || row.role === role;
    const serviceOk = !service || row.category === service;
    const portOk = !port || String(row.destination_port || "") === port;
    const threatOk = !threat ||
      (threat === "malicious" && row.malicious) ||
      (threat === "suspicious" && row.reputation_score >= 50) ||
      (threat === "clean" && !row.malicious && row.reputation_score < 50);
    return textOk && scopeOk && roleOk && serviceOk && portOk && threatOk;
  });
}

function renderRows() {
  const rows = filteredRows();
  document.getElementById("rowCount").textContent = `${rows.length} destinations`;
  if (!rows.length) {
    document.getElementById("intelRows").innerHTML = `<tr><td colspan="6" class="empty-state">No destinations match the current filters.</td></tr>`;
    return;
  }

  if (!selectedRow || !rows.some((row) => row.destination_ip === selectedRow.destination_ip)) {
    selectedRow = rows[0];
    showDetails(selectedRow);
  }

  document.getElementById("intelRows").innerHTML = rows.map((row) => {
    const selected = selectedRow && selectedRow.destination_ip === row.destination_ip ? "selected" : "";
    const threat = threatState(row);
    return `
      <tr class="${selected}" data-ip="${escapeHtml(row.destination_ip)}">
        <td class="ip-cell"><strong>${escapeHtml(row.destination_ip)}${row.is_primary_destination ? ' <span class="primary-destination-mark">PRIMARY</span>' : ""}</strong><span class="secondary-line">${escapeHtml(row.destination_kind || row.isp)}</span></td>
        <td><span class="role-pill">${escapeHtml(row.role || "client device")}</span><span class="secondary-line">${row.role_confidence || 0}% confidence</span></td>
        <td><span class="service-pill">${escapeHtml(row.category)}</span><span class="secondary-line">${row.confidence}% confidence</span></td>
        <td><strong>${escapeHtml(row.asn)}</strong><span class="secondary-line">${escapeHtml(row.asn_org)}</span></td>
        <td>${escapeHtml(row.country)}<span class="secondary-line">${escapeHtml(row.city || "Unknown city")}</span></td>
        <td><span class="threat-pill ${threat.className}">${threat.label}</span><span class="secondary-line">Score ${row.reputation_score}/100</span></td>
      </tr>
    `;
  }).join("");

  document.querySelectorAll("#intelRows tr[data-ip]").forEach((rowElement) => {
    rowElement.addEventListener("click", () => {
      const row = currentInvestigation.rows.find((item) => item.destination_ip === rowElement.dataset.ip);
      if (!row) return;
      selectedRow = row;
      renderRows();
      showDetails(row);
    });
  });
}

function showDetails(row) {
  document.getElementById("detailsEmpty").classList.add("d-none");
  document.getElementById("detailsContent").classList.remove("d-none");
  document.getElementById("detailIp").textContent = row.destination_ip;
  document.getElementById("detailOrg").textContent = `${row.asn_org} | ${row.asn}`;
  document.getElementById("detailMetricCards").innerHTML = metricCards(row);
  const threat = threatState(row);
  const badge = document.getElementById("detailThreatBadge");
  badge.textContent = threat.label;
  badge.className = `threat-badge threat-${threat.tone}`;
  renderDetailPanel(row);
}

function renderDetailPanel(row) {
  const panel = document.getElementById("detailPanel");
  if (selectedTab === "overview") {
    panel.innerHTML = `
      <div class="detail-card-grid">
        ${detailCard("IP Profile", [
          ["Destination", row.destination_ip],
          ["Destination Type", row.destination_kind || "Captured destination"],
          ["Source", row.source_ips?.join(", ") || row.source_ip || "Unknown"],
          ["Hostname", row.hostname || "Not resolved"],
          ["Port", portLabel(row)],
          ["IP Intelligence Source", row.ip_source || "Local GeoIP"]
        ])}
        ${detailCard("Role Analysis", [
          ["Primary Role", row.role || "client device"],
          ["Confidence", `${row.role_confidence || 0}%`],
          ["Secondary Roles", (row.role_secondary || []).join(", ") || "None"],
          ["Why", (row.role_reasons || []).join("; ") || "No role evidence available"],
          ["Evidence Packets", (row.evidence_packets || []).slice(0, 3).map((item) => `${shortDate(item.timestamp)} | ${item.flow_label || item.summary || "Packet"}`).join(" • ") || "Not available"]
        ])}
        ${detailCard("Geo", [
          ["Country", row.country],
          ["Region", row.region],
          ["City", row.city],
          ["Coordinates", coordinates(row)]
        ])}
        ${detailCard("Service", [
          ["Classification", row.service],
          ["Confidence", `${row.confidence}%`],
          ["Matched Range", row.matched_prefix || "No range match"],
          ["Evidence", (row.service_match_reasons || []).join("; ")]
        ])}
      </div>
    `;
    return;
  }

  if (selectedTab === "whois") {
    panel.innerHTML = `
      <div class="detail-card-grid">
        ${detailCard("ASN Details", [
          ["ASN", row.asn],
          ["Organization", row.asn_org],
          ["Provider", row.isp],
          ["Prefix", row.network_prefix]
        ])}
        ${detailCard("WHOIS Summary", [
          ["Registry", registryHint(row)],
          ["Network", row.network_prefix],
          ["Org", row.asn_org],
          ["Attribution Mode", row.network_prefix === "Unknown" ? "No offline match" : "Offline GeoLite-style range"]
        ])}
      </div>
    `;
    return;
  }

  if (selectedTab === "dns") {
    panel.innerHTML = detailList([
      ["Destination", row.destination_ip],
      ["Reverse DNS", row.hostname || "Not resolved in offline mode"],
      ["Provider DNS Hint", dnsHint(row)],
      ["Observed Port", portLabel(row)]
    ]);
    return;
  }

  if (selectedTab === "asn") {
    panel.innerHTML = detailList([
      ["ASN", row.asn],
      ["Organization", row.asn_org],
      ["Prefix", row.network_prefix],
      ["Provider", row.isp],
      ["Country", row.country],
      ["Region", row.region],
      ["City", row.city]
    ]);
    return;
  }

  if (selectedTab === "threat") {
    panel.innerHTML = `
      <div class="detail-card-grid">
        ${detailCard("Reputation", [
          ["Status", threatState(row).label],
          ["Threat Score", `${row.reputation_score}/100`],
          ["Abuse Reports", row.abuse_reports || 0]
        ])}
        ${detailCard("Feed Context", [
          ["Category", row.threat_category],
          ["Last Reported", row.last_reported || "None"],
          ["Last Checked", shortDate(row.last_checked)],
          ["Feeds Checked", row.feeds_checked || "Local feed"]
        ])}
      </div>
    `;
    return;
  }

  if (selectedTab === "correlation") {
    const events = currentInvestigation?.correlation?.events || [];
    const relevant = events.filter((event) => !row || event.destination_ip === row.destination_ip);
    const serviceRows = currentInvestigation?.correlation?.services || [];
    panel.innerHTML = relevant.length ? `
      <div class="detail-card-grid">
        <section class="detail-card">
          <h4>Session Correlation</h4>
          <table class="correlation-table">
            <thead>
              <tr>
                <th>Session</th>
                <th>PCAP Match</th>
                <th>TXT Match</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              ${serviceRows.map((service) => `
                <tr>
                  <td>${escapeHtml(service.session)}</td>
                  <td>${escapeHtml(service.pcap_match)}</td>
                  <td>${escapeHtml(service.txt_match)}</td>
                  <td>${escapeHtml(service.confidence)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </section>
        <section class="detail-card">
          <h4>Confidence Calculation</h4>
          ${renderConfidenceBreakdown(relevant[0])}
        </section>
        <section class="detail-card">
          <h4>Correlation Events</h4>
          <table class="correlation-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>PCAP Evidence</th>
                <th>TXT Evidence</th>
                <th>Match Score</th>
              </tr>
            </thead>
            <tbody>
              ${relevant.map((event) => `
                <tr>
                  <td>${shortDate(event.time)}</td>
                  <td>${escapeHtml(event.pcap_evidence)}<span class="secondary-line">${escapeHtml(event.provider)} | ${escapeHtml(event.service)}</span></td>
                  <td>${escapeHtml(event.txt_evidence)}<span class="secondary-line">${escapeHtml(event.subscriber || "No subscriber")} | IMEI ${escapeHtml(event.imei || "n/a")}</span></td>
                  <td><strong>${escapeHtml(event.match_score)}</strong><span class="secondary-line">${escapeHtml(event.confidence_label)}</span></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </section>
        <section class="detail-card">
          <h4>Correlation Graph</h4>
          ${renderCorrelationGraph(currentInvestigation?.correlation?.attribution_report, relevant)}
        </section>
      </div>
    ` : `<p class="muted">No correlated TXT/CDR session matched this destination.</p>`;
    return;
  }

  if (selectedTab === "report") {
    const report = currentInvestigation?.correlation?.attribution_report;
    panel.innerHTML = report ? `
      <div class="detail-card-grid">
        ${detailCard("Attribution Report", [
          ["Subscriber", report.subscriber],
          ["Assigned IP", report.assigned_ip],
          ["Correlated Services", report.correlated_services.join(", ") || "None"],
          ["Supporting Evidence", report.supporting_evidence.join(", ")],
          ["Correlation Confidence", `${report.confidence}% (${report.confidence_label})`],
          ["Associated Device", report.device]
        ])}
        ${detailCard("Assessment", [
          ["Assessment", report.assessment]
        ])}
      </div>
    ` : `<p class="muted">No attribution report is available for this investigation.</p>`;
    return;
  }

  if (selectedTab === "timeline") {
    panel.innerHTML = `
      <div class="timeline-list">
        ${timelineItem("First Seen", shortDate(row.first_seen))}
        ${timelineItem("Last Seen", shortDate(row.last_seen))}
        ${timelineItem("Duration", `${row.duration_seconds || 0} seconds`)}
        ${timelineItem("Connections", `${row.connection_count} connections, ${row.packet_count} packets`)}
        ${timelineItem("Traffic", formatBytes(row.bytes_transferred))}
      </div>
    `;
    return;
  }

  if (selectedTab === "flows") {
    const rawRows = row.raw_connections || [];
    panel.innerHTML = rawRows.length ? `
      <div class="raw-list">
        ${rawRows.map((record) => `
          <div class="raw-item">
            <div class="raw-item-header">
              <div>
                <strong>${escapeHtml(record.source_ip)}:${escapeHtml(String(record.source_port || "n/a"))}</strong>
                <span class="arrow">-></span>
                <strong>${escapeHtml(record.destination_ip)}:${escapeHtml(String(record.destination_port || "n/a"))}</strong>
                <span class="secondary-line">${escapeHtml(record.protocol || "UNKNOWN")} | ${shortDate(record.timestamp)} | ${record.packet_count} packets | ${formatBytes(record.bytes_transferred)}</span>
              </div>
              ${payloadBadge(record.payload_kind)}
            </div>
            ${record.packet_details?.[0]?.summary ? `<span class="secondary-line packet-layer-line">Layers: ${escapeHtml(record.packet_details[0].summary)}</span>` : ""}
            ${record.packet_details?.[0]?.decoded_type ? `<span class="secondary-line packet-layer-line">Decoded: ${escapeHtml(record.packet_details[0].decoded_type)}${record.packet_details[0].decoded_summary ? ` | ${escapeHtml(record.packet_details[0].decoded_summary)}` : ""}</span>` : ""}
            ${renderPayloadPanel(record, "flow")}
            ${renderPacketDetails(record.packet_details)}
          </div>
        `).join("")}
      </div>
    ` : `<p class="muted">No raw connection records were retained for this destination.</p>`;
    return;
  }

  if (selectedTab === "packets") {
    renderPacketsTab(panel, row);
    return;
  }

  panel.innerHTML = `
    <textarea class="form-control notes-box" placeholder="Add investigation notes for ${escapeHtml(row.destination_ip)}"></textarea>
  `;
}

function metricCards(row) {
  const items = [
    ["Country", row.country],
    ["ASN", row.asn],
    ["Connections", row.connection_count],
    ["Bytes", formatBytes(row.bytes_transferred)]
  ];
  return items.map(([label, value]) => `
    <div class="metric-card">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value))}</strong>
    </div>
  `).join("");
}

function detailCard(title, items) {
  return `
    <section class="detail-card">
      <h4>${escapeHtml(title)}</h4>
      ${detailList(items)}
    </section>
  `;
}

function renderConfidenceBreakdown(event) {
  const breakdown = event?.breakdown || [];
  if (!breakdown.length) return `<p class="muted">No scoring breakdown available.</p>`;
  const total = breakdown.reduce((sum, item) => sum + Number(item.points || 0), 0);
  return `
    <div class="detail-list">
      ${breakdown.map((item) => `
        <div class="detail-row">
          <span>${escapeHtml(item.label)}</span>
          <span>+${escapeHtml(String(item.points))}</span>
        </div>
      `).join("")}
      <div class="detail-row">
        <span>Final Score</span>
        <span>${escapeHtml(event.match_score)}</span>
      </div>
    </div>
  `;
}

function renderCorrelationGraph(report, events) {
  if (!report) return `<p class="muted">No correlation graph available.</p>`;
  const services = [...new Set(events.map((event) => event.service).filter(Boolean))];
  return `
    <div class="correlation-graph">
      <div class="graph-box">
        <strong>Subscriber</strong>
        <span>${escapeHtml(report.subscriber || "Unknown")}</span>
      </div>
      <div class="graph-box">
        <strong>Assigned IP</strong>
        <span>${escapeHtml(report.assigned_ip || "Unknown")}</span>
      </div>
      ${services.map((service) => `
        <div class="graph-box">
          <strong>${escapeHtml(service)}</strong>
          <span>Correlated from PCAP + TXT</span>
        </div>
      `).join("")}
    </div>
  `;
}

function payloadMeta(kind) {
  const normalized = String(kind || "").toLowerCase();
  if (normalized === "dns" || normalized === "plaintext") {
    const isDns = normalized === "dns";
    return {
      label: isDns ? "DNS" : "Plaintext",
      tone: "plain",
      note: isDns ? "DNS / mDNS payload" : "Readable payload extracted from the packet",
      contentLabel: isDns ? "DNS content" : "Readable content",
      mode: "text",
    };
  }
  if (normalized === "encrypted") {
    return {
      label: "Encrypted",
      tone: "enc",
      note: "Ciphertext preview shown because the packet contents are not decryptable here",
      contentLabel: "Ciphertext / bytes",
      mode: "hex",
    };
  }
  if (normalized === "binary") {
    return {
      label: "Binary",
      tone: "bin",
      note: "Non-text payload",
      contentLabel: "Raw bytes",
      mode: "hex",
    };
  }
  if (normalized === "metadata_only" || normalized === "empty") {
    return {
      label: "No Payload",
      tone: "none",
      note: "No extractable application payload in this packet",
      contentLabel: "No payload",
      mode: "none",
    };
  }
  return {
    label: "Unknown",
    tone: "none",
    note: "Payload present but could not be decoded",
    contentLabel: "Unavailable",
    mode: "none",
  };
}

function payloadBadge(kind) {
  const meta = payloadMeta(kind);
  return `<span class="payload-badge payload-${meta.tone}">${escapeHtml(meta.label)}</span>`;
}

function renderPayloadPanel(record, scope = "packet") {
  const meta = payloadMeta(record.payload_kind);
  const summary = record.summary || "";
  const content = payloadContent(record, meta);
  const scopeLabel = scope === "flow" ? "Flow Payload" : "Payload View";
  return `
    <div class="payload-panel payload-${meta.tone}">
      <div class="payload-panel-head">
        <div class="payload-panel-titleblock">
          <span class="payload-panel-title">${escapeHtml(scopeLabel)}</span>
          <span class="payload-panel-note">${escapeHtml(meta.note)}</span>
        </div>
        ${summary ? `<span class="payload-panel-layers">${escapeHtml(summary)}</span>` : ""}
      </div>
      <div class="payload-panel-body">
        ${content}
      </div>
    </div>
  `;
}

function payloadContent(record, meta) {
  const preview = record.payload_preview || "No packet payload extracted";
  const hex = record.payload_hex || "";
  if (meta.mode === "text") {
    return `
      <div class="payload-block">
        <span class="payload-block-label">${escapeHtml(meta.contentLabel)}</span>
        <pre class="payload-content payload-content-text">${escapeHtml(preview)}</pre>
        ${hex ? `<div class="payload-secondary">Raw bytes: <span class="payload-inline">${escapeHtml(hex)}</span></div>` : ""}
      </div>
    `;
  }
  if (meta.mode === "hex") {
    return `
      <div class="payload-block">
        <span class="payload-block-label">${escapeHtml(meta.contentLabel)}</span>
        <pre class="payload-content payload-content-hex">${escapeHtml(hex || preview)}</pre>
        <div class="payload-secondary">Plaintext not available without decryption material.</div>
      </div>
    `;
  }
  return `
    <div class="payload-block">
      <span class="payload-block-label">${escapeHtml(meta.contentLabel)}</span>
      <div class="payload-empty">${escapeHtml(meta.note)}</div>
    </div>
  `;
}

function renderPacketDetails(packetDetails) {
  if (!packetDetails || !packetDetails.length) {
    return "";
  }
  return `
    <div class="detail-card packet-breakdown" style="margin-top:10px;">
      <h4>Packet Breakdown</h4>
      <div class="raw-list">
        ${packetDetails.map((packet, index) => `
          <div class="raw-item">
            <div class="raw-item-header">
              <div>
                <strong>Packet ${index + 1}</strong>
                <span class="secondary-line">${shortDate(packet.timestamp)} | ${escapeHtml(packet.protocol || "UNKNOWN")} | ${packet.length} bytes</span>
                <span class="secondary-line">${escapeHtml(packet.source_ip)}:${escapeHtml(String(packet.source_port || "n/a"))} <span class="arrow">-></span> ${escapeHtml(packet.destination_ip)}:${escapeHtml(String(packet.destination_port || "n/a"))}</span>
              </div>
              ${payloadBadge(packet.payload_kind)}
            </div>
            ${packet.summary ? `<span class="secondary-line packet-layer-line">Layers: ${escapeHtml(packet.summary)}</span>` : ""}
            ${packet.decoded_type ? `<span class="secondary-line packet-layer-line">Decoded: ${escapeHtml(packet.decoded_type)}${packet.decoded_summary ? ` | ${escapeHtml(packet.decoded_summary)}` : ""}</span>` : ""}
            ${renderPayloadPanel(packet)}
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function renderPacketsTab(panel, selectedDestination) {
  if (!currentInvestigation) {
    panel.innerHTML = `<p class="muted">No packet data is available yet.</p>`;
    return;
  }

  const packets = filteredPacketRows();
  const protocolOptions = packetProtocolOptions();
  const toolbar = `
    <div class="packet-toolbar">
      <input id="packetSearchInput" class="form-control form-control-sm" placeholder="Search packets by IP, flow, payload, or decoding" value="${escapeHtml(packetSearchQuery)}">
      <select id="packetProtocolFilter" class="form-select form-select-sm">
        <option value="">All protocols</option>
        ${protocolOptions.map((protocol) => `<option value="${escapeHtml(protocol)}"${packetProtocolFilter === protocol ? " selected" : ""}>${escapeHtml(protocol)}</option>`).join("")}
      </select>
      <span class="muted packet-count">${packets.length} packets</span>
    </div>
  `;

  if (!packets.length) {
    panel.innerHTML = `${toolbar}<p class="muted">No packet-level rows match the current filters.</p>`;
    bindPacketFilters(selectedDestination);
    return;
  }

  const selectedPacket = packets.find((packet) => packet.__index === selectedPacketIndex) || packets[0];
  if (selectedPacket && selectedPacket.__index !== selectedPacketIndex) {
    selectedPacketIndex = selectedPacket.__index;
  }
  panel.innerHTML = `
    ${toolbar}
    <div class="packet-table-wrap">
      <table class="packet-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Flow</th>
            <th>Protocol</th>
            <th>Decoding</th>
            <th>Payload</th>
            <th>Bytes</th>
          </tr>
        </thead>
        <tbody>
          ${packets.map((packet) => packetTableRow(packet, selectedDestination)).join("")}
        </tbody>
      </table>
    </div>
    ${renderPacketFocus(selectedPacket)}
  `;
  bindPacketFilters(selectedDestination);

  document.querySelectorAll(".packet-row").forEach((rowElement) => {
    rowElement.addEventListener("click", () => {
      const packetIndex = Number(rowElement.dataset.packetIndex);
      selectedPacketIndex = Number.isNaN(packetIndex) ? 0 : packetIndex;
      renderPacketsTab(panel, selectedDestination);
    });
  });
}

function filteredPacketRows() {
  if (!currentInvestigation) return [];
  const search = packetSearchQuery.trim().toLowerCase();
  return (currentInvestigation.packet_rows || [])
    .map((packet, index) => ({ ...packet, __index: index }))
    .filter((packet) => {
      const protocol = String(packet.protocol || "").toUpperCase();
      const haystack = [
        packet.flow_label,
        packet.source_ip,
        packet.destination_ip,
        packet.payload_preview,
        packet.decoded_summary,
        packet.decoded_detail,
        packet.summary,
        packet.payload_kind,
        protocol,
        String(packet.length || "")
      ].join(" ").toLowerCase();
      const searchOk = !search || haystack.includes(search);
      const protocolOk = !packetProtocolFilter || protocol === packetProtocolFilter;
      return searchOk && protocolOk;
    });
}

function packetProtocolOptions() {
  if (!currentInvestigation) return [];
  return [...new Set((currentInvestigation.packet_rows || []).map((packet) => String(packet.protocol || "").toUpperCase()).filter(Boolean))].sort();
}

function bindPacketFilters(selectedDestination) {
  const searchInput = document.getElementById("packetSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (event) => {
      packetSearchQuery = event.target.value;
      renderDetailPanel(selectedDestination);
    });
  }

  const protocolFilter = document.getElementById("packetProtocolFilter");
  if (protocolFilter) {
    protocolFilter.addEventListener("change", (event) => {
      packetProtocolFilter = event.target.value;
      renderDetailPanel(selectedDestination);
    });
  }
}

function packetTableRow(packet, selectedDestination) {
  const payload = payloadMeta(packet.payload_kind);
  const selected = packet.__index === selectedPacketIndex ? "selected" : "";
  const related = selectedDestination && (
    packet.flow_destination_ip === selectedDestination.destination_ip ||
    packet.source_ip === selectedDestination.destination_ip ||
    packet.destination_ip === selectedDestination.destination_ip
  ) ? "related" : "";
  const flowLabel = truncateText(packet.flow_label || "Flow unavailable", 44);
  const flowPorts = truncateText(`${packet.source_port || "n/a"} -> ${packet.destination_port || "n/a"}`, 26);
  const protocolSummary = truncateText(packet.summary || "No layer summary", 40);
  const decodingSummary = truncateText(packet.decoded_summary || packet.decoded_detail || "No protocol-specific decoding", 48);
  const payloadPreview = truncateText(packet.payload_preview || "No packet payload extracted", 44);
  const packetNumber = packet.packet_index || packet.__index + 1;
  return `
    <tr class="packet-row ${selected} ${related}" data-packet-index="${packet.__index}">
      <td>
        <div class="packet-cell">
          <span class="packet-primary">${escapeHtml(shortDate(packet.timestamp))}</span>
          <span class="packet-secondary">${escapeHtml(`Packet ${packetNumber}`)}</span>
        </div>
      </td>
      <td>
        <div class="packet-cell">
          <span class="packet-primary">${escapeHtml(flowLabel)}</span>
          <span class="packet-secondary">${escapeHtml(flowPorts)}</span>
        </div>
      </td>
      <td>
        <div class="packet-cell">
          <span class="service-pill">${escapeHtml(packet.protocol || "UNKNOWN")}</span>
          <span class="packet-secondary">${escapeHtml(protocolSummary)}</span>
        </div>
      </td>
      <td>
        <div class="packet-cell">
          <span class="packet-primary">${escapeHtml(packet.decoded_type || payload.label)}</span>
          <span class="packet-secondary">${escapeHtml(decodingSummary)}</span>
        </div>
      </td>
      <td>
        <div class="packet-cell">
          <span class="payload-badge payload-${payload.tone}">${escapeHtml(payload.label)}</span>
          <span class="packet-secondary">${escapeHtml(payloadPreview)}</span>
        </div>
      </td>
      <td>
        <div class="packet-cell">
          <span class="packet-primary">${escapeHtml(formatBytes(packet.length))}</span>
          <span class="packet-secondary">${escapeHtml(`Packet ${packetNumber}`)}</span>
        </div>
      </td>
    </tr>
  `;
}

function renderPacketFocus(packet) {
  if (!packet) {
    return `<p class="muted">Select a packet to inspect its protocol-specific decoding.</p>`;
  }
  const payload = payloadMeta(packet.payload_kind);
  return `
    <div class="detail-card-grid packet-focus-grid" style="grid-template-columns: 1fr;">
      ${detailCard("Packet Profile", [
        ["Time", shortDate(packet.timestamp)],
        ["Flow", packet.flow_label || `${packet.source_ip} -> ${packet.destination_ip}`],
        ["Protocol", packet.protocol || "UNKNOWN"],
        ["Length", formatBytes(packet.length)],
        ["Payload Type", payload.label]
      ])}
      ${detailCard("Protocol Decoding", packetDecodedItems(packet))}
      ${detailCard("Payload View", [
        ["Preview", packet.payload_preview || "No packet payload extracted"],
        ["Hex", packet.payload_hex || "n/a"]
      ])}
    </div>
  `;
}

function packetDecodedItems(packet) {
  const fields = packet.decoded_fields || {};
  const items = [
    ["Decoded Type", packet.decoded_type || "Unknown"],
    ["Decoded Summary", packet.decoded_summary || packet.decoded_detail || "No protocol-specific decoding"],
  ];

  if ((packet.decoded_type || "").startsWith("DNS")) {
    items.push(["Transaction ID", fields.transaction_id ?? "n/a"]);
    items.push(["RCode", fields.rcode || "n/a"]);
    items.push(["Questions", (fields.questions || []).join("; ") || "None"]);
    items.push(["Answers", (fields.answers || []).join("; ") || "None"]);
    return items;
  }

  if (packet.decoded_type === "HTTP Request") {
    items.push(["Method", fields.method || "n/a"]);
    items.push(["Path", fields.path || "n/a"]);
    items.push(["Host", fields.host || "n/a"]);
    items.push(["Version", fields.version || "n/a"]);
    items.push(["Headers", renderHttpHeaders(fields.headers || {})]);
    items.push(["Body Preview", fields.body_preview || "n/a"]);
    return items;
  }

  if (packet.decoded_type === "HTTP Response") {
    items.push(["Status", `${fields.status_code || "n/a"} ${fields.reason || ""}`.trim()]);
    items.push(["Version", fields.version || "n/a"]);
    items.push(["Headers", renderHttpHeaders(fields.headers || {})]);
    items.push(["Body Preview", fields.body_preview || "n/a"]);
    return items;
  }

  if (packet.decoded_type === "Encrypted Payload") {
    items.push(["Ciphertext Preview", fields.ciphertext_preview || packet.payload_hex || "n/a"]);
    items.push(["Note", "Plaintext cannot be recovered without decryption material."]);
    return items;
  }

  return items;
}

function renderHttpHeaders(headers) {
  const entries = Object.entries(headers || {});
  if (!entries.length) return "None";
  return entries.slice(0, 8).map(([key, value]) => `${key}: ${value}`).join("; ");
}

function truncateText(value, maxLength = 48) {
  const text = String(value ?? "");
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, Math.max(0, maxLength - 1))}…`;
}

function detailList(items) {
  return `
    <div class="detail-list">
      ${items.map(([label, value]) => `
        <div class="detail-row">
          <span>${escapeHtml(String(label))}</span>
          <span>${escapeHtml(String(value ?? "n/a"))}</span>
        </div>
      `).join("")}
    </div>
  `;
}

function timelineItem(label, value) {
  return `
    <div class="timeline-item">
      <strong>${escapeHtml(label)}</strong>
      <span class="secondary-line">${escapeHtml(String(value))}</span>
    </div>
  `;
}

function updateExports(id) {
  [["exportPdf", "pdf"], ["exportXlsx", "xlsx"], ["exportCsv", "csv"], ["exportJson", "json"]].forEach(([elementId, format]) => {
    const link = document.getElementById(elementId);
    link.href = apiUrl(`/api/export/${id}.${format}`);
    link.classList.remove("disabled");
  });
}

function apiUrl(path) {
  const base = String(appConfig.apiBaseUrl || "").trim().replace(/\/$/, "");
  return base ? `${base}${path}` : path;
}

function threatState(row) {
  if (row.malicious) return { label: "Malicious", className: "bad", tone: "bad" };
  if (row.reputation_score >= 50) return { label: "Suspicious", className: "warn", tone: "warn" };
  return { label: "Clean", className: "clean", tone: "clean" };
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function portLabel(row) {
  if (!row.destination_port) return "Port Unknown";
  return `${escapeHtml(row.protocol || "IP")}/${escapeHtml(String(row.destination_port))} ${escapeHtml(row.port_name || "")}`.trim();
}

function coordinates(row) {
  if (row.latitude === null || row.latitude === undefined || row.longitude === null || row.longitude === undefined) {
    return "Not available";
  }
  return `${row.latitude}, ${row.longitude}`;
}

function registryHint(row) {
  if (row.country === "United States") return "ARIN";
  if (row.country === "India") return "APNIC";
  if (["Netherlands", "Germany"].includes(row.country)) return "RIPE NCC";
  if (row.country === "Australia") return "APNIC";
  return "Unknown";
}

function dnsHint(row) {
  if (row.destination_ip === "8.8.8.8") return "Google Public DNS";
  if (row.destination_ip === "1.1.1.1") return "Cloudflare Resolver";
  if ((row.destination_port || 0) === 53) return "DNS traffic observed";
  return row.category || "No DNS-specific signal";
}

function shortDate(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
}
