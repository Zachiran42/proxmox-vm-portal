"use strict";

const state = { csrfToken: "", user: null, usage: {}, settings: {}, profiles: [], networkProfiles: [], softwareModules: [], nodes: [], jobs: [], notifications: [], unreadNotifications: 0, users: [], auditEvents: [], operations: null, fleet: null, mco: null, integrations: {}, pollTimer: null, showArchived: false, detailsSshCommand: "", detailsVm: null };
const elements = Object.fromEntries(
  [
    "login-screen", "login-form", "local-login-fields", "login-error", "login-button",
    "login-separator", "oidc-login", "app-shell", "user-avatar", "user-name", "user-role",
    "first-password-dialog", "first-password-form", "first-password", "first-password-confirmation",
    "first-password-error", "save-first-password",
    "logout-button", "notifications-button", "notification-badge", "notifications-dialog", "notifications-summary", "notification-list", "notifications-empty", "close-notifications", "read-all-notifications", "open-profile-dialog", "refresh-profiles", "profile-grid", "empty-state",
    "profile-count", "stat-active", "stat-cloud", "stat-disabled", "profile-dialog",
    "profile-form", "close-profile-dialog", "cancel-profile", "profile-label", "profile-slug", "profile-version",
    "profile-error", "publish-profile", "cloud-fields", "iso-fields", "template-node",
    "template-vmid", "iso-node", "profile-iso", "toast", "machines-view", "images-view",
    "open-vm-dialog", "vm-dialog", "vm-form", "close-vm-dialog", "cancel-vm", "submit-vm",
    "vm-profile", "vm-node", "vm-name", "vm-usage-purpose", "vm-no-patient-data-ack", "vm-cpu", "vm-ram", "vm-disk", "vm-lifetime-days", "vm-lifetime-help", "vm-error",
    "network-step", "vm-network-profile", "vm-network-mode", "vm-static-network", "vm-ipv4-cidr",
    "vm-gateway", "vm-dns-servers",
    "guest-access-step", "vm-guest-username", "vm-guest-password",
    "vm-guest-password-confirmation", "guest-password-help", "quota-preview", "refresh-jobs", "show-archived", "job-list",
    "jobs-empty", "job-count", "quota-vms", "quota-cpu", "quota-ram", "quota-disk",
    "quota-vms-progress", "quota-cpu-progress", "quota-ram-progress", "quota-disk-progress",
    "operations-nav", "operations-mobile-nav", "operations-view", "admin-nav", "admin-mobile-nav", "admin-view", "open-user-dialog", "refresh-users",
    "user-list", "user-count", "stat-users-active", "stat-users-oidc", "stat-users-admin",
    "audit-list", "audit-empty", "audit-count", "audit-outcome", "audit-search", "refresh-audit",
    "user-dialog", "user-form", "user-id", "user-dialog-title", "user-dialog-intro",
    "close-user-dialog", "cancel-user", "save-user", "managed-username", "managed-role",
    "managed-password", "password-optional", "identity-help", "managed-quota-vms",
    "managed-quota-cpu", "managed-quota-ram", "managed-quota-disk", "active-checkbox",
    "managed-active", "user-error", "vm-action-dialog", "vm-action-form", "vm-action-id",
    "vm-action-kind", "vm-action-title", "vm-action-intro", "vm-delete-confirmation",
    "vm-confirm-name", "vm-confirm-expected", "vm-action-error", "close-vm-action",
    "cancel-vm-action", "submit-vm-action", "vm-details-dialog", "vm-details-title",
    "vm-details-intro", "vm-details-status", "vm-details-placement", "vm-details-profile", "vm-details-usage",
    "vm-details-resources", "vm-details-ssh-user", "vm-details-ipv4", "vm-details-observed",
    "vm-details-created", "vm-details-access", "vm-details-command", "copy-vm-ssh", "vm-image-lifecycle-warning",
    "vm-flow-request", "open-flow-request",
    "vm-sandbox-release", "vm-sandbox-release-status", "sandbox-release-form",
    "open-sandbox-glpi", "sandbox-ticket-reference", "sandbox-duration-hours",
    "sandbox-release-reason", "request-sandbox-release",
    "vm-password-management", "vm-password-status", "vm-password-help", "open-guest-password-dialog",
    "guest-password-dialog", "guest-password-form", "guest-password-vm-id", "guest-password-title",
    "guest-password-intro", "new-guest-password", "new-guest-password-confirmation",
    "guest-password-reset-help", "guest-password-reset-error", "close-guest-password-dialog",
    "cancel-guest-password", "save-guest-password",
    "vm-operation-history", "close-vm-details", "operations-checked", "refresh-operations",
    "service-grid", "incident-count", "fleet-filters", "fleet-search", "fleet-status", "fleet-node", "fleet-scope", "fleet-count", "fleet-list", "fleet-empty", "refresh-fleet",
    "mco-generated", "mco-summary", "mco-list", "mco-empty", "refresh-mco",
    "queue-count", "approval-count", "approval-list", "approval-empty", "incident-list", "incident-empty", "lifecycle-count", "lifecycle-list", "lifecycle-empty", "incident-dialog", "incident-form",
    "incident-kind", "incident-id", "incident-action", "incident-dialog-title",
    "incident-dialog-intro", "incident-close-confirmation", "incident-confirm-name",
    "incident-confirm-expected", "incident-error", "close-incident-dialog",
    "cancel-incident", "submit-incident", "settings-form", "guest-password-min-length", "static-ipv4-networks", "default-vm-lifetime-days", "max-vm-lifetime-days", "expiration-warning-days", "expiration-action", "expiration-grace-days", "vm-approval-required", "flow-request-url",
    "save-settings", "settings-error", "network-profile-form", "network-profile-label",
    "network-profile-slug", "network-profile-cidr", "network-profile-gateway",
    "network-profile-dns", "network-profile-bridge", "network-profile-vlan",
    "network-profile-netbox", "save-network-profile", "network-profile-error",
    "network-profile-pool-start", "network-profile-pool-end", "network-profile-excluded",
    "network-profile-manual", "network-profile-automatic", "network-profile-list",
    "network-profile-connectivity", "network-profile-connectivity-description",
    "network-profile-ssh-sources", "network-profile-ntp", "network-profile-apt",
    "network-profile-registry", "network-profile-monitoring",
    "software-module-form", "software-module-label", "software-module-slug",
    "software-module-description", "software-module-mode", "software-module-artifacts",
    "software-module-required", "save-software-module", "software-module-error",
    "software-module-list", "vm-software-modules",
    "vm-connectivity-notice",
    "image-lifecycle-dialog", "image-lifecycle-form", "image-lifecycle-slug",
    "image-lifecycle-title", "image-lifecycle-intro", "image-lifecycle-status",
    "image-supported-until", "image-replacement-slug", "image-lifecycle-error",
    "close-image-lifecycle", "cancel-image-lifecycle", "save-image-lifecycle",
    "proxmox-integration-form", "proxmox-integration-status", "proxmox-api-url",
    "proxmox-token-id", "proxmox-token-secret", "proxmox-ca-certificate",
    "proxmox-clear-ca", "save-proxmox-integration", "proxmox-integration-error",
    "netbox-integration-form", "netbox-integration-status", "netbox-base-url",
    "netbox-api-token", "netbox-ca-certificate", "netbox-clear-ca",
    "save-netbox-integration", "netbox-integration-error", "network-log-dialog",
    "siem-integration-form", "siem-integration-status", "siem-minimum-outcome",
    "siem-pull-token", "generate-siem-token", "siem-enabled", "save-siem-integration", "siem-integration-error",
    "network-log-title", "network-log-intro", "network-log-list", "network-log-empty",
    "close-network-log", "close-network-log-action"
  ].map((id) => [id, document.getElementById(id)])
);

function errorMessage(payload, fallback) {
  if (payload && payload.errors && typeof payload.errors === "object") {
    return Object.values(payload.errors).join(" ");
  }
  const known = {
    invalid_credentials: "Identifiant ou mot de passe incorrect.",
    too_many_attempts: "Trop de tentatives. Réessayez plus tard.",
    local_auth_disabled: "La connexion locale est désactivée.",
    ldap_access_denied: "Votre compte n'appartient à aucun groupe LDAP autorisé.",
    ldap_unavailable: "Le service LDAP/LDAPS est momentanément indisponible.",
    csrf_validation_failed: "La session a expiré. Reconnectez-vous.",
    pve_unavailable: "Proxmox est momentanément indisponible.",
    password_pusher_unavailable: "Password Pusher est momentanément indisponible.",
    quota_exceeded: "Cette demande dépasse votre quota disponible.",
    ip_pool_exhausted: "La plage d’adresses de ce réseau est épuisée.",
    name_conflict: "Une machine active utilise déjà ce nom.",
    vm_expired: "Cette machine a expiré. Un administrateur doit prolonger sa mise à disposition avant de la redémarrer.",
    lifecycle_limit_exceeded: "Cette prolongation dépasserait la durée maximale autorisée.",
    self_admin_protection: "Vous ne pouvez pas désactiver ou rétrograder votre propre compte administrateur.",
    last_admin_protection: "Le dernier administrateur actif doit être conservé.",
    external_identity_managed: "Le rôle et le mot de passe de cette identité sont gérés par son fournisseur d’identité.",
    password_change_required: "Vous devez modifier le mot de passe temporaire.",
    password_reuse: "Choisissez un mot de passe différent du mot de passe temporaire.",
    vm_not_ready: "Cette machine n’est pas encore prête.",
    confirmation_mismatch: "Le nom saisi ne correspond pas à la machine.",
    lifecycle_invalid_state: "Cette action n’est pas disponible dans l’état actuel.",
    operation_in_progress: "Une opération est déjà en cours sur cette machine.",
    maintenance_unavailable: "La maintenance nécessite une VM Cloud-Init démarrée avec QEMU Guest Agent.",
    maintenance_network_isolated: "Reconnectez temporairement la VM avant de contacter les dépôts APT.",
    maintenance_already_active: "Une maintenance est déjà en cours sur cette machine.",
    network_policy_unavailable: "La politique réseau n’est pas disponible pour cette machine.",
    network_policy_forbidden: "Le token Proxmox ne possède pas les droits pare-feu requis.",
    network_policy_not_enforced: "Proxmox n’a pas confirmé l’activation complète du pare-feu.",
    network_log_forbidden: "Le token Proxmox ne peut pas lire le journal pare-feu.",
    sandbox_release_unavailable: "Cette VM ne peut pas demander une ouverture réseau.",
    sandbox_release_already_pending: "Une demande d’ouverture est déjà en attente.",
    sandbox_release_not_pending: "Aucune demande d’ouverture n’est en attente.",
    flow_request_url_missing: "Le formulaire GLPI n’est pas configuré par l’administrateur.",
    guest_password_reset_unavailable: "La modification du mot de passe SSH n’est pas disponible pour cette machine.",
    guest_password_reset_requires_running_vm: "Démarrez la machine avant de modifier son mot de passe SSH.",
    guest_password_reset_permission_denied: "Le token Proxmox n’a pas le droit de modifier le mot de passe invité.",
    guest_agent_unavailable: "QEMU Guest Agent ne répond pas dans cette machine.",
    archive_invalid_state: "Seules les demandes échouées ou les VM supprimées peuvent être archivées.",
    incident_not_open: "Cet incident a déjà été traité.",
    incident_not_resumable: "Aucun identifiant Proxmox exploitable ne permet de reprendre ce suivi.",
    approval_already_decided: "Cette demande a déjà été traitée.",
    forbidden: "Cette action est réservée aux administrateurs."
  };
  return (payload && known[payload.error]) || fallback;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (state.csrfToken && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", state.csrfToken);
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  let payload = null;
  if (response.headers.get("content-type")?.includes("application/json")) payload = await response.json();
  if (!response.ok) {
    const error = new Error(errorMessage(payload, "Une erreur inattendue est survenue."));
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function setBusy(button, busy, busyLabel) {
  if (busy) button.dataset.originalLabel = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? busyLabel : button.dataset.originalLabel;
}

let toastTimer;
function showToast(message) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  toastTimer = window.setTimeout(() => { elements.toast.hidden = true; }, 3500);
}

function showError(element, message) {
  element.textContent = message;
  element.hidden = !message;
}

function showLogin() {
  window.clearTimeout(state.pollTimer);
  state.csrfToken = "";
  state.user = null;
  state.notifications = [];
  state.unreadNotifications = 0;
  if (elements["notifications-dialog"].open) elements["notifications-dialog"].close();
  if (elements["first-password-dialog"].open) elements["first-password-dialog"].close();
  elements["app-shell"].hidden = true;
  elements["login-screen"].hidden = false;
  document.getElementById("username")?.focus();
}

function showApplication(session) {
  state.user = session.user;
  state.usage = session.usage || {};
  state.settings = session.settings || {};
  state.csrfToken = session.csrf_token;
  elements["login-screen"].hidden = true;
  if (session.user.must_rotate_credentials) {
    elements["app-shell"].hidden = true;
    if (!elements["first-password-dialog"].open) elements["first-password-dialog"].showModal();
    elements["first-password"].focus();
    return;
  }
  if (elements["first-password-dialog"].open) elements["first-password-dialog"].close();
  elements["app-shell"].hidden = false;
  elements["user-name"].textContent = session.user.username;
  elements["user-role"].textContent = { admin: "administrateur", operator: "opérateur", user: "utilisateur" }[session.user.role] || session.user.role;
  elements["user-avatar"].textContent = session.user.username.slice(0, 1).toUpperCase();
  elements["open-profile-dialog"].hidden = session.user.role !== "admin";
  const canOperate = ["admin", "operator"].includes(session.user.role);
  elements["operations-nav"].hidden = !canOperate;
  elements["operations-mobile-nav"].hidden = !canOperate;
  elements["admin-nav"].hidden = session.user.role !== "admin";
  elements["admin-mobile-nav"].hidden = session.user.role !== "admin";
  renderQuotas();
  const requestedView = window.location.hash.slice(1);
  switchView(["images", "operations", "admin"].includes(requestedView) ? requestedView : "machines");
  const loaders = [loadProfiles(), loadNetworkProfiles(), loadSoftwareModules(), loadNodes(), loadJobs()];
  if (canOperate) loaders.push(loadOperations(), loadFleet(), loadMcoReport());
  if (session.user.role === "admin") loaders.push(loadUsers(), loadAudit(), loadIntegrations());
  if (session.user.role === "admin") {
    elements["guest-password-min-length"].value = state.settings.guest_password_min_length || 8;
    elements["static-ipv4-networks"].value = state.settings.static_ipv4_networks || "";
    elements["default-vm-lifetime-days"].value = state.settings.default_vm_lifetime_days || 90;
    elements["max-vm-lifetime-days"].value = state.settings.max_vm_lifetime_days || 365;
    elements["expiration-warning-days"].value = state.settings.expiration_warning_days || 14;
    elements["expiration-action"].value = state.settings.expiration_action || "notify_only";
    elements["expiration-grace-days"].value = state.settings.expiration_grace_days || 7;
    elements["vm-approval-required"].checked = Boolean(state.settings.vm_approval_required);
    elements["flow-request-url"].value = state.settings.flow_request_url || "";
  }
  Promise.all(loaders).catch(() => {});
}

async function restoreSession() {
  try {
    showApplication(await api("/api/me"));
  } catch (error) {
    if (error.status !== 401) showError(elements["login-error"], error.message);
    showLogin();
  }
}

async function login(event) {
  event.preventDefault();
  showError(elements["login-error"], "");
  setBusy(elements["login-button"], true, "Connexion…");
  const data = new FormData(elements["login-form"]);
  try {
    const session = await api("/login", {
      method: "POST",
      body: JSON.stringify({ username: data.get("username"), password: data.get("password") })
    });
    elements["login-form"].reset();
    showApplication(session);
  } catch (error) {
    showError(elements["login-error"], error.message);
  } finally {
    setBusy(elements["login-button"], false, "");
  }
}

async function logout() {
  try {
    await api("/logout", { method: "POST" });
  } catch (error) {
    if (error.status !== 401 && error.status !== 403) showToast(error.message);
  }
  showLogin();
}

async function saveFirstPassword(event) {
  event.preventDefault();
  showError(elements["first-password-error"], "");
  const password = elements["first-password"].value;
  const confirmation = elements["first-password-confirmation"].value;
  if (password !== confirmation) {
    showError(elements["first-password-error"], "Les mots de passe diffèrent.");
    return;
  }
  setBusy(elements["save-first-password"], true, "Enregistrement…");
  try {
    await api("/api/me/password", {
      method: "POST",
      body: JSON.stringify({ password })
    });
    elements["first-password-form"].reset();
    showApplication(await api("/api/me"));
  } catch (error) {
    showError(elements["first-password-error"], error.message);
  } finally {
    setBusy(elements["save-first-password"], false, "");
  }
}

function switchView(view) {
  if (view === "operations" && !["admin", "operator"].includes(state.user?.role)) view = "machines";
  if (view === "admin" && state.user?.role !== "admin") view = "machines";
  elements["machines-view"].hidden = view !== "machines";
  elements["images-view"].hidden = view !== "images";
  elements["operations-view"].hidden = view !== "operations";
  elements["admin-view"].hidden = view !== "admin";
  document.querySelectorAll("[data-view]").forEach((control) => {
    const active = control.dataset.view === view;
    control.classList.toggle("active", active);
    if (control.matches("a")) {
      if (active) control.setAttribute("aria-current", "page");
      else control.removeAttribute("aria-current");
    }
  });
  window.history.replaceState(null, "", `#${view}`);
}

function formatRam(mebibytes) {
  return mebibytes >= 1024 ? `${(mebibytes / 1024).toLocaleString("fr-FR")} Gio` : `${mebibytes} Mio`;
}

function quotaPercent(used, limit) {
  return limit ? Math.min(100, Math.round((used / limit) * 100)) : 100;
}

function renderQuotas() {
  const quota = state.user.quota;
  const usage = state.usage;
  elements["quota-vms"].textContent = `${usage.vms || 0} / ${quota.vms}`;
  elements["quota-cpu"].textContent = `${usage.cpu || 0} / ${quota.cpu}`;
  elements["quota-ram"].textContent = `${formatRam(usage.ram_mb || 0)} / ${formatRam(quota.ram_mb)}`;
  elements["quota-disk"].textContent = `${usage.disk_gb || 0} / ${quota.disk_gb} Gio`;
  for (const field of ["vms", "cpu", "ram", "disk"]) {
    const usageField = field === "ram" ? "ram_mb" : field === "disk" ? "disk_gb" : field;
    elements[`quota-${field}-progress`].value = quotaPercent(usage[usageField] || 0, quota[usageField]);
  }
}

function appendText(parent, tag, text, className) {
  const child = document.createElement(tag);
  child.textContent = text;
  if (className) child.className = className;
  parent.append(child);
  return child;
}

function renderProfile(profile) {
  const card = document.createElement("article");
  card.className = `profile-card${profile.enabled && profile.lifecycle_status === "active" ? "" : " disabled"}`;

  const top = document.createElement("div");
  top.className = "profile-top";
  appendText(top, "div", profile.source_type === "cloud_init" ? "CI" : "ISO", "profile-icon");
  const title = document.createElement("div");
  title.className = "profile-title";
  appendText(title, "h3", profile.label);
  appendText(title, "p", profile.description || "Aucune description");
  top.append(title);
  const lifecycleLabel = ({ active: profile.enabled ? "Active" : "Suspendue", deprecated: "Dépréciée", retired: "Retirée" })[profile.lifecycle_status] || "Suspendue";
  appendText(top, "span", lifecycleLabel, `badge ${profile.lifecycle_status === "active" && profile.enabled ? "badge-active" : "badge-disabled"}`);
  card.append(top);

  const meta = document.createElement("div");
  meta.className = "profile-meta";
  appendText(meta, "span", `# ${profile.slug}`);
  appendText(meta, "span", `Version ${profile.version}`);
  appendText(meta, "span", profile.source_type === "cloud_init" ? `${profile.template_node} · VMID ${profile.template_vmid}` : profile.iso);
  if (profile.supported_until) appendText(meta, "span", `Support jusqu’au ${new Date(`${profile.supported_until}T00:00:00`).toLocaleDateString("fr-FR")}`);
  if (profile.replacement_slug) appendText(meta, "span", `Remplacement : ${profile.replacement_slug}`);
  card.append(meta);

  const actions = document.createElement("div");
  actions.className = "profile-actions";
  appendText(actions, "span", profile.automatic_guest_access ? "✓ Accès sudo automatisé" : "Installation ISO", `access-label${profile.automatic_guest_access ? "" : " manual"}`);
  if (state.user.role === "admin") {
    if (profile.lifecycle_status === "active") {
      const toggle = appendText(actions, "button", profile.enabled ? "Suspendre" : "Réactiver", "switch-button");
      toggle.type = "button";
      toggle.addEventListener("click", () => toggleProfile(profile, toggle));
    }
    const lifecycle = appendText(actions, "button", "Cycle de vie", "switch-button");
    lifecycle.type = "button";
    lifecycle.addEventListener("click", () => openImageLifecycle(profile));
  }
  card.append(actions);
  return card;
}

function renderProfiles() {
  const active = state.profiles.filter((profile) => profile.enabled && profile.lifecycle_status === "active").length;
  const cloud = state.profiles.filter((profile) => profile.enabled && profile.lifecycle_status === "active" && profile.automatic_guest_access).length;
  elements["stat-active"].textContent = String(active);
  elements["stat-cloud"].textContent = String(cloud);
  elements["stat-disabled"].textContent = String(state.profiles.length - active);
  elements["profile-count"].textContent = `${state.profiles.length} profil${state.profiles.length > 1 ? "s" : ""} enregistré${state.profiles.length > 1 ? "s" : ""}`;
  elements["profile-grid"].replaceChildren(...state.profiles.map(renderProfile));
  elements["empty-state"].hidden = state.profiles.length !== 0;
  const activeProfiles = state.profiles.filter((profile) => profile.enabled && profile.lifecycle_status === "active");
  elements["vm-profile"].replaceChildren();
  if (!activeProfiles.length) {
    const option = new Option("Aucune image disponible", "");
    option.disabled = true;
    option.selected = true;
    elements["vm-profile"].add(option);
  } else {
    activeProfiles.forEach((profile) => {
      const option = new Option(profile.label, profile.slug);
      option.dataset.cloudInit = String(profile.automatic_guest_access);
      option.dataset.templateNode = profile.template_node || "";
      elements["vm-profile"].add(option);
    });
  }
  updateGuestAccessField();
}

async function loadProfiles() {
  elements["refresh-profiles"].disabled = true;
  try {
    const endpoint = state.user.role === "admin" ? "/api/admin/image-profiles" : "/api/image-profiles";
    state.profiles = (await api(endpoint)).profiles;
    renderProfiles();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["profile-count"].textContent = error.message;
  } finally {
    elements["refresh-profiles"].disabled = false;
  }
}

function integrationStatusLabel(integration) {
  if (!integration?.configured) return "Non configuré";
  const source = integration.source === "portal" ? "géré par le portail" : "configuration de secours du serveur";
  return `${integration.enabled ? "Activé" : "Désactivé"} · ${source}${integration.ca_configured ? " · CA interne" : ""}`;
}

async function loadIntegrations() {
  const [proxmox, netbox, siem] = await Promise.all([
    api("/api/admin/integrations/proxmox"),
    api("/api/admin/integrations/netbox"),
    api("/api/admin/integrations/siem")
  ]);
  state.integrations = { proxmox: proxmox.integration, netbox: netbox.integration, siem: siem.integration };
  elements["proxmox-api-url"].value = proxmox.integration.api_url || "";
  elements["proxmox-token-id"].value = proxmox.integration.token_id || "";
  elements["proxmox-token-secret"].value = "";
  elements["proxmox-ca-certificate"].value = "";
  elements["proxmox-clear-ca"].checked = false;
  elements["proxmox-integration-status"].textContent = integrationStatusLabel(proxmox.integration);
  elements["netbox-base-url"].value = netbox.integration.base_url || "";
  elements["netbox-api-token"].value = "";
  elements["netbox-ca-certificate"].value = "";
  elements["netbox-clear-ca"].checked = false;
  elements["netbox-integration-status"].textContent = integrationStatusLabel(netbox.integration);
  elements["siem-minimum-outcome"].value = siem.integration.minimum_outcome || "all";
  elements["siem-pull-token"].value = "";
  elements["siem-enabled"].checked = Boolean(siem.integration.enabled);
  elements["siem-integration-status"].textContent = siem.integration.configured
    ? `${siem.integration.enabled ? "Collecte autorisée" : "Désactivé"} · jeton configuré`
    : "Non configuré · aucune exposition SIEM";
}

async function saveProxmoxIntegration(event) {
  event.preventDefault();
  showError(elements["proxmox-integration-error"], "");
  setBusy(elements["save-proxmox-integration"], true, "Test en cours…");
  const payload = {
    api_url: elements["proxmox-api-url"].value,
    token_id: elements["proxmox-token-id"].value,
    clear_ca: elements["proxmox-clear-ca"].checked,
    enabled: true
  };
  if (elements["proxmox-token-secret"].value) payload.token_secret = elements["proxmox-token-secret"].value;
  if (elements["proxmox-ca-certificate"].value) payload.ca_certificate = elements["proxmox-ca-certificate"].value;
  try {
    const response = await api("/api/admin/integrations/proxmox", { method: "PUT", body: JSON.stringify(payload) });
    showToast(`Cluster Proxmox raccordé · ${response.integration.nodes.length} nœud(s) visible(s).`);
    await Promise.all([loadIntegrations(), loadNodes(), loadOperations(), loadAudit()]);
  } catch (error) {
    showError(elements["proxmox-integration-error"], error.message);
  } finally {
    setBusy(elements["save-proxmox-integration"], false, "");
  }
}

async function saveNetBoxIntegration(event) {
  event.preventDefault();
  showError(elements["netbox-integration-error"], "");
  setBusy(elements["save-netbox-integration"], true, "Test en cours…");
  const payload = {
    base_url: elements["netbox-base-url"].value,
    clear_ca: elements["netbox-clear-ca"].checked,
    enabled: true
  };
  if (elements["netbox-api-token"].value) payload.api_token = elements["netbox-api-token"].value;
  if (elements["netbox-ca-certificate"].value) payload.ca_certificate = elements["netbox-ca-certificate"].value;
  try {
    await api("/api/admin/integrations/netbox", { method: "PUT", body: JSON.stringify(payload) });
    showToast("NetBox raccordé et token validé.");
    await Promise.all([loadIntegrations(), loadNetworkProfiles(), loadAudit()]);
  } catch (error) {
    showError(elements["netbox-integration-error"], error.message);
  } finally {
    setBusy(elements["save-netbox-integration"], false, "");
  }
}

function renderNetworkProfiles() {
  const select = elements["vm-network-profile"];
  const activeProfiles = state.networkProfiles.filter((profile) => profile.enabled !== false);
  const placeholder = new Option(activeProfiles.length ? "Choisissez un réseau / VLAN" : "Réseau par défaut du template", "");
  placeholder.disabled = activeProfiles.length > 0;
  placeholder.selected = true;
  select.replaceChildren(placeholder);
  select.required = activeProfiles.length > 0;
  activeProfiles.forEach((profile) => {
    const suffix = profile.vlan_tag ? ` · VLAN ${profile.vlan_tag}` : "";
    select.add(new Option(`${profile.label} · ${profile.cidr}${suffix} · ${connectivityLabel(profile.connectivity_mode)}`, profile.slug));
  });
  if (state.user.role !== "admin") return;
  const list = elements["network-profile-list"];
  list.replaceChildren();
  state.networkProfiles.forEach((profile) => {
    const row = document.createElement("article");
    row.className = "user-card";
    const copy = document.createElement("div");
    appendText(copy, "strong", profile.label);
    const allocation = profile.allow_automatic_ip
      ? ` · Auto ${profile.pool_start}–${profile.pool_end}`
      : " · IP manuelle";
    appendText(copy, "span", `${profile.cidr} · ${profile.bridge}${profile.vlan_tag ? ` · VLAN ${profile.vlan_tag}` : ""}${profile.netbox_managed ? " · NetBox" : ""}${allocation} · ${connectivityLabel(profile.connectivity_mode)}`);
    if (profile.connectivity_description) appendText(copy, "span", profile.connectivity_description);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "button button-secondary";
    button.textContent = profile.enabled ? "Suspendre" : "Réactiver";
    button.addEventListener("click", () => toggleNetworkProfile(profile, button));
    row.append(copy, button);
    list.append(row);
  });
}

async function loadNetworkProfiles() {
  const endpoint = state.user.role === "admin" ? "/api/admin/network-profiles" : "/api/network-profiles";
  state.networkProfiles = (await api(endpoint)).profiles;
  renderNetworkProfiles();
}

function renderSoftwareModules() {
  const picker = elements["vm-software-modules"];
  picker.replaceChildren();
  state.softwareModules.filter((module) => module.enabled !== false).forEach((module) => {
    const label = document.createElement("label");
    label.className = "active-checkbox software-module-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = module.slug;
    input.checked = Boolean(module.required);
    input.disabled = Boolean(module.required);
    const copy = document.createElement("span");
    copy.textContent = `${module.label}${module.required ? " · obligatoire" : ""} — ${module.description || module.install_mode}`;
    label.append(input, copy);
    picker.append(label);
  });
  if (state.user?.role !== "admin") return;
  const list = elements["software-module-list"];
  list.replaceChildren();
  state.softwareModules.forEach((module) => {
    const row = document.createElement("article");
    row.className = "user-card";
    const copy = document.createElement("div");
    appendText(copy, "strong", module.label);
    appendText(copy, "span", `${module.install_mode} · ${module.artifacts.join(", ")}${module.required ? " · obligatoire" : ""}`);
    const button = appendText(row, "button", module.enabled ? "Suspendre" : "Réactiver", "button button-secondary");
    button.type = "button";
    button.addEventListener("click", async () => {
      setBusy(button, true, "Mise à jour…");
      try {
        await api(`/api/admin/software-modules/${encodeURIComponent(module.slug)}`, {
          method: "PATCH", body: JSON.stringify({ enabled: !module.enabled })
        });
        await loadSoftwareModules();
      } catch (error) { showToast(error.message); setBusy(button, false, ""); }
    });
    row.append(copy, button);
    list.append(row);
  });
}

async function loadSoftwareModules() {
  const endpoint = state.user?.role === "admin" ? "/api/admin/software-modules" : "/api/software-modules";
  state.softwareModules = (await api(endpoint)).modules;
  renderSoftwareModules();
}

async function saveSoftwareModule(event) {
  event.preventDefault();
  showError(elements["software-module-error"], "");
  setBusy(elements["save-software-module"], true, "Ajout…");
  try {
    await api("/api/admin/software-modules", {
      method: "POST",
      body: JSON.stringify({
        slug: elements["software-module-slug"].value,
        label: elements["software-module-label"].value,
        description: elements["software-module-description"].value.trim(),
        install_mode: elements["software-module-mode"].value,
        artifacts: elements["software-module-artifacts"].value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
        required: elements["software-module-required"].checked,
        enabled: true
      })
    });
    elements["software-module-form"].reset();
    showToast("Module logiciel publié.");
    await loadSoftwareModules();
  } catch (error) { showError(elements["software-module-error"], error.message); }
  finally { setBusy(elements["save-software-module"], false, ""); }
}

async function toggleNetworkProfile(profile, button) {
  setBusy(button, true, "Mise à jour…");
  try {
    await api(`/api/admin/network-profiles/${encodeURIComponent(profile.slug)}`, {
      method: "PATCH", body: JSON.stringify({ enabled: !profile.enabled })
    });
    await loadNetworkProfiles();
  } catch (error) {
    showToast(error.message);
    setBusy(button, false, "");
  }
}

async function saveNetworkProfile(event) {
  event.preventDefault();
  showError(elements["network-profile-error"], "");
  setBusy(elements["save-network-profile"], true, "Ajout…");
  const optionalNumber = (id) => elements[id].value ? Number(elements[id].value) : null;
  try {
    await api("/api/admin/network-profiles", {
      method: "POST",
      body: JSON.stringify({
        slug: elements["network-profile-slug"].value,
        label: elements["network-profile-label"].value,
        cidr: elements["network-profile-cidr"].value,
        gateway: elements["network-profile-gateway"].value,
        dns_servers: elements["network-profile-dns"].value.split(",").map((value) => value.trim()).filter(Boolean),
        bridge: elements["network-profile-bridge"].value,
        vlan_tag: optionalNumber("network-profile-vlan"),
        netbox_prefix_id: optionalNumber("network-profile-netbox"),
        pool_start: elements["network-profile-pool-start"].value || null,
        pool_end: elements["network-profile-pool-end"].value || null,
        excluded_ips: elements["network-profile-excluded"].value.split(",").map((value) => value.trim()).filter(Boolean),
        allow_manual_ip: elements["network-profile-manual"].checked,
        allow_automatic_ip: elements["network-profile-automatic"].checked,
        connectivity_mode: elements["network-profile-connectivity"].value,
        connectivity_description: elements["network-profile-connectivity-description"].value.trim(),
        sandbox_ssh_sources: elements["network-profile-ssh-sources"].value.split(",").map((value) => value.trim()).filter(Boolean),
        sandbox_ntp_servers: elements["network-profile-ntp"].value.split(",").map((value) => value.trim()).filter(Boolean),
        sandbox_apt_endpoints: elements["network-profile-apt"].value.split(",").map((value) => value.trim()).filter(Boolean),
        sandbox_registry_endpoints: elements["network-profile-registry"].value.split(",").map((value) => value.trim()).filter(Boolean),
        sandbox_monitoring_endpoints: elements["network-profile-monitoring"].value.split(",").map((value) => value.trim()).filter(Boolean),
        enabled: true
      })
    });
    elements["network-profile-form"].reset();
    elements["network-profile-bridge"].value = "vmbr0";
    elements["network-profile-manual"].checked = true;
    elements["network-profile-connectivity"].value = "sandbox";
    updateNetworkPoolFields();
    showToast("Réseau ajouté.");
    await loadNetworkProfiles();
  } catch (error) {
    showError(elements["network-profile-error"], error.message);
  } finally {
    setBusy(elements["save-network-profile"], false, "");
  }
}

function updateNetworkPoolFields() {
  const enabled = elements["network-profile-automatic"].checked;
  elements["network-profile-pool-start"].required = enabled;
  elements["network-profile-pool-end"].required = enabled;
  elements["network-profile-pool-start"].disabled = !enabled;
  elements["network-profile-pool-end"].disabled = !enabled;
  elements["network-profile-excluded"].disabled = !enabled;
}

async function toggleProfile(profile, button) {
  setBusy(button, true, "Mise à jour…");
  try {
    await api(`/api/admin/image-profiles/${encodeURIComponent(profile.slug)}`, {
      method: "PATCH", body: JSON.stringify({ enabled: !profile.enabled })
    });
    showToast(profile.enabled ? "Image suspendue." : "Image réactivée.");
    await loadProfiles();
  } catch (error) {
    showToast(error.message);
    setBusy(button, false, "");
  }
}

function fillSelect(select, values, emptyLabel) {
  select.replaceChildren();
  if (!values.length) {
    const option = new Option(emptyLabel, "");
    option.disabled = true;
    option.selected = true;
    select.add(option);
    return;
  }
  values.forEach((value) => select.add(new Option(value, value)));
}

async function loadNodes() {
  state.nodes = (await api("/api/nodes")).nodes;
  fillSelect(elements["template-node"], state.nodes, "Aucun nœud disponible");
  fillSelect(elements["iso-node"], state.nodes, "Aucun nœud disponible");
  fillSelect(elements["vm-node"], state.nodes, "Aucun nœud disponible");
  updateGuestAccessField();
  if (state.nodes.length) await loadIsos(state.nodes[0]);
}

async function loadIsos(node) {
  elements["profile-iso"].disabled = true;
  try {
    const isos = (await api(`/api/nodes/${encodeURIComponent(node)}/isos`)).isos;
    fillSelect(elements["profile-iso"], isos, "Aucune ISO disponible");
  } catch (error) {
    fillSelect(elements["profile-iso"], [], error.message);
  } finally {
    elements["profile-iso"].disabled = false;
  }
}

const terminalStatuses = new Set(["approval_pending", "succeeded", "failed", "attention"]);
const statusLabels = {
  approval_pending: "En attente d’approbation", queued: "En file", validating: "Validation", submitting: "Création",
  submitted: "En cours", polling: "En cours", succeeded: "Prête",
  failed: "Échec", attention: "À vérifier"
};
const vmStatusLabels = {
  pending_approval: "Approbation requise", queued: "Réservée", provisioning: "Provisionnement", accepted: "Prête",
  running: "Démarrée", stopped: "Arrêtée", rejected: "Refusée", failed: "Échec", deleted: "Supprimée"
};
const operationLabels = { start: "Démarrage", stop: "Arrêt", reboot: "Redémarrage", delete: "Suppression" };
const activeOperationStatuses = new Set(["queued", "submitting", "submitted", "polling"]);
const jobErrorLabels = {
  iso_unavailable: "ISO indisponible sur ce nœud",
  template_unavailable: "Template indisponible",
  pve_task_failed: "Proxmox a refusé la création",
  pve_inventory_invalid: "Inventaire Proxmox invalide",
  pve_create_unknown: "État Proxmox à vérifier",
  pve_start_unknown: "Démarrage à vérifier",
  pve_status_unknown: "État réel Proxmox indisponible",
  pve_operation_rejected: "Action refusée par Proxmox",
  pve_operation_failed: "Action échouée dans Proxmox",
  vm_must_be_stopped: "Arrêtez la VM avant de la supprimer",
  password_pusher_not_configured: "Remise d’accès indisponible",
  password_pusher_unavailable: "Password Pusher indisponible",
  approval_rejected: "Demande refusée par un administrateur",
  maintenance_vm_not_running: "La VM doit être démarrée",
  maintenance_network_isolated: "La VM est isolée du réseau",
  maintenance_agent_rejected: "QEMU Guest Agent a refusé la maintenance",
  maintenance_submission_unknown: "Soumission de maintenance à vérifier",
  maintenance_status_unknown: "Résultat de maintenance à vérifier",
  maintenance_command_failed: "La commande APT a échoué",
  guest_agent_not_ready: "QEMU Guest Agent n’est pas encore prêt",
  module_install_submission_invalid: "Le lancement des modules a échoué",
  module_install_status_unknown: "Installation des modules à vérifier",
  module_install_failed: "Un module logiciel n’a pas pu être installé"
};

function jobStatusClass(status) {
  if (status === "succeeded") return "status-success";
  if (status === "failed") return "status-error";
  if (status === "attention") return "status-attention";
  if (status === "approval_pending") return "status-attention";
  return "status-progress";
}

function renderJob(job) {
  const card = document.createElement("article");
  card.className = "job-card";
  const main = document.createElement("div");
  main.className = "job-main";
  appendText(main, "div", "VM", "vm-icon");
  const identity = document.createElement("div");
  appendText(identity, "strong", job.vm.name);
  const placement = `${job.vm.node}${job.vm.vmid ? ` · VMID ${job.vm.vmid}` : " · VMID en attente"}`;
  appendText(identity, "span", `${placement} · ${vmStatusLabels[job.vm.status] || job.vm.status}`);
  main.append(identity);
  card.append(main);

  const resources = document.createElement("div");
  resources.className = "job-resources";
  appendText(resources, "span", `${job.vm.cpu} vCPU · ${formatRam(job.vm.ram_mb)} · ${job.vm.disk_gb} Gio`);
  appendText(resources, "span", `Image ${job.vm.profile || "retirée"} · ${new Date(job.created_at).toLocaleString("fr-FR")}`);
  appendText(resources, "span", job.vm.network_mode === "static" ? `Réseau fixe : ${job.vm.ipv4_cidr}` : "Réseau : DHCP");
  if (job.vm.lifecycle?.expires_at) {
    const label = job.vm.lifecycle.state === "expired" ? "Expirée" : `Échéance : ${new Date(job.vm.lifecycle.expires_at).toLocaleDateString("fr-FR")}`;
    appendText(resources, "span", label, job.vm.lifecycle.state === "expired" ? "job-error" : "");
  } else {
    appendText(resources, "span", "Échéance : non gérée");
  }
  if (job.vm.guest_username) appendText(resources, "span", `SSH : ${job.vm.guest_username}`);
  if (job.vm.ssh_password_change?.requested) {
    appendText(resources, "span", "Renouvellement du mot de passe SSH demandé", "password-reset-pending");
  }
  const displayedIp = job.network?.ipv4 || job.network?.last_ipv4 || job.vm.last_ipv4;
  if (displayedIp) {
    appendText(resources, "span", `IPv4 : ${displayedIp}${job.network?.status === "ready" ? "" : " (dernière connue)"}`);
  } else if (job.vm.status === "running" && job.vm.guest_username) {
    appendText(resources, "span", "IPv4 : attribution en cours");
  }
  card.append(resources);

  const result = document.createElement("div");
  result.className = "job-result";
  if (job.error_code) appendText(result, "span", jobErrorLabels[job.error_code] || "Une vérification est nécessaire", "job-error");
  if (job.vm.approval?.status === "rejected" && job.vm.approval.reason) {
    appendText(result, "span", `Motif : ${job.vm.approval.reason}`, "job-error");
  }
  if (job.guest_access) {
    const access = appendText(result, "a", "Voir l’accès", "credential-button");
    access.href = job.guest_access.password_url;
    access.target = "_blank";
    access.rel = "noopener noreferrer";
    access.title = `Compte ${job.guest_access.username} · ${job.guest_access.expire_after_views} vue(s) maximum`;
  }
  if (displayedIp && job.vm.guest_username) {
    const command = `ssh ${job.vm.guest_username}@${displayedIp}`;
    const copy = appendText(result, "button", "Copier SSH", "credential-button");
    copy.type = "button";
    copy.title = command;
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(command);
        showToast(`Commande copiée : ${command}`);
      } catch (_error) {
        showToast(`Commande SSH : ${command}`);
      }
    });
  }
  if (job.operation && activeOperationStatuses.has(job.operation.status)) {
    appendText(result, "span", `${operationLabels[job.operation.action]} en cours`, "job-status status-progress");
  } else if (job.operation?.status === "attention") {
    appendText(result, "span", `${operationLabels[job.operation.action]} à vérifier`, "job-error");
  }
  appendText(result, "span", statusLabels[job.status] || job.status, `job-status ${jobStatusClass(job.status)}`);
  const controls = lifecycleControls(job);
  const actions = document.createElement("div");
  actions.className = "vm-actions";
  const details = appendText(actions, "button", "Détails", "vm-action-button");
  details.type = "button";
  details.addEventListener("click", () => openVmDetails(job));
  if (job.vm.guest_username && job.vm.vmid && !["deleted", "rejected", "failed"].includes(job.vm.status)) {
    const password = appendText(
      actions,
      "button",
      job.vm.ssh_password_change?.requested ? "Choisir le mot de passe SSH" : "Modifier le mot de passe SSH",
      `vm-action-button${job.vm.ssh_password_change?.requested ? " password-requested" : ""}`
    );
    password.type = "button";
    password.addEventListener("click", () => openGuestPasswordDialog(job));
  }
  controls.forEach(({ action, label, danger }) => {
    const button = appendText(actions, "button", label, `vm-action-button${danger ? " danger" : ""}`);
    button.type = "button";
    button.addEventListener("click", () => openVmActionDialog(job, action));
  });
  if (["rejected", "failed", "deleted"].includes(job.vm.status)) {
    const archived = Boolean(job.archived_at);
    const archive = appendText(actions, "button", archived ? "Restaurer" : "Archiver", "vm-action-button");
    archive.type = "button";
    archive.addEventListener("click", () => setVmArchived(job, !archived));
  }
  result.append(actions);
  card.append(result);
  return card;
}

function lifecycleControls(job) {
  if (job.status !== "succeeded" || activeOperationStatuses.has(job.operation?.status)) return [];
  if (["accepted", "stopped"].includes(job.vm.status)) {
    if (job.vm.lifecycle?.state === "expired") {
      return [{ action: "delete", label: "Supprimer", danger: true }];
    }
    return [{ action: "start", label: "Démarrer" }, { action: "delete", label: "Supprimer", danger: true }];
  }
  if (job.vm.status === "running") {
    return [{ action: "stop", label: "Arrêter" }, { action: "reboot", label: "Redémarrer" }];
  }
  return [];
}

function renderJobs() {
  elements["job-list"].replaceChildren(...state.jobs.map(renderJob));
  elements["jobs-empty"].hidden = state.jobs.length !== 0;
  elements["job-count"].textContent = `${state.jobs.length} demande${state.jobs.length > 1 ? "s" : ""} ${state.showArchived ? "archivée" : "récente"}${state.jobs.length > 1 ? "s" : ""}`;
  elements["show-archived"].textContent = state.showArchived ? "Voir les demandes" : "Voir les archives";
}

function scheduleJobPoll() {
  window.clearTimeout(state.pollTimer);
  if (state.jobs.some((job) =>
    !terminalStatuses.has(job.status)
    || activeOperationStatuses.has(job.operation?.status)
    || (job.vm.status === "running" && job.vm.guest_username && job.network?.status !== "ready")
  )) {
    state.pollTimer = window.setTimeout(loadJobs, 5000);
  }
}

async function loadJobs() {
  elements["refresh-jobs"].disabled = true;
  try {
    const historyPath = state.showArchived ? "/api/jobs?archived=only" : "/api/jobs";
    const [history, session] = await Promise.all([api(historyPath), api("/api/me")]);
    state.jobs = history.jobs;
    await Promise.all(state.jobs.map(async (job) => {
      if (!["running", "stopped", "accepted"].includes(job.vm.status) || !job.vm.vmid || !job.vm.guest_username) return;
      try {
        job.network = await api(`/api/vms/${encodeURIComponent(job.vm_id)}/network`);
      } catch (_error) {
        job.network = { status: "temporarily_unavailable", ipv4_addresses: [] };
      }
    }));
    state.usage = session.usage;
    state.csrfToken = session.csrf_token;
    renderQuotas();
    renderJobs();
    scheduleJobPoll();
    await loadNotifications(false);
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["job-count"].textContent = error.message;
  } finally {
    elements["refresh-jobs"].disabled = false;
  }
}

function renderNotificationBadge() {
  const count = state.unreadNotifications;
  elements["notification-badge"].textContent = count > 99 ? "99+" : String(count);
  elements["notification-badge"].hidden = count === 0;
  elements["notifications-button"].setAttribute(
    "aria-label",
    count ? `Ouvrir les notifications, ${count} non lue(s)` : "Ouvrir les notifications"
  );
}

function renderNotifications() {
  const cards = state.notifications.map((notification) => {
    const item = document.createElement("article");
    item.className = `notification-item${notification.read_at ? "" : " unread"}`;
    appendText(item, "span", "", "notification-dot");
    const copy = document.createElement("div");
    copy.className = "notification-copy";
    appendText(copy, "strong", notification.title);
    appendText(copy, "p", notification.message);
    appendText(copy, "span", new Date(notification.created_at).toLocaleString("fr-FR"));
    item.append(copy);
    if (!notification.read_at) {
      const read = appendText(item, "button", "Marquer comme lue", "notification-read");
      read.type = "button";
      read.addEventListener("click", () => markNotificationRead(notification, read));
    }
    return item;
  });
  elements["notification-list"].replaceChildren(...cards);
  elements["notifications-empty"].hidden = state.notifications.length !== 0;
  elements["notifications-summary"].textContent = `${state.unreadNotifications} notification${state.unreadNotifications > 1 ? "s" : ""} non lue${state.unreadNotifications > 1 ? "s" : ""}`;
  elements["read-all-notifications"].disabled = state.unreadNotifications === 0;
  renderNotificationBadge();
}

async function loadNotifications(renderList = false) {
  try {
    const response = await api("/api/notifications?limit=50");
    state.notifications = response.notifications;
    state.unreadNotifications = response.unread_count;
    if (renderList) renderNotifications();
    else renderNotificationBadge();
  } catch (error) {
    if (error.status === 401) return;
    if (renderList) elements["notifications-summary"].textContent = error.message;
  }
}

async function openNotifications() {
  elements["notifications-dialog"].showModal();
  await loadNotifications(true);
}

async function markNotificationRead(notification, button) {
  setBusy(button, true, "Lecture…");
  try {
    const response = await api(`/api/notifications/${encodeURIComponent(notification.id)}/read`, { method: "POST" });
    Object.assign(notification, response.notification);
    state.unreadNotifications = Math.max(0, state.unreadNotifications - 1);
    renderNotifications();
  } catch (error) {
    showToast(error.message);
    setBusy(button, false, "");
  }
}

async function markAllNotificationsRead() {
  setBusy(elements["read-all-notifications"], true, "Mise à jour…");
  try {
    await api("/api/notifications/read-all", { method: "POST" });
    await loadNotifications(true);
  } catch (error) {
    showToast(error.message);
  } finally {
    setBusy(elements["read-all-notifications"], false, "");
    elements["read-all-notifications"].disabled = state.unreadNotifications === 0;
  }
}

function closeVmDetails() {
  elements["vm-details-dialog"].close();
  state.detailsVm = null;
}

function generateSiemToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  elements["siem-pull-token"].value = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  elements["siem-pull-token"].type = "text";
  showToast("Jeton généré. Copiez-le dans le coffre du SIEM avant l’enregistrement.");
}

async function saveSiemIntegration(event) {
  event.preventDefault();
  showError(elements["siem-integration-error"], "");
  setBusy(elements["save-siem-integration"], true, "Enregistrement…");
  const payload = {
    minimum_outcome: elements["siem-minimum-outcome"].value,
    enabled: elements["siem-enabled"].checked
  };
  if (elements["siem-pull-token"].value) payload.pull_token = elements["siem-pull-token"].value;
  try {
    await api("/api/admin/integrations/siem", { method: "PUT", body: JSON.stringify(payload) });
    elements["siem-pull-token"].type = "password";
    showToast("Collecte SIEM configurée.");
    await Promise.all([loadIntegrations(), loadAudit()]);
  } catch (error) {
    showError(elements["siem-integration-error"], error.message);
  } finally {
    setBusy(elements["save-siem-integration"], false, "");
  }
}

function openImageLifecycle(profile) {
  elements["image-lifecycle-slug"].value = profile.slug;
  elements["image-lifecycle-title"].textContent = `Cycle de vie · ${profile.label}`;
  elements["image-lifecycle-intro"].textContent = `Version ${profile.version}. Les VM existantes seront signalées, jamais modifiées automatiquement.`;
  elements["image-lifecycle-status"].value = profile.lifecycle_status || "active";
  elements["image-supported-until"].value = profile.supported_until || "";
  const replacement = elements["image-replacement-slug"];
  replacement.replaceChildren(new Option("Aucune", ""));
  state.profiles
    .filter((candidate) => candidate.slug !== profile.slug && candidate.enabled && candidate.lifecycle_status === "active")
    .forEach((candidate) => replacement.add(new Option(`${candidate.label} · ${candidate.version}`, candidate.slug)));
  replacement.value = profile.replacement_slug || "";
  showError(elements["image-lifecycle-error"], "");
  elements["image-lifecycle-dialog"].showModal();
}

function closeImageLifecycle() {
  elements["image-lifecycle-dialog"].close();
}

async function saveImageLifecycle(event) {
  event.preventDefault();
  const status = elements["image-lifecycle-status"].value;
  if (status === "deprecated" && !elements["image-supported-until"].value) {
    return showError(elements["image-lifecycle-error"], "Une date de fin de support est requise pour une image dépréciée.");
  }
  setBusy(elements["save-image-lifecycle"], true, "Enregistrement…");
  try {
    await api(`/api/admin/image-profiles/${encodeURIComponent(elements["image-lifecycle-slug"].value)}`, {
      method: "PATCH",
      body: JSON.stringify({
        lifecycle_status: status,
        supported_until: elements["image-supported-until"].value || null,
        replacement_slug: elements["image-replacement-slug"].value || null
      })
    });
    closeImageLifecycle();
    showToast("Cycle de vie de l’image mis à jour.");
    await Promise.all([loadProfiles(), loadFleet(), loadAudit()]);
  } catch (error) {
    showError(elements["image-lifecycle-error"], error.message);
  } finally {
    setBusy(elements["save-image-lifecycle"], false, "");
  }
}

function connectivityLabel(mode) {
  return ({
    sandbox: "Bac à sable",
    isolated: "Isolé",
    internal: "Interne contrôlé",
    internet: "Internet autorisé",
    ticket_required: "Ouverture sur ticket"
  })[mode] || "Bac à sable";
}

function usagePurposeLabel(purpose) {
  return ({
    technical_test: "Test technique",
    functional_test: "Test fonctionnel",
    training: "Formation ou démonstration",
    security_test: "Test de sécurité autorisé"
  })[purpose] || purpose || "Non renseignée (VM antérieure)";
}

async function openVmDetails(job) {
  elements["vm-details-title"].textContent = job.vm.name;
  elements["vm-details-intro"].textContent = "Chargement des informations de la machine…";
  elements["vm-operation-history"].replaceChildren();
  elements["vm-details-access"].hidden = true;
  elements["vm-password-management"].hidden = true;
  elements["vm-flow-request"].hidden = true;
  elements["vm-sandbox-release"].hidden = true;
  elements["sandbox-release-form"].hidden = false;
  elements["sandbox-ticket-reference"].value = "";
  elements["sandbox-duration-hours"].value = "24";
  elements["sandbox-release-reason"].value = "";
  elements["vm-image-lifecycle-warning"].hidden = true;
  elements["vm-image-lifecycle-warning"].textContent = "";
  state.detailsSshCommand = "";
  state.detailsVm = null;
  elements["vm-details-dialog"].showModal();
  try {
    const detailsResponse = await api(`/api/vms/${encodeURIComponent(job.vm_id)}`);
    const details = detailsResponse.details;
    let network = {
      last_ipv4: details.network.last_ipv4,
      observed_at: details.network.observed_at
    };
    if (details.vm.vmid && details.vm.guest_username && details.vm.status !== "deleted") {
      try {
        network = await api(`/api/vms/${encodeURIComponent(job.vm_id)}/network`);
      } catch (_error) {
        // La dernière observation reste affichable même si Proxmox est indisponible.
      }
    }
    const ip = network.ipv4 || network.last_ipv4 || details.network.last_ipv4;
    elements["vm-details-intro"].textContent = `Identifiant interne ${details.vm_id}`;
    elements["vm-details-status"].textContent = vmStatusLabels[details.vm.status] || details.vm.status;
    elements["vm-details-placement"].textContent = `${details.vm.node}${details.vm.vmid ? ` · VMID ${details.vm.vmid}` : " · VMID en attente"}`;
    elements["vm-details-profile"].textContent = details.profile_label || details.vm.profile || "Profil retiré";
    elements["vm-details-usage"].textContent = usagePurposeLabel(details.vm.usage_purpose);
    const requestedNetwork = details.vm.network_mode === "static" ? `IPv4 fixe ${details.vm.ipv4_cidr}` : "DHCP";
    elements["vm-details-resources"].textContent = `${details.vm.cpu} vCPU · ${formatRam(details.vm.ram_mb)} · ${details.vm.disk_gb} Gio · ${requestedNetwork}`;
    elements["vm-details-ssh-user"].textContent = details.vm.guest_username || "Non automatisé";
    elements["vm-details-ipv4"].textContent = ip || "Non disponible";
    elements["vm-details-observed"].textContent = network.observed_at ? new Date(network.observed_at).toLocaleString("fr-FR") : "Jamais observée";
    elements["vm-details-created"].textContent = new Date(details.created_at).toLocaleString("fr-FR");
    const imageLifecycle = details.vm.image_lifecycle || {};
    const imageWarnings = {
      legacy: "Cette VM est antérieure au suivi des versions d’image.",
      profile_removed: "Le profil d’image d’origine n’existe plus dans le catalogue.",
      retired: "L’image d’origine a été retirée du catalogue.",
      unsupported: "La période de support de l’image d’origine est terminée.",
      deprecated: "L’image d’origine est dépréciée et ne peut plus servir à créer de nouvelles VM.",
      superseded: `Une version plus récente de cette image est disponible (${imageLifecycle.current_version || "version inconnue"}).`
    };
    if (imageWarnings[imageLifecycle.state]) {
      const replacement = imageLifecycle.replacement_slug
        ? ` Image de remplacement recommandée : ${imageLifecycle.replacement_slug}.`
        : "";
      elements["vm-image-lifecycle-warning"].textContent = `${imageWarnings[imageLifecycle.state]}${replacement}`;
      elements["vm-image-lifecycle-warning"].hidden = false;
    }
    state.detailsVm = details;
    if (details.vm.network_policy === "sandbox") {
      const release = details.vm.sandbox_release || {};
      elements["vm-sandbox-release-status"].textContent = release.status === "pending"
        ? `Votre demande ${release.ticket_reference || "GLPI"} est en attente d’une décision administrateur.`
        : release.status === "rejected"
          ? `Dernière demande refusée${release.reason ? ` : ${release.reason}` : "."}`
          : "Les accès hors des services internes approuvés sont bloqués.";
      elements["request-sandbox-release"].disabled = release.status === "pending";
      elements["sandbox-release-form"].hidden = release.status === "pending";
      elements["open-sandbox-glpi"].hidden = !state.settings.flow_request_url;
      elements["open-sandbox-glpi"].href = state.settings.flow_request_url || "#";
      elements["vm-sandbox-release"].hidden = false;
    }
    if (state.settings.flow_request_url && details.vm.network_policy !== "sandbox") {
      elements["open-flow-request"].href = state.settings.flow_request_url;
      elements["vm-flow-request"].hidden = false;
    }
    if (ip && details.vm.guest_username) {
      state.detailsSshCommand = `ssh ${details.vm.guest_username}@${ip}`;
      elements["vm-details-command"].textContent = state.detailsSshCommand;
      elements["vm-details-access"].hidden = false;
    }
    if (details.vm.guest_username && details.vm.vmid && !["deleted", "rejected", "failed"].includes(details.vm.status)) {
      const requested = Boolean(details.vm.ssh_password_change?.requested);
      elements["vm-password-status"].textContent = requested ? "Renouvellement demandé par un administrateur" : "Mot de passe SSH";
      elements["vm-password-help"].textContent = details.vm.status === "running"
        ? "Choisissez un nouveau mot de passe ; sa valeur ne sera pas conservée."
        : "Démarrez la VM avant d’appliquer un nouveau mot de passe.";
      elements["open-guest-password-dialog"].textContent = requested ? "Choisir maintenant" : "Modifier";
      elements["vm-password-management"].classList.toggle("requested", requested);
      elements["vm-password-management"].hidden = false;
    }
    if (!details.operations.length) {
      appendText(elements["vm-operation-history"], "p", "Aucune opération de cycle de vie enregistrée.", "detail-empty");
    } else {
      [...details.operations].reverse().forEach((operation) => {
        const row = document.createElement("div");
        row.className = "vm-operation-row";
        appendText(row, "strong", operationLabels[operation.action] || operation.action);
        appendText(row, "span", statusLabels[operation.status] || operation.status);
        appendText(row, "time", new Date(operation.updated_at).toLocaleString("fr-FR"));
        elements["vm-operation-history"].append(row);
      });
    }
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["vm-details-intro"].textContent = error.message;
  }
}

function openGuestPasswordDialog(record = state.detailsVm) {
  if (!record) return;
  const vm = record.vm || record;
  const vmId = record.vm_id || vm.id;
  if (!vmId) return;
  if (elements["vm-details-dialog"].open) closeVmDetails();
  elements["guest-password-form"].reset();
  elements["guest-password-vm-id"].value = vmId;
  elements["guest-password-title"].textContent = "Nouveau mot de passe SSH";
  elements["guest-password-intro"].textContent = `${vm.name} · compte ${vm.guest_username}`;
  const minimum = Math.max(Number(state.settings.guest_password_min_length || 8), 5);
  elements["new-guest-password"].minLength = minimum;
  elements["new-guest-password-confirmation"].minLength = minimum;
  elements["guest-password-reset-help"].textContent = `Minimum ${minimum} caractères. Le secret est transmis à Proxmox via HTTPS et QEMU Guest Agent, puis oublié par le portail.`;
  showError(elements["guest-password-reset-error"], "");
  elements["guest-password-dialog"].showModal();
  elements["new-guest-password"].focus();
}

function closeGuestPasswordDialog() {
  elements["guest-password-form"].reset();
  elements["guest-password-dialog"].close();
}

async function submitGuestPassword(event) {
  event.preventDefault();
  const password = elements["new-guest-password"].value;
  const confirmation = elements["new-guest-password-confirmation"].value;
  showError(elements["guest-password-reset-error"], "");
  if (password !== confirmation) {
    showError(elements["guest-password-reset-error"], "Les mots de passe diffèrent.");
    return;
  }
  setBusy(elements["save-guest-password"], true, "Application…");
  try {
    const vmId = encodeURIComponent(elements["guest-password-vm-id"].value);
    await api(`/api/vms/${vmId}/guest-password`, {
      method: "POST",
      body: JSON.stringify({ password })
    });
    closeGuestPasswordDialog();
    showToast("Le mot de passe SSH a été modifié et n’a pas été conservé.");
    await Promise.all([loadJobs(), loadNotifications(false)]);
  } catch (error) {
    if (error.status === 401) return showLogin();
    showError(elements["guest-password-reset-error"], error.message);
  } finally {
    setBusy(elements["save-guest-password"], false, "");
  }
}

async function requestSandboxRelease() {
  if (!state.detailsVm) return;
  if (!state.settings.flow_request_url) return showToast(errorMessage({ error: "flow_request_url_missing" }));
  const ticketReference = elements["sandbox-ticket-reference"].value.trim();
  const reason = elements["sandbox-release-reason"].value.trim();
  const durationHours = Number(elements["sandbox-duration-hours"].value);
  try {
    await api(`/api/vms/${encodeURIComponent(state.detailsVm.vm_id)}/sandbox-release-request`, {
      method: "POST",
      body: JSON.stringify({
        reason,
        ticket_reference: ticketReference,
        duration_hours: durationHours
      })
    });
    elements["request-sandbox-release"].disabled = true;
    elements["sandbox-release-form"].hidden = true;
    elements["vm-sandbox-release-status"].textContent = `Votre demande ${ticketReference} est en attente d’une décision administrateur.`;
    showToast("Référence GLPI transmise aux administrateurs.");
    await loadJobs();
  } catch (error) { showToast(error.message); }
}

async function setVmArchived(job, archived) {
  try {
    await api(`/api/vms/${encodeURIComponent(job.vm_id)}/archive`, {
      method: "POST",
      body: JSON.stringify({ archived })
    });
    showToast(archived ? "Demande archivée sans supprimer son historique." : "Demande restaurée dans la liste principale.");
    await loadJobs();
  } catch (error) {
    if (error.status === 401) return showLogin();
    showToast(error.message);
  }
}

async function toggleArchivedJobs() {
  state.showArchived = !state.showArchived;
  await loadJobs();
}

const vmActionCopy = {
  start: ["Démarrer la machine", "Proxmox recevra une demande de démarrage suivie jusqu’à son résultat."],
  stop: ["Arrêter la machine", "Un arrêt propre du système invité sera demandé à Proxmox."],
  reboot: ["Redémarrer la machine", "Le système invité sera redémarré et l’opération sera journalisée."],
  delete: ["Supprimer définitivement", "Cette opération détruit la VM et ses disques dans Proxmox."]
};

function openVmActionDialog(job, action) {
  elements["vm-action-form"].reset();
  elements["vm-action-id"].value = job.vm_id;
  elements["vm-action-kind"].value = action;
  elements["vm-action-title"].textContent = vmActionCopy[action][0];
  elements["vm-action-intro"].textContent = `${job.vm.name} · ${vmActionCopy[action][1]}`;
  elements["vm-delete-confirmation"].hidden = action !== "delete";
  elements["vm-confirm-name"].required = action === "delete";
  elements["vm-confirm-expected"].textContent = job.vm.name;
  elements["submit-vm-action"].classList.toggle("button-danger", action === "delete");
  showError(elements["vm-action-error"], "");
  elements["vm-action-dialog"].showModal();
  if (action === "delete") elements["vm-confirm-name"].focus();
  else elements["submit-vm-action"].focus();
}

function closeVmActionDialog() {
  elements["vm-action-dialog"].close();
}

async function submitVmAction(event) {
  event.preventDefault();
  const action = elements["vm-action-kind"].value;
  const payload = { action };
  if (action === "delete") payload.confirm_name = elements["vm-confirm-name"].value;
  showError(elements["vm-action-error"], "");
  setBusy(elements["submit-vm-action"], true, "Transmission…");
  try {
    await api(`/api/vms/${encodeURIComponent(elements["vm-action-id"].value)}/actions`, {
      method: "POST", body: JSON.stringify(payload)
    });
    closeVmActionDialog();
    showToast(`${operationLabels[action]} placé dans la file.`);
    await loadJobs();
  } catch (error) {
    if (error.status === 401) return showLogin();
    showError(elements["vm-action-error"], error.message);
  } finally {
    setBusy(elements["submit-vm-action"], false, "");
  }
}

function updateGuestAccessField() {
  const option = elements["vm-profile"].selectedOptions[0];
  const automatic = option?.dataset.cloudInit === "true";
  const templateNode = option?.dataset.templateNode || "";
  fillSelect(
    elements["vm-node"],
    automatic && templateNode ? [templateNode] : state.nodes,
    "Aucun nœud disponible"
  );
  elements["guest-access-step"].hidden = !automatic;
  elements["network-step"].hidden = !automatic;
  elements["vm-guest-username"].required = automatic;
  elements["vm-guest-password"].required = automatic;
  elements["vm-guest-password-confirmation"].required = automatic;
  const minimum = state.settings.guest_password_min_length || 8;
  elements["vm-guest-password"].minLength = minimum;
  elements["vm-guest-password-confirmation"].minLength = minimum;
  elements["guest-password-help"].textContent = `Choisissez au moins ${minimum} caractère${minimum > 1 ? "s" : ""}. Aucune autre règle de complexité. Le secret chiffré sera supprimé après configuration.`;
  if (!automatic) {
    elements["vm-guest-username"].value = "";
    elements["vm-guest-password"].value = "";
    elements["vm-guest-password-confirmation"].value = "";
    elements["vm-network-mode"].value = "dhcp";
  }
  updateNetworkFields();
}

function updateNetworkFields() {
  const network = state.networkProfiles.find((profile) => profile.slug === elements["vm-network-profile"].value);
  const notice = elements["vm-connectivity-notice"];
  notice.hidden = !network;
  notice.className = `connectivity-notice connectivity-${network?.connectivity_mode || "sandbox"}`;
  if (network) {
    const enforcement = "La VM sera créée en bac à sable : DROP par défaut, services internes approuvés uniquement.";
    const ticket = network.flow_request_required
      ? " Une demande d’ouverture de flux sera nécessaire."
      : "";
    notice.textContent = `${connectivityLabel(network.connectivity_mode)} — ${network.connectivity_description || "Portée définie par l’administrateur."} ${enforcement}${ticket}`;
  } else {
    notice.textContent = "";
  }
  const automaticOption = elements["vm-network-mode"].querySelector('option[value="automatic"]');
  const manualOption = elements["vm-network-mode"].querySelector('option[value="static"]');
  automaticOption.disabled = !network?.allow_automatic_ip;
  automaticOption.hidden = automaticOption.disabled;
  manualOption.disabled = Boolean(network && !network.allow_manual_ip);
  manualOption.hidden = manualOption.disabled;
  if (elements["vm-network-mode"].selectedOptions[0]?.disabled) {
    elements["vm-network-mode"].value = network?.allow_automatic_ip ? "automatic" : "dhcp";
  }
  const fixed = elements["vm-network-mode"].value === "static";
  elements["vm-static-network"].hidden = !fixed;
  ["vm-ipv4-cidr", "vm-gateway", "vm-dns-servers"].forEach((id) => {
    elements[id].required = fixed;
    if (!fixed) elements[id].value = "";
  });
  if (fixed && network) {
    elements["vm-ipv4-cidr"].placeholder = `Adresse dans ${network.cidr}`;
    elements["vm-gateway"].value = network.gateway;
    elements["vm-dns-servers"].value = network.dns_servers.join(", ");
    elements["vm-gateway"].readOnly = true;
    elements["vm-dns-servers"].readOnly = true;
  } else {
    elements["vm-ipv4-cidr"].placeholder = "192.168.1.50/24";
    elements["vm-gateway"].readOnly = false;
    elements["vm-dns-servers"].readOnly = false;
  }
}

function updateQuotaPreview() {
  const requested = {
    vms: 1,
    cpu: Number(elements["vm-cpu"].value) || 0,
    ram_mb: Number(elements["vm-ram"].value) || 0,
    disk_gb: Number(elements["vm-disk"].value) || 0
  };
  const exceeded = Object.keys(requested).filter((field) => (state.usage[field] || 0) + requested[field] > state.user.quota[field]);
  elements["quota-preview"].classList.toggle("exceeded", exceeded.length > 0);
  elements["quota-preview"].textContent = exceeded.length
    ? `Quota insuffisant : ${exceeded.map((field) => ({ vms: "machines", cpu: "vCPU", ram_mb: "mémoire", disk_gb: "stockage" })[field]).join(", ")}.`
    : "Cette demande respecte vos quotas actuels.";
}

async function openVmDialog() {
  elements["vm-form"].reset();
  elements["vm-lifetime-days"].value = state.settings.default_vm_lifetime_days || 90;
  elements["vm-lifetime-days"].max = state.settings.max_vm_lifetime_days || 365;
  const expirationPolicy = {
    notify_only: "À l’échéance, son redémarrage sera bloqué.",
    quarantine: "À l’échéance, elle sera arrêtée et isolée.",
    delete: `À l’échéance, elle sera isolée puis supprimée après ${state.settings.expiration_grace_days || 7} jour(s).`
  }[state.settings.expiration_action || "notify_only"];
  elements["vm-lifetime-help"].textContent = `Durée maximale autorisée : ${state.settings.max_vm_lifetime_days || 365} jours. ${expirationPolicy}`;
  showError(elements["vm-error"], "");
  updateGuestAccessField();
  updateQuotaPreview();
  elements["vm-dialog"].showModal();
  try {
    if (!state.nodes.length) await loadNodes();
    if (!state.profiles.length) await loadProfiles();
    if (!state.networkProfiles.length) await loadNetworkProfiles();
    if (!elements["vm-node"].value || !elements["vm-profile"].value) {
      showError(elements["vm-error"], "Un nœud et une image active sont requis avant de créer une VM.");
    }
  } catch (error) {
    showError(elements["vm-error"], error.message);
  }
  elements["vm-name"].focus();
}

function closeVmDialog() {
  elements["vm-dialog"].close();
}

async function submitVm(event) {
  event.preventDefault();
  showError(elements["vm-error"], "");
  setBusy(elements["submit-vm"], true, "Réservation…");
  const form = new FormData(elements["vm-form"]);
  const payload = {
    name: form.get("name"), node: form.get("node"), profile: form.get("profile"),
    cpu: Number(form.get("cpu")), ram_mb: Number(form.get("ram_mb")), disk_gb: Number(form.get("disk_gb")),
    lifetime_days: Number(form.get("lifetime_days")),
    usage_purpose: form.get("usage_purpose"),
    no_patient_data_ack: elements["vm-no-patient-data-ack"].checked
  };
  if (!elements["guest-access-step"].hidden) {
    if (elements["vm-guest-password"].value !== elements["vm-guest-password-confirmation"].value) {
      showError(elements["vm-error"], "Les mots de passe SSH diffèrent.");
      setBusy(elements["submit-vm"], false, "");
      return;
    }
    payload.guest_username = form.get("guest_username");
    payload.guest_password = form.get("guest_password");
    payload.software_modules = [...elements["vm-software-modules"].querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
    payload.network_mode = form.get("network_mode") || "dhcp";
    if (form.get("network_profile")) payload.network_profile = form.get("network_profile");
    if (payload.network_mode === "static") {
      payload.ipv4_cidr = form.get("ipv4_cidr");
      payload.gateway = form.get("gateway");
      payload.dns_servers = String(form.get("dns_servers")).split(",").map((value) => value.trim()).filter(Boolean);
    }
  }
  try {
    const response = await api("/api/vms", { method: "POST", body: JSON.stringify(payload) });
    closeVmDialog();
    showToast(response.status === "pending_approval" ? "La demande attend l’approbation d’un administrateur." : "La machine a été réservée et placée dans la file.");
    const session = await api("/api/me");
    state.usage = session.usage;
    state.csrfToken = session.csrf_token;
    renderQuotas();
    await loadJobs();
  } catch (error) {
    showError(elements["vm-error"], error.message);
  } finally {
    setBusy(elements["submit-vm"], false, "");
  }
}

async function saveSettings(event) {
  event.preventDefault();
  showError(elements["settings-error"], "");
  setBusy(elements["save-settings"], true, "Enregistrement…");
  try {
    const minimum = Number(elements["guest-password-min-length"].value);
    const response = await api("/api/admin/settings", {
      method: "PATCH",
      body: JSON.stringify({
        guest_password_min_length: minimum,
        static_ipv4_networks: elements["static-ipv4-networks"].value,
        default_vm_lifetime_days: Number(elements["default-vm-lifetime-days"].value),
        max_vm_lifetime_days: Number(elements["max-vm-lifetime-days"].value),
        expiration_warning_days: Number(elements["expiration-warning-days"].value),
        expiration_action: elements["expiration-action"].value,
        expiration_grace_days: Number(elements["expiration-grace-days"].value),
        vm_approval_required: elements["vm-approval-required"].checked,
        flow_request_url: elements["flow-request-url"].value.trim()
      })
    });
    state.settings = response.settings;
    updateGuestAccessField();
    showToast("Paramètres de provisionnement mis à jour.");
    await loadAudit();
  } catch (error) {
    showError(elements["settings-error"], error.message);
  } finally {
    setBusy(elements["save-settings"], false, "");
  }
}

const serviceLabels = {
  database: "Base PostgreSQL", worker: "Worker", proxmox: "Proxmox",
  password_pusher: "Password Pusher"
};
const serviceStatusLabels = {
  healthy: "Opérationnel", configured: "Configuré", degraded: "Dégradé",
  unavailable: "Indisponible", disabled: "Désactivé", unknown: "En attente"
};

const mcoSummaryLabels = {
  machines: "VM suivies",
  updates_available: "Mises à jour disponibles",
  reboot_required: "Redémarrages requis",
  never_scanned: "Jamais analysées",
  maintenance_failures: "Maintenances en échec",
  expired: "VM expirées",
  lifecycle_warning: "Échéances proches",
  isolated: "VM isolées",
  obsolete_images: "Images à remplacer",
  sandbox_release_requests: "Ouvertures sandbox à traiter"
};

function renderMcoReport() {
  if (!state.mco) return;
  elements["mco-generated"].textContent = `Rapport généré le ${new Date(state.mco.generated_at).toLocaleString("fr-FR")}`;
  const cards = Object.entries(state.mco.summary).map(([key, value]) => {
    const card = document.createElement("article");
    appendText(card, "strong", String(value));
    appendText(card, "span", mcoSummaryLabels[key] || key);
    if (value && key !== "machines") card.className = "mco-alert";
    return card;
  });
  elements["mco-summary"].replaceChildren(...cards);
  const issues = state.mco.items.slice(0, 12).map((item) => {
    const card = document.createElement("article");
    card.className = `incident-card mco-${item.severity}`;
    const identity = document.createElement("div");
    identity.className = "incident-identity";
    appendText(identity, "strong", item.name);
    appendText(identity, "span", `${item.owner} · ${item.node}${item.vmid ? ` · VMID ${item.vmid}` : ""}`);
    card.append(identity);
    appendText(card, "p", item.detail, "incident-detail");
    appendText(card, "span", item.severity === "critical" ? "Critique" : "À planifier", "queue-count");
    return card;
  });
  elements["mco-list"].replaceChildren(...issues);
  elements["mco-empty"].hidden = state.mco.items.length !== 0;
}

async function loadMcoReport() {
  elements["refresh-mco"].disabled = true;
  try {
    state.mco = (await api("/api/admin/mco/report")).report;
    renderMcoReport();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["mco-generated"].textContent = error.message;
  } finally {
    elements["refresh-mco"].disabled = false;
  }
}

function serviceDetail(name, service) {
  if (name === "proxmox") return `${service.online_nodes} nœud(s) en ligne · ${service.latency_ms} ms`;
  if (name === "worker" && service.last_seen_at) return `Dernier signal il y a ${service.age_seconds} s`;
  if (name === "password_pusher" && service.status === "disabled") return "Accès automatique indisponible";
  return serviceStatusLabels[service.status] || service.status;
}

function renderOperations() {
  if (!state.operations) return;
  const services = Object.entries(state.operations.services).map(([name, service]) => {
    const card = document.createElement("article");
    card.className = "service-card";
    appendText(card, "span", "", `service-dot ${service.status}`);
    const copy = document.createElement("div");
    copy.className = "service-copy";
    appendText(copy, "strong", serviceLabels[name] || name);
    appendText(copy, "span", serviceDetail(name, service));
    card.append(copy);
    return card;
  });
  elements["service-grid"].replaceChildren(...services);
  elements["operations-checked"].textContent = `Vérifié le ${new Date(state.operations.checked_at).toLocaleString("fr-FR")}`;
  elements["queue-count"].textContent = `${state.operations.queue.active} tâche${state.operations.queue.active > 1 ? "s" : ""} active${state.operations.queue.active > 1 ? "s" : ""}`;
  elements["incident-count"].textContent = `${state.operations.queue.attention} incident${state.operations.queue.attention > 1 ? "s" : ""} ouvert${state.operations.queue.attention > 1 ? "s" : ""}`;
  elements["incident-list"].replaceChildren(...state.operations.incidents.map(renderIncident));
  elements["incident-empty"].hidden = state.operations.incidents.length !== 0;
  const lifecycle = state.operations.lifecycle || { expired: 0, warning: 0, items: [] };
  elements["lifecycle-count"].textContent = `${lifecycle.expired} expirée(s) · ${lifecycle.warning} proche(s) de l’échéance`;
  elements["lifecycle-list"].replaceChildren(...lifecycle.items.map(renderLifecycleItem));
  elements["lifecycle-empty"].hidden = lifecycle.items.length !== 0;
  const approvals = state.operations.approvals || { pending: 0, items: [] };
  elements["approval-count"].textContent = `${approvals.pending} demande${approvals.pending > 1 ? "s" : ""} en attente`;
  elements["approval-list"].replaceChildren(...approvals.items.map(renderApprovalItem));
  elements["approval-empty"].hidden = approvals.items.length !== 0;
}

function renderApprovalItem(item) {
  const card = document.createElement("article");
  card.className = "incident-card";
  const identity = document.createElement("div");
  identity.className = "incident-identity";
  appendText(identity, "strong", item.name);
  appendText(identity, "span", `${item.owner} · ${item.node} · ${item.profile || "profil retiré"}`);
  card.append(identity);
  const network = item.ipv4_cidr ? ` · IP ${item.ipv4_cidr}` : " · DHCP";
  appendText(card, "p", `${item.cpu} vCPU · ${formatRam(item.ram_mb)} · ${item.disk_gb} Gio${network} · ${new Date(item.requested_at).toLocaleString("fr-FR")}`, "incident-detail");
  if (state.user?.role === "admin") {
    const actions = document.createElement("div");
    actions.className = "incident-actions";
    const approve = appendText(actions, "button", "Approuver", "incident-button");
    approve.type = "button";
    approve.addEventListener("click", () => decideApproval(item, "approve", approve));
    const reject = appendText(actions, "button", "Refuser", "incident-button danger");
    reject.type = "button";
    reject.addEventListener("click", () => decideApproval(item, "reject", reject));
    card.append(actions);
  } else {
    appendText(card, "span", "Lecture seule", "queue-count");
  }
  return card;
}

async function decideApproval(item, action, button) {
  let reason = null;
  if (action === "reject") {
    reason = window.prompt(`Motif du refus pour ${item.name} (visible par l’utilisateur) :`);
    if (reason === null) return;
    reason = reason.trim();
    if (!reason) return showToast("Un motif de refus est requis.");
  } else if (!window.confirm(`Approuver le provisionnement de ${item.name} pour ${item.owner} ?`)) {
    return;
  }
  setBusy(button, true, action === "approve" ? "Approbation…" : "Refus…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(item.id)}/approval`, {
      method: "POST", body: JSON.stringify({ action, reason })
    });
    showToast(action === "approve" ? `${item.name} placée dans la file de provisionnement.` : `${item.name} refusée.`);
    await Promise.all([loadOperations(), loadAudit(), loadUsers()]);
  } catch (error) {
    showToast(error.message);
    setBusy(button, false, "");
  }
}

function renderLifecycleItem(item) {
  const card = document.createElement("article");
  card.className = "incident-card";
  const identity = document.createElement("div");
  identity.className = "incident-identity";
  appendText(identity, "strong", item.name);
  appendText(identity, "span", `${item.owner} · ${item.node}${item.vmid ? ` · VMID ${item.vmid}` : ""}`);
  card.append(identity);
  const wording = item.state === "expired" ? "Expirée" : `${item.days_remaining} jour(s) restant(s)`;
  appendText(card, "p", `${wording} · ${new Date(item.expires_at).toLocaleString("fr-FR")}`, item.state === "expired" ? "job-error" : "incident-detail");
  if (state.user?.role === "admin") {
    const actions = document.createElement("div");
    actions.className = "incident-actions";
    for (const days of [30, 90]) {
      const button = appendText(actions, "button", `+ ${days} jours`, "incident-button");
      button.type = "button";
      button.addEventListener("click", () => extendLifecycle(item, days, button));
    }
    card.append(actions);
  } else {
    appendText(card, "span", "Lecture seule", "queue-count");
  }
  return card;
}

async function extendLifecycle(item, days, button) {
  setBusy(button, true, "Prolongation…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(item.id)}/lifecycle`, {
      method: "PATCH", body: JSON.stringify({ extend_days: days })
    });
    showToast(`${item.name} prolongée de ${days} jours.`);
    await Promise.all([loadOperations(), loadAudit()]);
  } catch (error) {
    showToast(error.message);
    setBusy(button, false, "");
  }
}

function renderIncident(incident) {
  const card = document.createElement("article");
  card.className = "incident-card";
  const identity = document.createElement("div");
  identity.className = "incident-identity";
  appendText(identity, "strong", incident.vm.name);
  appendText(identity, "span", `${incident.vm.owner} · ${incident.vm.node}${incident.vm.vmid ? ` · VMID ${incident.vm.vmid}` : ""}`);
  card.append(identity);
  const action = incident.action === "provision" ? "Provisionnement" : operationLabels[incident.action];
  appendText(card, "p", `${action} · ${jobErrorLabels[incident.error_code] || incident.error_code || "État ambigu"} · ${new Date(incident.updated_at).toLocaleString("fr-FR")}`, "incident-detail");
  if (state.user?.role === "admin") {
    const actions = document.createElement("div");
    actions.className = "incident-actions";
    if (incident.can_resume) {
      const resume = appendText(actions, "button", "Reprendre le suivi", "incident-button");
      resume.type = "button";
      resume.addEventListener("click", () => openIncidentDialog(incident, "resume_tracking"));
    }
    const close = appendText(actions, "button", "Clôturer en échec", "incident-button danger");
    close.type = "button";
    close.addEventListener("click", () => openIncidentDialog(incident, "close_failed"));
    card.append(actions);
  } else {
    appendText(card, "span", "Lecture seule", "queue-count");
  }
  return card;
}

async function loadOperations() {
  elements["refresh-operations"].disabled = true;
  try {
    state.operations = await api("/api/admin/operations");
    renderOperations();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["operations-checked"].textContent = error.message;
  } finally {
    elements["refresh-operations"].disabled = false;
  }
}

function replaceFilterOptions(select, values, emptyLabel, labeler = (value) => value) {
  const selected = select.value;
  select.replaceChildren(new Option(emptyLabel, ""));
  values.forEach((value) => select.add(new Option(labeler(value), value)));
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
}

function renderFleet() {
  if (!state.fleet) return;
  const rows = state.fleet.items.map((vm) => {
    const row = document.createElement("tr");
    const machine = document.createElement("td");
    appendText(machine, "strong", vm.name);
    const imageLifecycle = vm.image_lifecycle || {};
    const version = imageLifecycle.version ? ` · v${imageLifecycle.version}` : "";
    appendText(machine, "span", `${vm.profile || "Profil retiré"}${version}`);
    if (imageLifecycle.state && imageLifecycle.state !== "supported") {
      const imageStateLabels = {
        legacy: "Version non suivie",
        profile_removed: "Profil supprimé",
        retired: "Image retirée",
        unsupported: "Support terminé",
        deprecated: "Image dépréciée",
        superseded: `Nouvelle version ${imageLifecycle.current_version || "disponible"}`
      };
      appendText(machine, "span", imageStateLabels[imageLifecycle.state] || "Image à vérifier", "fleet-image-warning");
    }
    row.append(machine);
    appendText(row, "td", vm.owner);
    appendText(row, "td", `${vm.node}${vm.vmid ? ` · ${vm.vmid}` : " · VMID en attente"}`);
    const network = document.createElement("td");
    appendText(network, "strong", vm.ipv4 || "IP en attente");
    appendText(network, "span", vm.network_policy === "isolated"
      ? "Quarantaine · lien coupé"
      : vm.network_policy === "sandbox"
        ? `Bac à sable · DROP · r${vm.network_policy_revision || 1}`
        : "Ouverture approuvée");
    row.append(network);
    appendText(row, "td", `${vm.cpu} vCPU · ${formatRam(vm.ram_mb)} · ${vm.disk_gb} Gio`);
    const status = appendText(row, "td", vmStatusLabels[vm.status] || vm.status);
    status.className = `fleet-status ${["failed", "rejected"].includes(vm.status) ? "status-error" : ["running", "accepted"].includes(vm.status) ? "status-success" : "status-progress"}`;
    const maintenance = document.createElement("td");
    const maintenanceJob = vm.maintenance;
    if (!maintenanceJob) {
      appendText(maintenance, "strong", "Non analysée");
    } else if (["queued", "submitting", "submitted"].includes(maintenanceJob.status)) {
      appendText(maintenance, "strong", maintenanceJob.action === "update" ? "Mise à jour…" : "Analyse…");
    } else if (maintenanceJob.status === "succeeded") {
      const remaining = maintenanceJob.report?.remaining_count ?? 0;
      appendText(maintenance, "strong", remaining ? `${remaining} disponible${remaining > 1 ? "s" : ""}` : "À jour");
      if (maintenanceJob.report?.reboot_required) appendText(maintenance, "span", "Redémarrage requis");
    } else {
      appendText(maintenance, "strong", "À vérifier");
      appendText(maintenance, "span", jobErrorLabels[maintenanceJob.error_code] || maintenanceJob.error_code || "Échec de maintenance");
    }
    row.append(maintenance);
    const lifecycle = vm.lifecycle || {};
    appendText(row, "td", lifecycle.expires_at ? `${lifecycle.days_remaining} j` : "Non gérée");
    const actions = document.createElement("td");
    actions.className = "fleet-actions";
    let hasAction = false;
    if (
      state.user?.role === "admin"
      && vm.guest_username
      && vm.vmid
      && !["deleted", "rejected", "failed"].includes(vm.status)
    ) {
      const pending = Boolean(vm.ssh_password_change?.requested);
      const reset = appendText(actions, "button", pending ? "Demandée" : "Demander reset SSH", "incident-button");
      reset.type = "button";
      reset.disabled = pending;
      reset.title = pending
        ? `Demande envoyée à ${vm.owner}`
        : `Inviter ${vm.owner} à choisir un nouveau mot de passe SSH`;
      reset.addEventListener("click", () => requestGuestPasswordReset(vm, reset));
      hasAction = true;
    }
    if (
      state.user?.role === "admin"
      && vm.vmid
      && vm.profile
      && vm.status === "running"
    ) {
      const activeMaintenance = ["queued", "submitting", "submitted"].includes(vm.maintenance?.status);
      const scan = appendText(actions, "button", "Analyser APT", "incident-button");
      scan.type = "button";
      scan.disabled = activeMaintenance || vm.network_policy === "isolated";
      scan.addEventListener("click", () => queueMaintenance(vm, "scan", scan));
      const update = appendText(actions, "button", "Mettre à jour", "incident-button");
      update.type = "button";
      update.disabled = activeMaintenance || vm.network_policy === "isolated";
      update.addEventListener("click", () => queueMaintenance(vm, "update", update));
      hasAction = true;
    }
    if (state.user?.role === "admin" && vm.vmid && !["deleted", "rejected", "failed"].includes(vm.status)) {
      const isolated = vm.network_policy === "isolated";
      const policy = appendText(actions, "button", isolated ? "Remettre en sandbox" : "Mettre en quarantaine", isolated ? "incident-button" : "incident-button danger");
      policy.type = "button";
      policy.addEventListener("click", () => changeNetworkPolicy(vm, isolated ? "sandbox" : "isolated", policy));
      if (vm.sandbox_release?.status === "pending") {
        const approve = appendText(actions, "button", "Approuver l’ouverture", "incident-button");
        approve.type = "button";
        approve.title = `${vm.sandbox_release.ticket_reference || "Ticket GLPI absent"} · ${vm.sandbox_release.duration_hours || "?"} h`;
        approve.addEventListener("click", () => decideSandboxRelease(vm, "approve", approve));
        const reject = appendText(actions, "button", "Refuser l’ouverture", "incident-button danger");
        reject.type = "button";
        reject.addEventListener("click", () => decideSandboxRelease(vm, "reject", reject));
      }
      const logs = appendText(actions, "button", "Journal réseau", "incident-button");
      logs.type = "button";
      logs.addEventListener("click", () => openNetworkLog(vm));
      hasAction = true;
    }
    if (!hasAction) appendText(actions, "span", "—");
    row.append(actions);
    return row;
  });
  elements["fleet-list"].replaceChildren(...rows);
  elements["fleet-empty"].hidden = rows.length !== 0;
  elements["fleet-count"].textContent = `${state.fleet.count} machine${state.fleet.count > 1 ? "s" : ""} affichée${state.fleet.count > 1 ? "s" : ""}`;
  replaceFilterOptions(elements["fleet-status"], state.fleet.filters.statuses, "Tous les états", (value) => vmStatusLabels[value] || value);
  replaceFilterOptions(elements["fleet-node"], state.fleet.filters.nodes, "Tous les nœuds");
}

async function queueMaintenance(vm, action, button) {
  if (action === "update" && !window.confirm(`Installer maintenant les mises à jour APT de ${vm.name} ? Aucun redémarrage automatique ne sera effectué.`)) return;
  setBusy(button, true, action === "update" ? "Planification…" : "Analyse…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(vm.id)}/maintenance`, {
      method: "POST",
      body: JSON.stringify({ action })
    });
    showToast(action === "update" ? `Mise à jour de ${vm.name} planifiée.` : `Analyse APT de ${vm.name} planifiée.`);
    await loadFleet();
  } catch (error) {
    if (error.status === 401) return showLogin();
    showToast(error.message);
    setBusy(button, false, "");
  }
}

async function changeNetworkPolicy(vm, policy, button) {
  if (policy === "isolated" && !window.confirm(`Isoler totalement ${vm.name} ? Le SSH, le LAN et Internet seront bloqués par Proxmox.`)) return;
  setBusy(button, true, policy === "isolated" ? "Quarantaine…" : "Sandbox…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(vm.id)}/network-policy`, {
      method: "POST",
      body: JSON.stringify({ policy })
    });
    showToast(policy === "isolated" ? `${vm.name} est en quarantaine totale.` : `${vm.name} est revenue dans son bac à sable.`);
    await Promise.all([loadFleet(), loadAudit()]);
  } catch (error) {
    if (error.status === 401) return showLogin();
    showToast(error.message);
    setBusy(button, false, "");
  }
}

async function decideSandboxRelease(vm, action, button) {
  const requestContext = vm.sandbox_release
    ? `${vm.sandbox_release.ticket_reference || "ticket GLPI inconnu"}, ${vm.sandbox_release.duration_hours || "?"} heure(s)`
    : "demande sans contexte";
  const reason = window.prompt(action === "approve"
    ? `Validation de ${requestContext}. Justification administrative :`
    : "Motif du refus :");
  if (reason === null) return;
  setBusy(button, true, "Décision…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(vm.id)}/sandbox-release-decision`, {
      method: "POST", body: JSON.stringify({ action, reason: reason.trim() })
    });
    showToast(action === "approve" ? `${vm.name} est sortie du bac à sable.` : `Demande refusée pour ${vm.name}.`);
    await Promise.all([loadFleet(), loadAudit()]);
  } catch (error) { showToast(error.message); setBusy(button, false, ""); }
}

async function openNetworkLog(vm) {
  elements["network-log-title"].textContent = `Tentatives réseau · ${vm.name}`;
  elements["network-log-intro"].textContent = "Lecture du journal pare-feu Proxmox…";
  elements["network-log-list"].replaceChildren();
  elements["network-log-empty"].hidden = true;
  elements["network-log-dialog"].showModal();
  try {
    const payload = await api(`/api/admin/vms/${encodeURIComponent(vm.id)}/network-log`);
    const entries = payload.entries.map((entry) => {
      const line = document.createElement("code");
      line.textContent = entry.message;
      return line;
    });
    elements["network-log-list"].replaceChildren(...entries);
    elements["network-log-empty"].hidden = entries.length !== 0;
    elements["network-log-intro"].textContent = payload.policy === "isolated"
      ? "VM isolée : les paquets refusés en entrée et en sortie sont journalisés."
      : "Mode normal : seuls les paquets refusés par les règles Proxmox sont journalisés.";
  } catch (error) {
    elements["network-log-intro"].textContent = error.message;
  }
}

async function requestGuestPasswordReset(vm, button) {
  setBusy(button, true, "Envoi…");
  try {
    await api(`/api/admin/vms/${encodeURIComponent(vm.id)}/guest-password-reset`, {
      method: "POST",
      body: JSON.stringify({})
    });
    showToast(`${vm.owner} a été invité à renouveler le mot de passe SSH de ${vm.name}.`);
    await Promise.all([loadFleet(), loadAudit()]);
  } catch (error) {
    if (error.status === 401) return showLogin();
    showToast(error.message);
    setBusy(button, false, "");
  }
}

async function loadFleet() {
  elements["refresh-fleet"].disabled = true;
  const parameters = new URLSearchParams();
  if (elements["fleet-search"].value.trim()) parameters.set("search", elements["fleet-search"].value.trim());
  if (elements["fleet-status"].value) parameters.set("status", elements["fleet-status"].value);
  if (elements["fleet-node"].value) parameters.set("node", elements["fleet-node"].value);
  parameters.set("scope", elements["fleet-scope"].value);
  try {
    state.fleet = await api(`/api/operations/vms?${parameters}`);
    renderFleet();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["fleet-count"].textContent = error.message;
  } finally {
    elements["refresh-fleet"].disabled = false;
  }
}

function openIncidentDialog(incident, action) {
  elements["incident-form"].reset();
  elements["incident-kind"].value = incident.kind;
  elements["incident-id"].value = incident.id;
  elements["incident-action"].value = action;
  const closing = action === "close_failed";
  elements["incident-dialog-title"].textContent = closing ? "Clôturer en échec" : "Reprendre le suivi Proxmox";
  elements["incident-dialog-intro"].textContent = closing
    ? `Cette décision marque ${incident.vm.name} en échec après votre vérification manuelle dans Proxmox.`
    : `Le worker reprendra uniquement le suivi de l’UPID existant pour ${incident.vm.name}, sans soumettre une nouvelle action.`;
  elements["incident-close-confirmation"].hidden = !closing;
  elements["incident-confirm-name"].required = closing;
  elements["incident-confirm-expected"].textContent = incident.vm.name;
  elements["submit-incident"].classList.toggle("button-danger", closing);
  showError(elements["incident-error"], "");
  elements["incident-dialog"].showModal();
  if (closing) elements["incident-confirm-name"].focus();
  else elements["submit-incident"].focus();
}

function closeIncidentDialog() {
  elements["incident-dialog"].close();
}

async function submitIncident(event) {
  event.preventDefault();
  const action = elements["incident-action"].value;
  const payload = { action };
  if (action === "close_failed") payload.confirm_name = elements["incident-confirm-name"].value;
  showError(elements["incident-error"], "");
  setBusy(elements["submit-incident"], true, "Traitement…");
  try {
    const kind = encodeURIComponent(elements["incident-kind"].value);
    const id = encodeURIComponent(elements["incident-id"].value);
    await api(`/api/admin/incidents/${kind}/${id}/actions`, { method: "POST", body: JSON.stringify(payload) });
    closeIncidentDialog();
    showToast(action === "resume_tracking" ? "Suivi remis dans la file." : "Incident clôturé en échec.");
    await Promise.all([loadOperations(), loadAudit(), loadUsers()]);
  } catch (error) {
    if (error.status === 401) return showLogin();
    showError(elements["incident-error"], error.message);
  } finally {
    setBusy(elements["submit-incident"], false, "");
  }
}

function renderUser(user) {
  const card = document.createElement("article");
  card.className = `user-card${user.is_active ? "" : " inactive"}`;
  const identity = document.createElement("div");
  identity.className = "user-identity";
  appendText(identity, "div", user.username.slice(0, 1).toUpperCase(), "avatar");
  const copy = document.createElement("div");
  appendText(copy, "strong", user.username);
  appendText(copy, "span", { oidc: "Keycloak / OIDC", ldap: "LDAP / LDAPS", local: "Compte local" }[user.authentication] || user.authentication);
  identity.append(copy);
  card.append(identity);
  appendText(card, "span", { admin: "Administrateur", operator: "Opérateur", user: "Utilisateur" }[user.role], "role-label");
  appendText(
    card,
    "span",
    `${user.usage.vms}/${user.quota.vms} VM · ${user.usage.cpu}/${user.quota.cpu} vCPU · ${formatRam(user.usage.ram_mb)}/${formatRam(user.quota.ram_mb)} · ${user.usage.disk_gb}/${user.quota.disk_gb} Gio`,
    "user-quota"
  );
  appendText(card, "span", user.is_active ? "Actif" : "Suspendu", `user-state ${user.is_active ? "active" : "inactive"}`);
  const edit = appendText(card, "button", "Modifier", "edit-user");
  edit.type = "button";
  edit.addEventListener("click", () => openEditUserDialog(user));
  return card;
}

function renderUsers() {
  elements["user-list"].replaceChildren(...state.users.map(renderUser));
  elements["user-count"].textContent = `${state.users.length} compte${state.users.length > 1 ? "s" : ""}`;
  elements["stat-users-active"].textContent = String(state.users.filter((user) => user.is_active).length);
  elements["stat-users-oidc"].textContent = String(state.users.filter((user) => user.authentication !== "local").length);
  elements["stat-users-admin"].textContent = String(state.users.filter((user) => user.is_active && user.role === "admin").length);
}

async function loadUsers() {
  elements["refresh-users"].disabled = true;
  try {
    state.users = (await api("/api/admin/users")).users;
    renderUsers();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["user-count"].textContent = error.message;
  } finally {
    elements["refresh-users"].disabled = false;
  }
}

const auditActionLabels = {
  "authentication.login": "Connexion",
  "authentication.logout": "Déconnexion",
  "authentication.throttled": "Connexion ralentie",
  "authentication.oidc_login": "Connexion Keycloak",
  "authorization.denied": "Autorisation refusée",
  "user.create": "Utilisateur créé",
  "user.update": "Utilisateur modifié",
  "image_profile.create": "Image publiée",
  "image_profile.update": "Image modifiée",
  "vm.enqueue": "VM demandée",
  "vm.create": "Création de VM",
  "vm.provision": "Provisionnement",
  "vm.start": "Démarrage de VM",
  "vm.stop": "Arrêt de VM",
  "vm.reboot": "Redémarrage de VM",
  "vm.delete": "Suppression de VM",
  "vm.guest_password_reset.request": "Reset SSH demandé",
  "vm.guest_password_reset.apply": "Mot de passe SSH modifié",
  "vm.maintenance.scan": "Analyse des mises à jour",
  "vm.maintenance.update": "Mise à jour de la VM",
  "vm.network_policy.update": "Politique réseau modifiée",
  "incident.resume_tracking": "Suivi repris",
  "incident.close_failed": "Incident clôturé"
};

function filteredAuditEvents() {
  const outcome = elements["audit-outcome"].value;
  const search = elements["audit-search"].value.trim().toLowerCase();
  return state.auditEvents.filter((event) => {
    const label = auditActionLabels[event.action] || event.action;
    const matchesOutcome = !outcome || event.outcome === outcome;
    const haystack = `${label} ${event.action} ${event.target_type} ${event.target_id || ""}`.toLowerCase();
    return matchesOutcome && (!search || haystack.includes(search));
  });
}

function renderAudit() {
  const events = filteredAuditEvents();
  const outcomeLabels = { success: "Succès", failure: "Échec", denied: "Refus" };
  elements["audit-list"].replaceChildren(...events.map((event) => {
    const row = document.createElement("article");
    row.className = "audit-row";
    appendText(row, "time", new Date(event.created_at).toLocaleString("fr-FR"), "audit-time");
    appendText(row, "span", auditActionLabels[event.action] || event.action, "audit-action");
    appendText(row, "span", `${event.target_type}${event.target_id ? ` · ${event.target_id}` : ""}`, "audit-target");
    appendText(row, "span", outcomeLabels[event.outcome] || event.outcome, `audit-outcome outcome-${event.outcome}`);
    return row;
  }));
  elements["audit-empty"].hidden = events.length !== 0;
  elements["audit-count"].textContent = `${events.length} événement${events.length > 1 ? "s" : ""} affiché${events.length > 1 ? "s" : ""}`;
}

async function loadAudit() {
  elements["refresh-audit"].disabled = true;
  try {
    state.auditEvents = (await api("/api/admin/audit-events")).events;
    renderAudit();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["audit-count"].textContent = error.message;
  } finally {
    elements["refresh-audit"].disabled = false;
  }
}

function setUserDialogMode(user = null) {
  elements["user-form"].reset();
  showError(elements["user-error"], "");
  const editing = user !== null;
  elements["user-id"].value = editing ? String(user.id) : "";
  elements["user-dialog-title"].textContent = editing ? `Modifier ${user.username}` : "Nouvel utilisateur";
  elements["user-dialog-intro"].textContent = editing
    ? "Les changements de rôle, d’état et de quota sont journalisés."
    : "Créez un compte local avec le minimum de droits et de ressources nécessaires.";
  elements["managed-username"].disabled = editing;
  elements["managed-username"].value = editing ? user.username : "";
  elements["managed-role"].value = editing ? user.role : "user";
  elements["managed-active"].checked = editing ? user.is_active : true;
  elements["active-checkbox"].hidden = !editing;
  elements["managed-quota-vms"].value = editing ? user.quota.vms : 3;
  elements["managed-quota-cpu"].value = editing ? user.quota.cpu : 8;
  elements["managed-quota-ram"].value = editing ? user.quota.ram_mb : 16384;
  elements["managed-quota-disk"].value = editing ? user.quota.disk_gb : 200;
  elements["managed-password"].value = "";
  elements["managed-password"].required = !editing;
  elements["password-optional"].hidden = !editing;
  const externallyManaged = editing && user.authentication !== "local";
  const self = editing && user.id === state.user.id;
  elements["managed-role"].disabled = externallyManaged || self;
  elements["managed-password"].disabled = externallyManaged;
  elements["managed-active"].disabled = self;
  document.querySelector('label[for="managed-password"]').hidden = externallyManaged;
  elements["managed-password"].hidden = externallyManaged;
  elements["identity-help"].textContent = externallyManaged
    ? "Le rôle et le mot de passe sont synchronisés depuis Keycloak ; seuls l’état local et les quotas sont modifiables."
    : "Le mot de passe n’est jamais retourné par l’API ni écrit dans l’audit.";
  elements["save-user"].textContent = editing ? "Enregistrer" : "Créer le compte";
}

function openCreateUserDialog() {
  setUserDialogMode();
  elements["user-dialog"].showModal();
  elements["managed-username"].focus();
}

function openEditUserDialog(user) {
  setUserDialogMode(user);
  elements["user-dialog"].showModal();
  elements["managed-quota-vms"].focus();
}

function closeUserDialog() {
  elements["user-dialog"].close();
}

async function saveUser(event) {
  event.preventDefault();
  showError(elements["user-error"], "");
  setBusy(elements["save-user"], true, "Enregistrement…");
  const editing = Boolean(elements["user-id"].value);
  const quota = {
    vms: Number(elements["managed-quota-vms"].value),
    cpu: Number(elements["managed-quota-cpu"].value),
    ram_mb: Number(elements["managed-quota-ram"].value),
    disk_gb: Number(elements["managed-quota-disk"].value)
  };
  const payload = editing
    ? { role: elements["managed-role"].value, is_active: elements["managed-active"].checked, quota }
    : { username: elements["managed-username"].value, password: elements["managed-password"].value, role: elements["managed-role"].value, quota };
  if (editing && !elements["managed-password"].disabled && elements["managed-password"].value) {
    payload.password = elements["managed-password"].value;
  }
  try {
    const path = editing ? `/api/admin/users/${encodeURIComponent(elements["user-id"].value)}` : "/api/admin/users";
    await api(path, { method: editing ? "PATCH" : "POST", body: JSON.stringify(payload) });
    closeUserDialog();
    showToast(editing ? "Utilisateur mis à jour." : "Utilisateur créé.");
    await Promise.all([loadUsers(), loadAudit()]);
  } catch (error) {
    showError(elements["user-error"], error.message);
  } finally {
    setBusy(elements["save-user"], false, "");
  }
}

function sourceType() {
  return elements["profile-form"].querySelector('input[name="source_type"]:checked').value;
}

function updateSourceFields() {
  const cloud = sourceType() === "cloud_init";
  elements["cloud-fields"].hidden = !cloud;
  elements["iso-fields"].hidden = cloud;
  elements["template-node"].required = cloud;
  elements["template-vmid"].required = cloud;
  elements["profile-iso"].required = !cloud;
}

async function openProfileDialog() {
  elements["profile-form"].reset();
  delete elements["profile-slug"].dataset.edited;
  showError(elements["profile-error"], "");
  updateSourceFields();
  elements["profile-dialog"].showModal();
  try {
    await loadNodes();
  } catch (error) {
    showError(elements["profile-error"], error.message);
  }
  elements["profile-label"].focus();
}

function closeProfileDialog() {
  elements["profile-dialog"].close();
}

function slugify(value) {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 63);
}

async function publishProfile(event) {
  event.preventDefault();
  showError(elements["profile-error"], "");
  setBusy(elements["publish-profile"], true, "Vérification…");
  const form = new FormData(elements["profile-form"]);
  const type = sourceType();
  const payload = {
    slug: form.get("slug"), label: form.get("label"), description: form.get("description"),
    version: form.get("version"), source_type: type
  };
  if (type === "cloud_init") {
    payload.template_node = form.get("template_node");
    payload.template_vmid = Number(form.get("template_vmid"));
  } else {
    payload.iso = form.get("iso");
  }
  try {
    await api("/api/admin/image-profiles", { method: "POST", body: JSON.stringify(payload) });
    closeProfileDialog();
    showToast("Image vérifiée et publiée.");
    await loadProfiles();
  } catch (error) {
    showError(elements["profile-error"], error.message);
  } finally {
    setBusy(elements["publish-profile"], false, "");
  }
}

function configureAuthenticationChoices() {
  const localEnabled = document.body.dataset.localAuth === "true";
  const oidcEnabled = document.body.dataset.oidc === "true";
  elements["local-login-fields"].hidden = !localEnabled;
  elements["oidc-login"].hidden = !oidcEnabled;
  elements["login-separator"].hidden = !(localEnabled && oidcEnabled);
  if (!localEnabled) elements["login-form"].noValidate = true;
}

elements["login-form"].addEventListener("submit", login);
elements["first-password-form"].addEventListener("submit", saveFirstPassword);
elements["first-password-dialog"].addEventListener("cancel", (event) => event.preventDefault());
elements["logout-button"].addEventListener("click", logout);
elements["notifications-button"].addEventListener("click", openNotifications);
elements["close-notifications"].addEventListener("click", () => elements["notifications-dialog"].close());
elements["read-all-notifications"].addEventListener("click", markAllNotificationsRead);
document.querySelectorAll("[data-view]").forEach((control) => control.addEventListener("click", (event) => {
  event.preventDefault();
  switchView(control.dataset.view);
}));
elements["open-vm-dialog"].addEventListener("click", openVmDialog);
elements["close-vm-dialog"].addEventListener("click", closeVmDialog);
elements["cancel-vm"].addEventListener("click", closeVmDialog);
elements["vm-form"].addEventListener("submit", submitVm);
elements["close-vm-action"].addEventListener("click", closeVmActionDialog);
elements["cancel-vm-action"].addEventListener("click", closeVmActionDialog);
elements["vm-action-form"].addEventListener("submit", submitVmAction);
elements["close-vm-details"].addEventListener("click", closeVmDetails);
elements["copy-vm-ssh"].addEventListener("click", async () => {
  if (!state.detailsSshCommand) return;
  try {
    await navigator.clipboard.writeText(state.detailsSshCommand);
    showToast(`Commande copiée : ${state.detailsSshCommand}`);
  } catch (_error) {
    showToast(`Commande SSH : ${state.detailsSshCommand}`);
  }
});
elements["open-guest-password-dialog"].addEventListener("click", () => openGuestPasswordDialog());
elements["close-guest-password-dialog"].addEventListener("click", closeGuestPasswordDialog);
elements["cancel-guest-password"].addEventListener("click", closeGuestPasswordDialog);
elements["guest-password-form"].addEventListener("submit", submitGuestPassword);
elements["request-sandbox-release"].addEventListener("click", requestSandboxRelease);
elements["close-network-log"].addEventListener("click", () => elements["network-log-dialog"].close());
elements["close-network-log-action"].addEventListener("click", () => elements["network-log-dialog"].close());
elements["vm-profile"].addEventListener("change", updateGuestAccessField);
elements["vm-network-profile"].addEventListener("change", updateNetworkFields);
elements["vm-network-mode"].addEventListener("change", updateNetworkFields);
elements["refresh-jobs"].addEventListener("click", loadJobs);
elements["show-archived"].addEventListener("click", toggleArchivedJobs);
[elements["vm-cpu"], elements["vm-ram"], elements["vm-disk"]].forEach((input) => input.addEventListener("input", updateQuotaPreview));
elements["open-user-dialog"].addEventListener("click", openCreateUserDialog);
elements["close-user-dialog"].addEventListener("click", closeUserDialog);
elements["cancel-user"].addEventListener("click", closeUserDialog);
elements["user-form"].addEventListener("submit", saveUser);
elements["settings-form"].addEventListener("submit", saveSettings);
elements["proxmox-integration-form"].addEventListener("submit", saveProxmoxIntegration);
elements["netbox-integration-form"].addEventListener("submit", saveNetBoxIntegration);
elements["siem-integration-form"].addEventListener("submit", saveSiemIntegration);
elements["generate-siem-token"].addEventListener("click", generateSiemToken);
elements["network-profile-form"].addEventListener("submit", saveNetworkProfile);
elements["software-module-form"].addEventListener("submit", saveSoftwareModule);
elements["network-profile-automatic"].addEventListener("change", updateNetworkPoolFields);
elements["refresh-users"].addEventListener("click", loadUsers);
elements["refresh-operations"].addEventListener("click", loadOperations);
elements["refresh-mco"].addEventListener("click", loadMcoReport);
elements["refresh-fleet"].addEventListener("click", loadFleet);
elements["fleet-filters"].addEventListener("submit", (event) => {
  event.preventDefault();
  loadFleet();
});
elements["close-incident-dialog"].addEventListener("click", closeIncidentDialog);
elements["cancel-incident"].addEventListener("click", closeIncidentDialog);
elements["incident-form"].addEventListener("submit", submitIncident);
elements["refresh-audit"].addEventListener("click", loadAudit);
elements["audit-outcome"].addEventListener("change", renderAudit);
elements["audit-search"].addEventListener("input", renderAudit);
elements["refresh-profiles"].addEventListener("click", loadProfiles);
elements["open-profile-dialog"].addEventListener("click", openProfileDialog);
elements["close-profile-dialog"].addEventListener("click", closeProfileDialog);
elements["cancel-profile"].addEventListener("click", closeProfileDialog);
elements["profile-form"].addEventListener("submit", publishProfile);
elements["image-lifecycle-form"].addEventListener("submit", saveImageLifecycle);
elements["close-image-lifecycle"].addEventListener("click", closeImageLifecycle);
elements["cancel-image-lifecycle"].addEventListener("click", closeImageLifecycle);
elements["profile-form"].querySelectorAll('input[name="source_type"]').forEach((radio) => radio.addEventListener("change", updateSourceFields));
elements["iso-node"].addEventListener("change", (event) => loadIsos(event.target.value));
elements["profile-label"].addEventListener("input", () => {
  if (!elements["profile-slug"].dataset.edited) elements["profile-slug"].value = slugify(elements["profile-label"].value);
});
elements["profile-slug"].addEventListener("input", () => { elements["profile-slug"].dataset.edited = "true"; });
elements["profile-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["profile-dialog"]) closeProfileDialog();
});
elements["image-lifecycle-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["image-lifecycle-dialog"]) closeImageLifecycle();
});
elements["vm-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["vm-dialog"]) closeVmDialog();
});
elements["vm-action-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["vm-action-dialog"]) closeVmActionDialog();
});
elements["vm-details-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["vm-details-dialog"]) closeVmDetails();
});
elements["guest-password-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["guest-password-dialog"]) closeGuestPasswordDialog();
});
elements["network-log-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["network-log-dialog"]) elements["network-log-dialog"].close();
});
elements["user-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["user-dialog"]) closeUserDialog();
});
elements["incident-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["incident-dialog"]) closeIncidentDialog();
});
elements["notifications-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["notifications-dialog"]) elements["notifications-dialog"].close();
});

configureAuthenticationChoices();
updateNetworkPoolFields();
restoreSession();
