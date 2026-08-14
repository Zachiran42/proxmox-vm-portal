"use strict";

const state = { csrfToken: "", user: null, usage: {}, settings: {}, profiles: [], nodes: [], jobs: [], users: [], auditEvents: [], operations: null, pollTimer: null };
const elements = Object.fromEntries(
  [
    "login-screen", "login-form", "local-login-fields", "login-error", "login-button",
    "login-separator", "oidc-login", "app-shell", "user-avatar", "user-name", "user-role",
    "first-password-dialog", "first-password-form", "first-password", "first-password-confirmation",
    "first-password-error", "save-first-password",
    "logout-button", "open-profile-dialog", "refresh-profiles", "profile-grid", "empty-state",
    "profile-count", "stat-active", "stat-cloud", "stat-disabled", "profile-dialog",
    "profile-form", "close-profile-dialog", "cancel-profile", "profile-label", "profile-slug",
    "profile-error", "publish-profile", "cloud-fields", "iso-fields", "template-node",
    "template-vmid", "iso-node", "profile-iso", "toast", "machines-view", "images-view",
    "open-vm-dialog", "vm-dialog", "vm-form", "close-vm-dialog", "cancel-vm", "submit-vm",
    "vm-profile", "vm-node", "vm-name", "vm-cpu", "vm-ram", "vm-disk", "vm-error",
    "guest-access-step", "vm-guest-username", "vm-guest-password",
    "vm-guest-password-confirmation", "guest-password-help", "quota-preview", "refresh-jobs", "job-list",
    "jobs-empty", "job-count", "quota-vms", "quota-cpu", "quota-ram", "quota-disk",
    "quota-vms-progress", "quota-cpu-progress", "quota-ram-progress", "quota-disk-progress",
    "admin-nav", "admin-mobile-nav", "admin-view", "open-user-dialog", "refresh-users",
    "user-list", "user-count", "stat-users-active", "stat-users-oidc", "stat-users-admin",
    "audit-list", "audit-empty", "audit-count", "audit-outcome", "audit-search", "refresh-audit",
    "user-dialog", "user-form", "user-id", "user-dialog-title", "user-dialog-intro",
    "close-user-dialog", "cancel-user", "save-user", "managed-username", "managed-role",
    "managed-password", "password-optional", "identity-help", "managed-quota-vms",
    "managed-quota-cpu", "managed-quota-ram", "managed-quota-disk", "active-checkbox",
    "managed-active", "user-error", "vm-action-dialog", "vm-action-form", "vm-action-id",
    "vm-action-kind", "vm-action-title", "vm-action-intro", "vm-delete-confirmation",
    "vm-confirm-name", "vm-confirm-expected", "vm-action-error", "close-vm-action",
    "cancel-vm-action", "submit-vm-action", "operations-checked", "refresh-operations",
    "service-grid", "incident-count",
    "queue-count", "incident-list", "incident-empty", "incident-dialog", "incident-form",
    "incident-kind", "incident-id", "incident-action", "incident-dialog-title",
    "incident-dialog-intro", "incident-close-confirmation", "incident-confirm-name",
    "incident-confirm-expected", "incident-error", "close-incident-dialog",
    "cancel-incident", "submit-incident", "settings-form", "guest-password-min-length",
    "save-settings", "settings-error"
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
    csrf_validation_failed: "La session a expiré. Reconnectez-vous.",
    pve_unavailable: "Proxmox est momentanément indisponible.",
    password_pusher_unavailable: "Password Pusher est momentanément indisponible.",
    quota_exceeded: "Cette demande dépasse votre quota disponible.",
    name_conflict: "Une machine active utilise déjà ce nom.",
    self_admin_protection: "Vous ne pouvez pas désactiver ou rétrograder votre propre compte administrateur.",
    last_admin_protection: "Le dernier administrateur actif doit être conservé.",
    external_identity_managed: "Le rôle et le mot de passe de cette identité sont gérés dans Keycloak.",
    password_change_required: "Vous devez modifier le mot de passe temporaire.",
    password_reuse: "Choisissez un mot de passe différent du mot de passe temporaire.",
    vm_not_ready: "Cette machine n’est pas encore prête.",
    confirmation_mismatch: "Le nom saisi ne correspond pas à la machine.",
    lifecycle_invalid_state: "Cette action n’est pas disponible dans l’état actuel.",
    operation_in_progress: "Une opération est déjà en cours sur cette machine.",
    incident_not_open: "Cet incident a déjà été traité.",
    incident_not_resumable: "Aucun identifiant Proxmox exploitable ne permet de reprendre ce suivi.",
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
  elements["admin-nav"].hidden = session.user.role !== "admin";
  elements["admin-mobile-nav"].hidden = session.user.role !== "admin";
  renderQuotas();
  const requestedView = window.location.hash.slice(1);
  switchView(["images", "admin"].includes(requestedView) ? requestedView : "machines");
  const loaders = [loadProfiles(), loadNodes(), loadJobs()];
  if (session.user.role === "admin") loaders.push(loadUsers(), loadAudit(), loadOperations());
  if (session.user.role === "admin") {
    elements["guest-password-min-length"].value = state.settings.guest_password_min_length || 8;
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
  if (view === "admin" && state.user?.role !== "admin") view = "machines";
  elements["machines-view"].hidden = view !== "machines";
  elements["images-view"].hidden = view !== "images";
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
  card.className = `profile-card${profile.enabled ? "" : " disabled"}`;

  const top = document.createElement("div");
  top.className = "profile-top";
  appendText(top, "div", profile.source_type === "cloud_init" ? "CI" : "ISO", "profile-icon");
  const title = document.createElement("div");
  title.className = "profile-title";
  appendText(title, "h3", profile.label);
  appendText(title, "p", profile.description || "Aucune description");
  top.append(title);
  appendText(top, "span", profile.enabled ? "Active" : "Suspendue", `badge ${profile.enabled ? "badge-active" : "badge-disabled"}`);
  card.append(top);

  const meta = document.createElement("div");
  meta.className = "profile-meta";
  appendText(meta, "span", `# ${profile.slug}`);
  appendText(meta, "span", profile.source_type === "cloud_init" ? `${profile.template_node} · VMID ${profile.template_vmid}` : profile.iso);
  card.append(meta);

  const actions = document.createElement("div");
  actions.className = "profile-actions";
  appendText(actions, "span", profile.automatic_guest_access ? "✓ Accès sudo automatisé" : "Installation ISO", `access-label${profile.automatic_guest_access ? "" : " manual"}`);
  if (state.user.role === "admin") {
    const toggle = appendText(actions, "button", profile.enabled ? "Suspendre" : "Réactiver", "switch-button");
    toggle.type = "button";
    toggle.addEventListener("click", () => toggleProfile(profile, toggle));
  }
  card.append(actions);
  return card;
}

function renderProfiles() {
  const active = state.profiles.filter((profile) => profile.enabled).length;
  const cloud = state.profiles.filter((profile) => profile.enabled && profile.automatic_guest_access).length;
  elements["stat-active"].textContent = String(active);
  elements["stat-cloud"].textContent = String(cloud);
  elements["stat-disabled"].textContent = String(state.profiles.length - active);
  elements["profile-count"].textContent = `${state.profiles.length} profil${state.profiles.length > 1 ? "s" : ""} enregistré${state.profiles.length > 1 ? "s" : ""}`;
  elements["profile-grid"].replaceChildren(...state.profiles.map(renderProfile));
  elements["empty-state"].hidden = state.profiles.length !== 0;
  const activeProfiles = state.profiles.filter((profile) => profile.enabled);
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

const terminalStatuses = new Set(["succeeded", "failed", "attention"]);
const statusLabels = {
  queued: "En file", validating: "Validation", submitting: "Création",
  submitted: "En cours", polling: "En cours", succeeded: "Prête",
  failed: "Échec", attention: "À vérifier"
};
const vmStatusLabels = {
  queued: "Réservée", provisioning: "Provisionnement", accepted: "Prête",
  running: "Démarrée", stopped: "Arrêtée", failed: "Échec", deleted: "Supprimée"
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
  password_pusher_unavailable: "Password Pusher indisponible"
};

function jobStatusClass(status) {
  if (status === "succeeded") return "status-success";
  if (status === "failed") return "status-error";
  if (status === "attention") return "status-attention";
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
  if (job.vm.guest_username) appendText(resources, "span", `SSH : ${job.vm.guest_username}`);
  if (job.network?.status === "ready") {
    appendText(resources, "span", `IPv4 : ${job.network.ipv4}`);
  } else if (job.vm.status === "running" && job.vm.guest_username) {
    appendText(resources, "span", "IPv4 : attribution en cours");
  }
  card.append(resources);

  const result = document.createElement("div");
  result.className = "job-result";
  if (job.error_code) appendText(result, "span", jobErrorLabels[job.error_code] || "Une vérification est nécessaire", "job-error");
  if (job.guest_access) {
    const access = appendText(result, "a", "Voir l’accès", "credential-button");
    access.href = job.guest_access.password_url;
    access.target = "_blank";
    access.rel = "noopener noreferrer";
    access.title = `Compte ${job.guest_access.username} · ${job.guest_access.expire_after_views} vue(s) maximum`;
  }
  if (job.network?.status === "ready" && job.vm.guest_username) {
    const command = `ssh ${job.vm.guest_username}@${job.network.ipv4}`;
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
  if (controls.length) {
    const actions = document.createElement("div");
    actions.className = "vm-actions";
    controls.forEach(({ action, label, danger }) => {
      const button = appendText(actions, "button", label, `vm-action-button${danger ? " danger" : ""}`);
      button.type = "button";
      button.addEventListener("click", () => openVmActionDialog(job, action));
    });
    result.append(actions);
  }
  card.append(result);
  return card;
}

function lifecycleControls(job) {
  if (job.status !== "succeeded" || activeOperationStatuses.has(job.operation?.status)) return [];
  if (["accepted", "stopped"].includes(job.vm.status)) {
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
  elements["job-count"].textContent = `${state.jobs.length} demande${state.jobs.length > 1 ? "s" : ""} récente${state.jobs.length > 1 ? "s" : ""}`;
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
    const [history, session] = await Promise.all([api("/api/jobs"), api("/api/me")]);
    state.jobs = history.jobs;
    await Promise.all(state.jobs.map(async (job) => {
      if (job.vm.status !== "running" || !job.vm.vmid || !job.vm.guest_username) return;
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
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["job-count"].textContent = error.message;
  } finally {
    elements["refresh-jobs"].disabled = false;
  }
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
  showError(elements["vm-error"], "");
  updateGuestAccessField();
  updateQuotaPreview();
  elements["vm-dialog"].showModal();
  try {
    if (!state.nodes.length) await loadNodes();
    if (!state.profiles.length) await loadProfiles();
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
    cpu: Number(form.get("cpu")), ram_mb: Number(form.get("ram_mb")), disk_gb: Number(form.get("disk_gb"))
  };
  if (!elements["guest-access-step"].hidden) {
    if (elements["vm-guest-password"].value !== elements["vm-guest-password-confirmation"].value) {
      showError(elements["vm-error"], "Les mots de passe SSH diffèrent.");
      setBusy(elements["submit-vm"], false, "");
      return;
    }
    payload.guest_username = form.get("guest_username");
    payload.guest_password = form.get("guest_password");
  }
  try {
    await api("/api/vms", { method: "POST", body: JSON.stringify(payload) });
    closeVmDialog();
    showToast("La machine a été réservée et placée dans la file.");
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
      body: JSON.stringify({ guest_password_min_length: minimum })
    });
    state.settings = response.settings;
    updateGuestAccessField();
    showToast("Politique des mots de passe SSH mise à jour.");
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
  appendText(copy, "span", user.authentication === "oidc" ? "Keycloak / OIDC" : "Compte local");
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
  elements["stat-users-oidc"].textContent = String(state.users.filter((user) => user.authentication === "oidc").length);
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
  const externallyManaged = editing && user.authentication === "oidc";
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
    slug: form.get("slug"), label: form.get("label"), description: form.get("description"), source_type: type
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
elements["vm-profile"].addEventListener("change", updateGuestAccessField);
elements["refresh-jobs"].addEventListener("click", loadJobs);
[elements["vm-cpu"], elements["vm-ram"], elements["vm-disk"]].forEach((input) => input.addEventListener("input", updateQuotaPreview));
elements["open-user-dialog"].addEventListener("click", openCreateUserDialog);
elements["close-user-dialog"].addEventListener("click", closeUserDialog);
elements["cancel-user"].addEventListener("click", closeUserDialog);
elements["user-form"].addEventListener("submit", saveUser);
elements["settings-form"].addEventListener("submit", saveSettings);
elements["refresh-users"].addEventListener("click", loadUsers);
elements["refresh-operations"].addEventListener("click", loadOperations);
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
elements["profile-form"].querySelectorAll('input[name="source_type"]').forEach((radio) => radio.addEventListener("change", updateSourceFields));
elements["iso-node"].addEventListener("change", (event) => loadIsos(event.target.value));
elements["profile-label"].addEventListener("input", () => {
  if (!elements["profile-slug"].dataset.edited) elements["profile-slug"].value = slugify(elements["profile-label"].value);
});
elements["profile-slug"].addEventListener("input", () => { elements["profile-slug"].dataset.edited = "true"; });
elements["profile-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["profile-dialog"]) closeProfileDialog();
});
elements["vm-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["vm-dialog"]) closeVmDialog();
});
elements["vm-action-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["vm-action-dialog"]) closeVmActionDialog();
});
elements["user-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["user-dialog"]) closeUserDialog();
});
elements["incident-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["incident-dialog"]) closeIncidentDialog();
});

configureAuthenticationChoices();
restoreSession();
