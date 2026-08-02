"use strict";

const state = { csrfToken: "", user: null, usage: {}, profiles: [], nodes: [], jobs: [], pollTimer: null };
const elements = Object.fromEntries(
  [
    "login-screen", "login-form", "local-login-fields", "login-error", "login-button",
    "login-separator", "oidc-login", "app-shell", "user-avatar", "user-name", "user-role",
    "logout-button", "open-profile-dialog", "refresh-profiles", "profile-grid", "empty-state",
    "profile-count", "stat-active", "stat-cloud", "stat-disabled", "profile-dialog",
    "profile-form", "close-profile-dialog", "cancel-profile", "profile-label", "profile-slug",
    "profile-error", "publish-profile", "cloud-fields", "iso-fields", "template-node",
    "template-vmid", "iso-node", "profile-iso", "toast", "machines-view", "images-view",
    "open-vm-dialog", "vm-dialog", "vm-form", "close-vm-dialog", "cancel-vm", "submit-vm",
    "vm-profile", "vm-node", "vm-name", "vm-cpu", "vm-ram", "vm-disk", "vm-error",
    "guest-access-step", "vm-guest-username", "quota-preview", "refresh-jobs", "job-list",
    "jobs-empty", "job-count", "quota-vms", "quota-cpu", "quota-ram", "quota-disk",
    "quota-vms-progress", "quota-cpu-progress", "quota-ram-progress", "quota-disk-progress"
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
  elements["app-shell"].hidden = true;
  elements["login-screen"].hidden = false;
  document.getElementById("username")?.focus();
}

function showApplication(session) {
  state.user = session.user;
  state.usage = session.usage || {};
  state.csrfToken = session.csrf_token;
  elements["login-screen"].hidden = true;
  elements["app-shell"].hidden = false;
  elements["user-name"].textContent = session.user.username;
  elements["user-role"].textContent = { admin: "administrateur", operator: "opérateur", user: "utilisateur" }[session.user.role] || session.user.role;
  elements["user-avatar"].textContent = session.user.username.slice(0, 1).toUpperCase();
  elements["open-profile-dialog"].hidden = session.user.role !== "admin";
  renderQuotas();
  switchView(window.location.hash === "#images" ? "images" : "machines");
  Promise.all([loadProfiles(), loadNodes(), loadJobs()]).catch(() => {});
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

function switchView(view) {
  const machines = view === "machines";
  elements["machines-view"].hidden = !machines;
  elements["images-view"].hidden = machines;
  document.querySelectorAll("[data-view]").forEach((control) => {
    const active = control.dataset.view === view;
    control.classList.toggle("active", active);
    if (control.matches("a")) {
      if (active) control.setAttribute("aria-current", "page");
      else control.removeAttribute("aria-current");
    }
  });
  window.history.replaceState(null, "", machines ? "#machines" : "#images");
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
const jobErrorLabels = {
  iso_unavailable: "ISO indisponible sur ce nœud",
  template_unavailable: "Template indisponible",
  pve_task_failed: "Proxmox a refusé la création",
  pve_inventory_invalid: "Inventaire Proxmox invalide",
  pve_create_unknown: "État Proxmox à vérifier",
  pve_start_unknown: "Démarrage à vérifier",
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
  appendText(identity, "span", placement);
  main.append(identity);
  card.append(main);

  const resources = document.createElement("div");
  resources.className = "job-resources";
  appendText(resources, "span", `${job.vm.cpu} vCPU · ${formatRam(job.vm.ram_mb)} · ${job.vm.disk_gb} Gio`);
  appendText(resources, "span", `Image ${job.vm.profile || "retirée"} · ${new Date(job.created_at).toLocaleString("fr-FR")}`);
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
  appendText(result, "span", statusLabels[job.status] || job.status, `job-status ${jobStatusClass(job.status)}`);
  card.append(result);
  return card;
}

function renderJobs() {
  elements["job-list"].replaceChildren(...state.jobs.map(renderJob));
  elements["jobs-empty"].hidden = state.jobs.length !== 0;
  elements["job-count"].textContent = `${state.jobs.length} demande${state.jobs.length > 1 ? "s" : ""} récente${state.jobs.length > 1 ? "s" : ""}`;
}

function scheduleJobPoll() {
  window.clearTimeout(state.pollTimer);
  if (state.jobs.some((job) => !terminalStatuses.has(job.status))) {
    state.pollTimer = window.setTimeout(loadJobs, 5000);
  }
}

async function loadJobs() {
  elements["refresh-jobs"].disabled = true;
  try {
    state.jobs = (await api("/api/jobs")).jobs;
    renderJobs();
    scheduleJobPoll();
  } catch (error) {
    if (error.status === 401) return showLogin();
    elements["job-count"].textContent = error.message;
  } finally {
    elements["refresh-jobs"].disabled = false;
  }
}

function updateGuestAccessField() {
  const option = elements["vm-profile"].selectedOptions[0];
  const automatic = option?.dataset.cloudInit === "true";
  elements["guest-access-step"].hidden = !automatic;
  elements["vm-guest-username"].required = automatic;
  if (!automatic) elements["vm-guest-username"].value = "";
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
  if (!elements["guest-access-step"].hidden) payload.guest_username = form.get("guest_username");
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
elements["logout-button"].addEventListener("click", logout);
document.querySelectorAll("[data-view]").forEach((control) => control.addEventListener("click", (event) => {
  event.preventDefault();
  switchView(control.dataset.view);
}));
elements["open-vm-dialog"].addEventListener("click", openVmDialog);
elements["close-vm-dialog"].addEventListener("click", closeVmDialog);
elements["cancel-vm"].addEventListener("click", closeVmDialog);
elements["vm-form"].addEventListener("submit", submitVm);
elements["vm-profile"].addEventListener("change", updateGuestAccessField);
elements["refresh-jobs"].addEventListener("click", loadJobs);
[elements["vm-cpu"], elements["vm-ram"], elements["vm-disk"]].forEach((input) => input.addEventListener("input", updateQuotaPreview));
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

configureAuthenticationChoices();
restoreSession();
