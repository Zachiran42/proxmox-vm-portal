"use strict";

const state = { csrfToken: "", user: null, profiles: [], nodes: [] };
const elements = Object.fromEntries(
  [
    "login-screen", "login-form", "local-login-fields", "login-error", "login-button",
    "login-separator", "oidc-login", "app-shell", "user-avatar", "user-name", "user-role",
    "logout-button", "open-profile-dialog", "refresh-profiles", "profile-grid", "empty-state",
    "profile-count", "stat-active", "stat-cloud", "stat-disabled", "profile-dialog",
    "profile-form", "close-profile-dialog", "cancel-profile", "profile-label", "profile-slug",
    "profile-error", "publish-profile", "cloud-fields", "iso-fields", "template-node",
    "template-vmid", "iso-node", "profile-iso", "toast"
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
  state.csrfToken = "";
  state.user = null;
  elements["app-shell"].hidden = true;
  elements["login-screen"].hidden = false;
  document.getElementById("username")?.focus();
}

function showApplication(session) {
  state.user = session.user;
  state.csrfToken = session.csrf_token;
  elements["login-screen"].hidden = true;
  elements["app-shell"].hidden = false;
  elements["user-name"].textContent = session.user.username;
  elements["user-role"].textContent = { admin: "administrateur", operator: "opérateur", user: "utilisateur" }[session.user.role] || session.user.role;
  elements["user-avatar"].textContent = session.user.username.slice(0, 1).toUpperCase();
  elements["open-profile-dialog"].hidden = session.user.role !== "admin";
  loadProfiles();
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

configureAuthenticationChoices();
restoreSession();
