"use strict";

/*
 * VaultX frontend connected to the C++ Crow API.
 * No demo records are stored in this file.
 */

let records = [];
let currentPage = "all";
let currentCategory = null;
let editingId = null;
let isUnlocked = false;
let isLoading = false;

const API_BASE = "";
const $ = (id) => document.getElementById(id);

const icons = {
    "Login": "🔑",
    "Secure Note": "▤",
    "Card": "▣",
    "Identity": "♙",
    "API Key": "⌘",
    "Wi-Fi": "◉"
};

// Fields for each record type. Must match the schema in src/Entry.cpp.
const TYPE_FIELDS = {
    "Login": [
        { k: "username", l: "Username / Email", req: true, ph: "you@example.com" },
        { k: "password", l: "Password", req: true, secret: true, gen: true },
        { k: "url", l: "Website URL", type: "url", ph: "https://example.com" }
    ],
    "Secure Note": [],
    "Card": [
        { k: "cardholder", l: "Cardholder name", req: true, ph: "Name on card" },
        { k: "number", l: "Card number", req: true, secret: true, ph: "1234 5678 9012 3456" },
        { k: "expiry", l: "Expiry date", req: true, ph: "MM/YY" },
        { k: "cvv", l: "CVV", secret: true },
        { k: "pin", l: "PIN", secret: true }
    ],
    "Identity": [
        { k: "fullName", l: "Full name", req: true },
        { k: "email", l: "Email", type: "email" },
        { k: "phone", l: "Phone", type: "tel" },
        { k: "address", l: "Address" },
        { k: "idNumber", l: "ID number", secret: true }
    ],
    "API Key": [
        { k: "keyName", l: "Key name / service", req: true, ph: "e.g. Stripe live key" },
        { k: "apiKey", l: "API key", req: true, secret: true, gen: true },
        { k: "endpoint", l: "Endpoint URL", type: "url", ph: "https://api.example.com" }
    ],
    "Wi-Fi": [
        { k: "ssid", l: "Network name (SSID)", req: true },
        { k: "password", l: "Password", req: true, secret: true, gen: true },
        { k: "security", l: "Security type", opts: ["WPA3", "WPA2", "WPA", "WEP", "None"] }
    ]
};

const SUBTITLE_KEY = {
    "Login": "username",
    "Card": "cardholder",
    "Identity": "fullName",
    "API Key": "keyName",
    "Wi-Fi": "ssid"
};

function subtitleOf(record) {
    return record.fields[SUBTITLE_KEY[record.type]] || "";
}

const pageInfo = {
    all: ["YOUR PERSONAL SPACE", "All items", "Everything important, protected in one place."],
    favorites: ["QUICK ACCESS", "Favorites", "Your most important records."],
    recent: ["YOUR ACTIVITY", "Recently added", "Records you've added recently."],
    trash: ["RECOVERABLE ITEMS", "Trash", "Deleted records in your vault."],
    generator: ["PASSWORD TOOLS", "Password generator", "Create strong, random passwords."],
    security: ["VAULT HEALTH", "Security center", "Review the strength of your passwords."],
    settings: ["PREFERENCES", "Settings", "Manage your VaultX experience."]
};

function showToast(message) {
    const toast = $("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2600);
}

function openModal(id) {
    $(id)?.classList.remove("hidden");
}

function closeModal(id) {
    if (id === "detailsModal") detailsRecord = null;  // drop decrypted values
    $(id)?.classList.add("hidden");
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

const NON_FIELD_KEYS = new Set([
    "id", "type", "title", "service", "folder", "category", "notes",
    "favorite", "deleted", "created", "createdAt", "website",
    "hint", "strength", "reused", "hasNotes"
]);

function normalizeRecord(raw) {
    const fields = {};

    for (const [key, value] of Object.entries(raw)) {
        if (!NON_FIELD_KEYS.has(key) && typeof value === "string" && value) {
            fields[key] = value;
        }
    }

    return {
        id: Number(raw.id),
        title: String(raw.title ?? raw.service ?? ""),
        type: String(raw.type ?? "Login"),
        fields,
        username: String(raw.username ?? ""),
        password: String(raw.password ?? ""),
        url: String(raw.url ?? raw.website ?? ""),
        folder: String(raw.folder ?? raw.category ?? "Personal"),
        notes: String(raw.notes ?? ""),
        hint: String(raw.hint ?? ""),
        strength: Number(raw.strength ?? 0),
        reused: Boolean(raw.reused),
        hasNotes: Boolean(raw.hasNotes),
        favorite: Boolean(raw.favorite),
        deleted: Boolean(raw.deleted),
        created: Number(raw.created ?? raw.createdAt ?? Date.now())
    };
}

async function apiRequest(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            ...(options.headers || {})
        },
        cache: "no-store",
        credentials: "same-origin"
    });

    const bodyText = await response.text();
    let body = {};

    if (bodyText) {
        try {
            body = JSON.parse(bodyText);
        } catch {
            body = { message: bodyText };
        }
    }

    if (!response.ok) {
        // The server locks itself after 15 idle minutes.
        if (response.status === 401 && isUnlocked && !path.endsWith("/unlock")) {
            isUnlocked = false;
            records = [];
            render();
            setConnectionStatus("Vault locked");
            unlockVault("Locked after inactivity. Enter your master password.");
        }

        throw new Error(
            body.error ||
            body.message ||
            `Request failed (${response.status}).`
        );
    }

    return body;
}

function setConnectionStatus(message, connected = false) {
    const status = document.querySelector(".sidebar-status");

    if (status) {
        status.innerHTML =
            `<span class="status-dot"></span>${escapeHTML(message)}`;

        status.classList.toggle("connected", connected);
    }
}

let vaultInitialized = true;

function masterScore(password) {
    let score = 0;
    if (password.length >= 10) score++;
    if (password.length >= 14) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;
    return score;
}

function updateUnlockStrength() {
    const bar = $("unlockStrength");
    const score = masterScore($("unlockPassword").value);
    bar.style.width = `${score * 25}%`;
    bar.style.background =
        ["#f07178", "#f07178", "#f5b84b", "#6cc17a", "#35c995"][score];
}

// Opens the unlock dialog (or the "create vault" dialog on first run).
async function unlockVault(notice = "") {
    try {
        const status = await apiRequest("/api/status");
        vaultInitialized = status.initialized;

        if (status.unlocked && !isUnlocked) {
            isUnlocked = true;
            await loadEntries();
            setConnectionStatus("Connected · Vault unlocked", true);
            return;
        }
    } catch (error) {
        setConnectionStatus("Backend unavailable");
        return showToast("Cannot reach the VaultX server.");
    }

    const creating = !vaultInitialized;

    $("unlockTitle").textContent = creating ? "Create your vault" : "Unlock VaultX";
    $("unlockHint").textContent = creating
        ? "Choose a strong master password (at least 10 characters). It cannot be recovered if you forget it."
        : "Enter your master password to decrypt your records.";
    $("unlockSubmit").textContent = creating ? "Create vault" : "Unlock";
    $("unlockPassword").autocomplete = creating ? "new-password" : "current-password";
    $("confirmBlock").classList.toggle("hidden", !creating);
    $("unlockForm").reset();
    $("unlockError").textContent = notice;
    $("unlockError").className = notice ? "form-error info" : "form-error";
    updateUnlockStrength();

    openModal("unlockModal");
    setTimeout(() => $("unlockPassword").focus(), 50);
}

async function submitUnlock(event) {
    event.preventDefault();

    const masterPassword = $("unlockPassword").value;
    const error = $("unlockError");
    const button = $("unlockSubmit");
    const label = button.textContent;

    error.textContent = "";
    error.className = "form-error";

    if (!vaultInitialized) {
        if (masterPassword.length < 10) {
            error.textContent = "Use at least 10 characters.";
            return;
        }

        if (masterPassword !== $("unlockConfirm").value) {
            error.textContent = "Passwords do not match.";
            return;
        }
    }

    button.disabled = true;
    button.textContent = "Please wait…";

    try {
        await apiRequest("/api/unlock", {
            method: "POST",
            body: JSON.stringify({ masterPassword })
        });

        isUnlocked = true;
        vaultInitialized = true;

        $("unlockForm").reset();
        closeModal("unlockModal");

        await loadEntries();

        setConnectionStatus("Connected · Vault unlocked", true);
        showToast("Vault unlocked.");

    } catch (err) {
        isUnlocked = false;
        error.textContent = err.message;
        setConnectionStatus("Vault locked");

    } finally {
        button.disabled = false;
        button.textContent = label;
    }
}

async function lockVault() {
    try {
        await apiRequest("/api/lock", {
            method: "POST",
            body: "{}"
        });
    } catch (error) {
        console.error("Vault lock request failed:", error);
    }

    records = [];
    isUnlocked = false;

    render();

    setConnectionStatus("Vault locked");
    unlockVault("Vault locked.");
}

async function loadEntries() {
    if (isLoading) return;

    isLoading = true;

    if (!records.length && $("pageContent")) {
        $("pageContent").innerHTML =
            '<div class="loading-state"><span class="spinner"></span>Decrypting your vault…</div>';
    }

    try {
        const data = await apiRequest("/api/entries");

        const list = Array.isArray(data)
            ? data
            : (data.entries || data.records || []);

        records = list.map(normalizeRecord);

        render();

        return true;

    } catch (error) {

        if (/401|403|locked|unlock/i.test(error.message)) {
            isUnlocked = false;
            records = [];
            render();
        }

        showToast(
            `Could not load vault records: ${error.message}`
        );

        setConnectionStatus("Backend unavailable");

        return false;

    } finally {
        isLoading = false;
    }
}

function activeRecords() {
    return records.filter(record => !record.deleted);
}

function visibleRecords() {
    let list = activeRecords();

    if (currentPage === "favorites") {
        list = list.filter(record => record.favorite);

    } else if (currentPage === "recent") {
        list = [...list]
            .sort((a, b) => b.created - a.created)
            .slice(0, 10);

    } else if (currentPage === "trash") {
        list = records.filter(record => record.deleted);

    } else if (currentCategory) {
        list = list.filter(
            record => record.type === currentCategory
        );
    }

    const query =
        $("searchInput")?.value.trim().toLowerCase() || "";

    if (query) {
        list = list.filter(record =>
            record.title.toLowerCase().includes(query) ||
            subtitleOf(record).toLowerCase().includes(query) ||
            record.folder.toLowerCase().includes(query) ||
            record.type.toLowerCase().includes(query) ||
            record.notes.toLowerCase().includes(query)
        );
    }

    return list;
}

function renderRecordCard(record) {
    return `
        <article class="record-card">
            <div class="record-top">

                <div class="record-icon">
                    ${icons[record.type] || "•"}
                </div>

                <div class="record-main">
                    <strong>${escapeHTML(record.title)}</strong>
                    <small>
                        ${escapeHTML([subtitleOf(record), record.hint].filter(Boolean).join(" · ") || record.type)}
                    </small>
                </div>

                <button
                    class="favorite-button ${record.favorite ? "selected" : ""}"
                    data-favorite="${record.id}"
                    title="Toggle favorite">

                    ${record.favorite ? "★" : "☆"}

                </button>
            </div>

            <div class="record-bottom">
                <small>
                    ${escapeHTML(record.folder)} ·
                    ${escapeHTML(record.type)}
                </small>

                <button
                    class="text-button"
                    data-view="${record.id}">
                    View details →
                </button>
            </div>
        </article>`;
}

// Strength (0-100) is calculated by the server, so passwords never reach the page.
function passwordScore(record) {
    return Math.round((record.strength || 0) / 20);
}

function analyzeVault() {
    const logins = activeRecords().filter(
        r => r.type === "Login"
    );

    if (!logins.length) {
        return {
            score: 0,
            label: "No login data",
            message: "Add a login record to analyse your vault."
        };
    }

    const average = logins.reduce(
        (sum, r) => sum + passwordScore(r),
        0
    ) / (logins.length * 5);

    const score = Math.round(average * 100);

    return {
        score,
        label: score >= 80
            ? "Good"
            : score >= 50
                ? "Needs improvement"
                : "Needs attention",

        message:
            "A basic password-strength estimate, not a formal security audit."
    };
}

function renderDashboard() {
    const total = activeRecords().length;

    const logins = activeRecords().filter(
        r => r.type === "Login"
    ).length;

    const favorites = activeRecords().filter(
        r => r.favorite
    ).length;

    const health = analyzeVault();

    return `
        <div class="stat-grid">

            <div class="stat-card">
                <span class="stat-label">Total records</span>
                <strong>${total}</strong>
                <small>Stored in your vault</small>
            </div>

            <div class="stat-card">
                <span class="stat-label">Login accounts</span>
                <strong>${logins}</strong>
                <small>Login records</small>
            </div>

            <div class="stat-card">
                <span class="stat-label">Favorites</span>
                <strong>${favorites}</strong>
                <small>Quick access records</small>
            </div>

        </div>

        <div class="dashboard-grid">

            <div class="panel">
                <div class="panel-title">
                    <div>
                        <h3>Vault overview</h3>
                        <p>Your records at a glance</p>
                    </div>
                </div>

                <div class="security-score">
                    <div class="score-circle">${health.score}</div>

                    <div>
                        <strong>${health.label}</strong>
                        <p>${health.message}</p>
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-title">
                    <div>
                        <h3>Quick actions</h3>
                        <p>Useful vault tools</p>
                    </div>
                </div>

                <button class="secondary-button" data-action="new">
                    ＋ Add a record
                </button>

                <button class="secondary-button" data-action="generator">
                    ⚄ Generate password
                </button>

                <button class="secondary-button" data-action="security">
                    ◈ Check security
                </button>
            </div>

        </div>

        <div class="record-toolbar">
            <h2>Recently added</h2>
            <button class="text-button" data-action="all">
                View all →
            </button>
        </div>

        <div class="record-grid">
            ${activeRecords()
                .slice()
                .sort((a, b) => b.created - a.created)
                .slice(0, 6)
                .map(renderRecordCard)
                .join("")}
        </div>

        ${total ? "" : `
            <div class="empty-state">
                <h3>Your vault is empty</h3>
                <p>Add your first record to get started.</p>
            </div>
        `}
    `;
}

function renderRecords() {
    const list = visibleRecords();

    return `
        <div class="record-toolbar">

            <h2>
                ${list.length}
                record${list.length === 1 ? "" : "s"}
            </h2>

            <select id="sortRecords">
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="name">Name A–Z</option>
            </select>

        </div>

        <div class="record-grid" id="recordGrid">
            ${list.map(renderRecordCard).join("")}
        </div>

        ${list.length ? "" : `
            <div class="empty-state">
                <h3>No records found</h3>
                <p>Try another search or add a new record.</p>
            </div>
        `}
    `;
}

function renderGeneratorPage() {
    return `
        <div class="panel">

            <div class="panel-title">
                <div>
                    <h3>Create a strong password</h3>
                    <p>Generate a random password for a new account.</p>
                </div>
            </div>

            <div class="generated-password" id="pageGeneratedPassword">
                Click Generate
            </div>

            <div class="generator-actions">
                <button class="secondary-button" id="pageCopyGenerated">
                    Copy
                </button>

                <button class="primary-button" id="pageRegenerate">
                    ↻ Generate password
                </button>
            </div>

            <label>
                Length:
                <strong id="pageLengthValue">20</strong>
            </label>

            <input
                type="range"
                id="pagePasswordLength"
                min="8"
                max="64"
                value="20">

            <div class="checkbox-grid">
                <label>
                    <input type="checkbox" id="pageUpper" checked>
                    Uppercase
                </label>

                <label>
                    <input type="checkbox" id="pageLower" checked>
                    Lowercase
                </label>

                <label>
                    <input type="checkbox" id="pageNumbers" checked>
                    Numbers
                </label>

                <label>
                    <input type="checkbox" id="pageSymbols" checked>
                    Symbols
                </label>
            </div>

        </div>
    `;
}

function renderSecurityPage() {
    const health = analyzeVault();

    const weak = activeRecords().filter(
        r => r.type === "Login" && (passwordScore(r) < 3 || r.reused)
    );

    return `
        <div class="stat-grid">

            <div class="stat-card">
                <span class="stat-label">Security score</span>
                <strong>${health.score}/100</strong>
                <small>${health.label}</small>
            </div>

            <div class="stat-card">
                <span class="stat-label">Weak passwords</span>
                <strong>${weak.length}</strong>
                <small>Basic strength check</small>
            </div>

            <div class="stat-card">
                <span class="stat-label">Records checked</span>
                <strong>${activeRecords().length}</strong>
                <small>Active records</small>
            </div>

        </div>

        <div class="panel">

            <div class="panel-title">
                <div>
                    <h3>Security recommendations</h3>
                    <p>Improve your vault hygiene.</p>
                </div>
            </div>

            <div class="security-list">

                ${weak.length
                    ? weak.map(r => `
                        <div class="security-item">
                            <div>
                                <strong>${escapeHTML(r.title)}</strong>
                                <br>
                                <small>
                                    ${r.reused ? "This password is reused on another login." : "Consider replacing this weak password."}
                                </small>
                            </div>

                            <button
                                class="text-button"
                                data-view="${r.id}">
                                Review →
                            </button>
                        </div>
                    `).join("")
                    : `
                        <div class="security-item">
                            <div>
                                <strong>No weak passwords detected</strong>
                                <br>
                                <small>
                                    This basic check is not a full security audit.
                                </small>
                            </div>
                            <span>✓</span>
                        </div>
                    `
                }

                <div class="security-item">
                    <div>
                        <strong>Use a unique master password</strong>
                        <br>
                        <small>
                            Never reuse your master password on another site.
                        </small>
                    </div>
                    <span>◇</span>
                </div>

                <div class="security-item">
                    <div>
                        <strong>Keep encrypted backups</strong>
                        <br>
                        <small>
                            Back up your vault and verify that it can be restored.
                        </small>
                    </div>
                    <span>◇</span>
                </div>

            </div>
        </div>
    `;
}

function renderSettings() {
    return `
        <div class="panel">

            <div class="panel-title">
                <div>
                    <h3>Master password</h3>
                    <p>Re-encrypts your whole vault with a new master password.</p>
                </div>
            </div>

            <form id="changePasswordForm" class="settings-form" autocomplete="off">
                <label for="cpCurrent">Current master password</label>
                <input id="cpCurrent" type="password" maxlength="1024" required
                    autocomplete="current-password" spellcheck="false">

                <label for="cpNew">New master password</label>
                <input id="cpNew" type="password" maxlength="1024" required
                    autocomplete="new-password" spellcheck="false">
                <div class="strength"><i id="cpStrength"></i></div>

                <label for="cpConfirm">Confirm new master password</label>
                <input id="cpConfirm" type="password" maxlength="1024" required
                    autocomplete="new-password" spellcheck="false">

                <p class="form-error" id="cpError"></p>

                <button type="submit" class="primary-button" id="cpSubmit">
                    Change master password
                </button>
            </form>
        </div>

        <div class="panel">

            <div class="panel-title">
                <div>
                    <h3>General settings</h3>
                    <p>VaultX preferences and information.</p>
                </div>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Application</strong>
                    <p>VaultX password manager</p>
                </div>
                <span>v1.1</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Storage</strong>
                    <p>Everything (fields, notes, flags) is encrypted in a local SQLite file</p>
                </div>
                <span>Local</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Auto-lock</strong>
                    <p>The vault locks itself after 15 minutes of inactivity</p>
                </div>
                <span>15 min</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Vault status</strong>
                    <p>${isUnlocked ? "Vault is unlocked" : "Vault is locked"}</p>
                </div>
                <button class="secondary-button" id="lockNowButton">Lock now</button>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Theme</strong>
                    <p>Switch the interface theme</p>
                </div>
                <button class="secondary-button" id="themeButton">
                    Toggle theme
                </button>
            </div>

        </div>
    `;
}

let lastRenderKey = "";

function render() {
    if (!$("pageContent")) return;

    $("allCount").textContent = activeRecords().length;

    $("breadcrumb").textContent =
        currentCategory || pageInfo[currentPage][1];

    $("pageEyebrow").textContent =
        pageInfo[currentPage][0];

    $("pageTitle").textContent =
        currentCategory || pageInfo[currentPage][1];

    $("pageDescription").textContent =
        pageInfo[currentPage][2];

    document.querySelectorAll(".nav-item").forEach(button => {

        const selectedPage =
            button.dataset.page === currentPage && !currentCategory;

        const selectedCategory =
            button.dataset.category === currentCategory;

        button.classList.toggle(
            "active",
            selectedPage || selectedCategory
        );
    });

    if (!isUnlocked) {

        $("pageContent").innerHTML = `
            <div class="empty-state">
                <h3>Your vault is locked</h3>

                <p>
                    Unlock VaultX with your master password
                    to load your encrypted records.
                </p>

                <button class="primary-button" id="unlockPageButton">
                    Unlock vault
                </button>
            </div>
        `;

    } else if (
        currentPage === "all" ||
        ["favorites", "recent", "trash"].includes(currentPage)
    ) {

        $("pageContent").innerHTML =
            currentPage === "all" &&
            !currentCategory &&
            !$("searchInput").value
                ? renderDashboard()
                : renderRecords();

    } else if (currentPage === "generator") {

        $("pageContent").innerHTML = renderGeneratorPage();
        setupPageGenerator();

    } else if (currentPage === "security") {

        $("pageContent").innerHTML = renderSecurityPage();

    } else if (currentPage === "settings") {

        $("pageContent").innerHTML = renderSettings();
    }

    const renderKey = [currentPage, currentCategory, isUnlocked].join("|");

    if (renderKey !== lastRenderKey) {
        lastRenderKey = renderKey;
        $("pageContent").classList.remove("page-in");
        void $("pageContent").offsetWidth;
        $("pageContent").classList.add("page-in");
    }

    $("newItemButton").style.display =
        currentPage === "trash" || !isUnlocked
            ? "none"
            : "block";
}

function navigate(page, category = null) {
    currentPage = page;
    currentCategory = category;

    $("searchInput").value = "";

    render();

    $("sidebar").classList.remove("open");
}

function openNewItem() {
    if (!isUnlocked) {
        return showToast("Unlock your vault first.");
    }

    editingId = null;

    $("itemForm").reset();
    $("itemId").value = "";

    $("modalTitle").textContent = "New item";

    $("itemType").value =
        currentCategory || "Login";

    updateTypeFields();

    openModal("itemModal");
}

function fieldHTML(field, value) {
    const id = `f_${field.k}`;
    const label = `<label for="${id}">${escapeHTML(field.l)}${field.req ? " *" : ""}</label>`;

    if (field.opts) {
        return label + `
            <select id="${id}">
                ${field.opts.map(option => `
                    <option${option === value ? " selected" : ""}>${escapeHTML(option)}</option>
                `).join("")}
            </select>`;
    }

    if (field.secret) {
        return label + `
            <div class="input-with-action">
                <input id="${id}" type="password" maxlength="256" autocomplete="off"
                    placeholder="${escapeHTML(field.ph || "")}" value="${escapeHTML(value)}">
                <button type="button" class="inline-button" data-toggle="${field.k}">Show</button>
                ${field.gen ? `<button type="button" class="inline-button" data-generate="${field.k}">Generate</button>` : ""}
            </div>`;
    }

    return label + `
        <input id="${id}" type="${field.type || "text"}" maxlength="500" autocomplete="off"
            placeholder="${escapeHTML(field.ph || "")}" value="${escapeHTML(value)}">`;
}

function updateTypeFields(values = {}) {
    const type = $("itemType").value;
    const defs = TYPE_FIELDS[type] || [];

    $("typeFields").innerHTML =
        defs.map(field => fieldHTML(field, values[field.k] || "")).join("");

    const isNote = type === "Secure Note";

    $("notesLabel").textContent = isNote ? "Note content *" : "Notes";
    $("itemNotes").rows = isNote ? 8 : 3;
}

function itemPayload() {
    const type = $("itemType").value;

    const item = {
        title: $("itemTitle").value.trim(),
        type,
        folder: $("itemFolder").value,
        notes: $("itemNotes").value.trim()
    };

    for (const field of TYPE_FIELDS[type] || []) {
        const input = $(`f_${field.k}`);
        if (input) item[field.k] = field.secret ? input.value : input.value.trim();
    }

    return item;
}

function validateItem(item) {
    if (!item.title) return "Please enter a title.";

    for (const field of TYPE_FIELDS[item.type] || []) {
        if (field.req && !item[field.k]) return `${field.l} is required.`;
    }

    if (item.type === "Secure Note" && !item.notes) {
        return "Note content is required.";
    }

    if (item.type === "Login" && item.password.length < 6) {
        return "Password must contain at least 6 characters.";
    }

    return "";
}

async function saveItem(event) {
    event.preventDefault();

    const item = itemPayload();
    const problem = validateItem(item);

    if (problem) return showToast(problem);

    try {

        if (editingId !== null) {

            await apiRequest(
                `/api/entries/${encodeURIComponent(editingId)}`,
                {
                    method: "PUT",
                    body: JSON.stringify(item)
                }
            );

            showToast("Record updated.");

        } else {

            await apiRequest("/api/entries", {
                method: "POST",
                body: JSON.stringify(item)
            });

            showToast("Record added.");
        }

        closeModal("itemModal");

        await loadEntries();

    } catch (error) {

        showToast(
            `Could not save record: ${error.message}`
        );
    }
}

let detailsRecord = null;

// Secrets and notes are only fetched when an item is opened.
async function fetchFull(id) {
    return normalizeRecord(
        await apiRequest(`/api/entries/${encodeURIComponent(id)}`)
    );
}

async function showDetails(id) {
    let item;

    try {
        item = await fetchFull(id);
    } catch (error) {
        return showToast(`Could not open record: ${error.message}`);
    }

    detailsRecord = item;
    $("detailsTitle").textContent = item.title;

    const inTrash = item.deleted;
    const plainRow = (label, value, className = "") => `
        <div class="detail-row">
            <small>${escapeHTML(label)}</small>
            <strong class="${className}">${escapeHTML(value)}</strong>
        </div>`;

    let html = plainRow("Type", `${icons[item.type] || ""} ${item.type}`);

    for (const field of TYPE_FIELDS[item.type] || []) {
        const value = item.fields[field.k];

        if (!value) continue;

        html += `
            <div class="detail-row with-actions">
                <div class="detail-main">
                    <small>${escapeHTML(field.l)}</small>
                    <strong data-value="${field.k}" data-masked="${field.secret ? 1 : 0}">${
                        field.secret ? "••••••••••" : escapeHTML(value)
                    }</strong>
                </div>
                <div class="row-buttons">
                    ${field.secret ? `<button class="mini-button" data-reveal="${field.k}">Show</button>` : ""}
                    <button class="mini-button" data-copy-field="${field.k}">Copy</button>
                </div>
            </div>`;
    }

    html += plainRow("Folder", item.folder);

    if (item.notes) html += plainRow("Notes", item.notes, "pre");

    html += `
        <div class="detail-actions">
            ${inTrash
                ? `<button class="secondary-button" data-restore="${item.id}">Restore</button>`
                : `<button class="secondary-button" data-edit="${item.id}">Edit</button>`}
            <button class="secondary-button danger" data-delete="${item.id}">
                ${inTrash ? "Permanently delete" : "Move to trash"}
            </button>
        </div>`;

    $("detailsContent").innerHTML = html;

    openModal("detailsModal");
}

async function editItem(id) {
    let item;

    try {
        item = await fetchFull(id);
    } catch (error) {
        return showToast(`Could not open record: ${error.message}`);
    }

    editingId = id;

    $("itemId").value = id;
    $("itemTitle").value = item.title;
    $("itemType").value = item.type;

    if (![...$("itemFolder").options].some(o => o.value === item.folder)) {
        $("itemFolder").add(new Option(item.folder));
    }

    $("itemFolder").value = item.folder;
    $("itemNotes").value = item.notes;

    updateTypeFields(item.fields);

    $("modalTitle").textContent = "Edit item";

    closeModal("detailsModal");
    openModal("itemModal");
}

async function restoreItem(id) {
    try {
        await apiRequest(
            `/api/entries/${encodeURIComponent(id)}/trash`,
            {
                method: "PATCH",
                body: JSON.stringify({ deleted: false })
            }
        );

        showToast("Record restored.");
        closeModal("detailsModal");
        await loadEntries();

    } catch (error) {
        showToast(`Could not restore record: ${error.message}`);
    }
}

async function deleteItem(id) {
    const permanently = currentPage === "trash";

    if (
        permanently &&
        !confirm("Permanently delete this record?")
    ) {
        return;
    }

    try {

        if (permanently) {

            await apiRequest(
                `/api/entries/${encodeURIComponent(id)}`,
                { method: "DELETE" }
            );

            showToast("Record permanently deleted.");

        } else {

            await apiRequest(
                `/api/entries/${encodeURIComponent(id)}/trash`,
                {
                    method: "PATCH",
                    body: JSON.stringify({ deleted: true })
                }
            );

            showToast("Record moved to trash.");
        }

        closeModal("detailsModal");

        await loadEntries();

    } catch (error) {

        showToast(
            `Could not delete record: ${error.message}`
        );
    }
}

async function toggleFavorite(id) {
    const item = records.find(r => r.id === id);

    if (!item) return;

    const next = !item.favorite;

    item.favorite = next;  // update instantly, undo if the server refuses
    render();

    try {
        await apiRequest(
            `/api/entries/${encodeURIComponent(id)}/favorite`,
            {
                method: "PATCH",
                body: JSON.stringify({ favorite: next })
            }
        );
    } catch (error) {
        item.favorite = !next;
        render();
        showToast(`Could not update favorite: ${error.message}`);
    }
}

function secureRandomIndex(max) {
    if (!window.crypto?.getRandomValues) {
        throw new Error(
            "Secure random generation is unavailable."
        );
    }

    const limit = Math.floor(256 / max) * max;
    const byte = new Uint8Array(1);

    do {
        window.crypto.getRandomValues(byte);
    } while (byte[0] >= limit);

    return byte[0] % max;
}

function generatePassword(length, options) {
    const groups = [];

    if (options.upper) {
        groups.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    if (options.lower) {
        groups.push("abcdefghijklmnopqrstuvwxyz");
    }

    if (options.numbers) {
        groups.push("0123456789");
    }

    if (options.symbols) {
        groups.push("!@#$%^&*()-_=+[]{}?");
    }

    if (!groups.length) {
        throw new Error(
            "Select at least one character type."
        );
    }

    if (length < groups.length) {
        throw new Error(
            "Password length is too short for selected options."
        );
    }

    const all = groups.join("");

    const chars = groups.map(
        group => group[secureRandomIndex(group.length)]
    );

    while (chars.length < length) {
        chars.push(all[secureRandomIndex(all.length)]);
    }

    for (let i = chars.length - 1; i > 0; i--) {
        const j = secureRandomIndex(i + 1);

        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join("");
}

function generatorOptions(prefix = "") {
    return {
        upper: $(prefix + "Upper")?.checked ?? true,
        lower: $(prefix + "Lower")?.checked ?? true,
        numbers: $(prefix + "Numbers")?.checked ?? true,
        symbols: $(prefix + "Symbols")?.checked ?? true
    };
}

function generateForModal() {
    const length = Number($("passwordLength").value);

    $("lengthValue").textContent = length;

    try {

        $("generatedPassword").textContent =
            generatePassword(
                length,
                generatorOptions("include")
            );

    } catch (error) {

        showToast(error.message);
    }
}

function setupPageGenerator() {
    const length = $("pagePasswordLength");

    if (!length) return;

    const generate = () => {

        $("pageLengthValue").textContent = length.value;

        try {

            $("pageGeneratedPassword").textContent =
                generatePassword(
                    Number(length.value),
                    {
                        upper: $("pageUpper").checked,
                        lower: $("pageLower").checked,
                        numbers: $("pageNumbers").checked,
                        symbols: $("pageSymbols").checked
                    }
                );

        } catch (error) {

            showToast(error.message);
        }
    };

    length.addEventListener("input", generate);

    $("pageRegenerate").addEventListener(
        "click",
        generate
    );

    $("pageCopyGenerated").addEventListener(
        "click",
        () => copyText(
            $("pageGeneratedPassword").textContent
        )
    );

    generate();
}

let clipboardTimer = null;

async function copyText(value) {
    if (!value) {
        return showToast("Nothing to copy.");
    }

    try {
        await navigator.clipboard.writeText(value);

        showToast("Copied. Clipboard clears in 30 seconds.");

        clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(
            () => navigator.clipboard.writeText(" ").catch(() => {}),
            30000
        );

    } catch {
        showToast(
            "Clipboard access unavailable. Use the VaultX website in a secure browser context."
        );
    }
}

// Navigation and form events

document.querySelectorAll("[data-page]").forEach(button =>
    button.addEventListener(
        "click",
        () => navigate(button.dataset.page)
    )
);

document.querySelectorAll("[data-category]").forEach(button =>
    button.addEventListener(
        "click",
        () => navigate("all", button.dataset.category)
    )
);

$("newItemButton").addEventListener(
    "click",
    openNewItem
);

$("itemForm").addEventListener(
    "submit",
    saveItem
);

$("itemType").addEventListener(
    "change",
    () => updateTypeFields()
);

$("searchInput").addEventListener(
    "input",
    render
);

$("mobileMenu").addEventListener(
    "click",
    () => $("sidebar").classList.toggle("open")
);

$("lockButton").addEventListener(
    "click",
    () => isUnlocked ? lockVault() : unlockVault()
);

$("typeFields").addEventListener("click", event => {

    const button = event.target.closest("button");

    if (!button) return;

    if (button.dataset.toggle) {
        const input = $(`f_${button.dataset.toggle}`);

        input.type = input.type === "password" ? "text" : "password";
        button.textContent = input.type === "password" ? "Show" : "Hide";
    }

    if (button.dataset.generate) {
        try {
            $(`f_${button.dataset.generate}`).value = generatePassword(
                20,
                { upper: true, lower: true, numbers: true, symbols: true }
            );

            showToast("Generated a strong value.");

        } catch (error) {
            showToast(error.message);
        }
    }
});

$("pageContent").addEventListener("input", event => {
    if (event.target.id !== "cpNew") return;

    const bar = $("cpStrength");
    const score = masterScore(event.target.value);

    bar.style.width = `${score * 25}%`;
    bar.style.background =
        ["#f07178", "#f07178", "#f5b84b", "#6cc17a", "#35c995"][score];
});

$("pageContent").addEventListener("click", event => {
    if (event.target.closest("#lockNowButton")) lockVault();
});

$("pageContent").addEventListener("submit", async event => {
    if (event.target.id !== "changePasswordForm") return;

    event.preventDefault();

    const current = $("cpCurrent").value;
    const next = $("cpNew").value;
    const error = $("cpError");
    const button = $("cpSubmit");

    error.textContent = "";

    if (next.length < 10) {
        error.textContent = "Use at least 10 characters.";
        return;
    }

    if (next !== $("cpConfirm").value) {
        error.textContent = "The new passwords do not match.";
        return;
    }

    if (next === current) {
        error.textContent = "The new password must be different.";
        return;
    }

    button.disabled = true;
    button.textContent = "Re-encrypting vault…";

    try {
        await apiRequest("/api/change-password", {
            method: "POST",
            body: JSON.stringify({ current, next })
        });

        event.target.reset();
        $("cpStrength").style.width = "0";

        showToast("Master password changed. Your vault was re-encrypted.");

    } catch (err) {
        error.textContent = err.message;

    } finally {
        button.disabled = false;
        button.textContent = "Change master password";
    }
});

$("unlockForm").addEventListener("submit", submitUnlock);
$("unlockPassword").addEventListener("input", updateUnlockStrength);

$("toggleUnlock").addEventListener("click", () => {
    const input = $("unlockPassword");

    input.type = input.type === "password" ? "text" : "password";
    $("toggleUnlock").textContent = input.type === "password" ? "Show" : "Hide";
});

$("passwordLength").addEventListener(
    "input",
    generateForModal
);

$("regenerate").addEventListener(
    "click",
    generateForModal
);

$("copyGenerated").addEventListener(
    "click",
    () => copyText(
        $("generatedPassword").textContent
    )
);

document.querySelectorAll("[data-close]").forEach(button =>
    button.addEventListener(
        "click",
        () => closeModal(button.dataset.close)
    )
);

document.querySelectorAll(".modal-backdrop").forEach(backdrop =>
    backdrop.addEventListener("click", event => {

        if (event.target === backdrop) {
            closeModal(backdrop.id);
        }

    })
);

// Delegated actions for dynamically rendered content

$("pageContent").addEventListener("click", event => {

    const target = event.target.closest("button");

    if (!target) return;

    if (target.dataset.view) {
        showDetails(Number(target.dataset.view));
    }

    if (target.dataset.favorite) {
        toggleFavorite(Number(target.dataset.favorite));
    }

    if (target.dataset.action === "new") {
        openNewItem();
    }

    if (target.dataset.action === "generator") {
        navigate("generator");
    }

    if (target.dataset.action === "security") {
        navigate("security");
    }

    if (target.dataset.action === "all") {
        navigate("all");
    }

    if (target.id === "unlockPageButton") {
        unlockVault();
    }

    if (target.id === "themeButton") {
        document.body.classList.toggle("dark-mode");
        showToast("Theme changed.");
    }
});

// Sorting

$("pageContent").addEventListener("change", event => {

    if (event.target.id !== "sortRecords") return;

    const grid = $("recordGrid");

    if (!grid) return;

    const sorted = visibleRecords();

    if (event.target.value === "oldest") {

        sorted.sort((a, b) => a.created - b.created);

    } else if (event.target.value === "name") {

        sorted.sort((a, b) =>
            a.title.localeCompare(b.title)
        );

    } else {

        sorted.sort((a, b) => b.created - a.created);
    }

    grid.innerHTML = sorted
        .map(renderRecordCard)
        .join("");
});

// Details modal actions

$("detailsContent").addEventListener("click", event => {

    const button = event.target.closest("button");

    if (!button) return;

    const item = detailsRecord;

    if (button.dataset.reveal && item) {
        const key = button.dataset.reveal;
        const element = $("detailsContent").querySelector(`[data-value="${key}"]`);
        const hidden = element.dataset.masked === "1";

        element.textContent = hidden ? item.fields[key] : "••••••••••";
        element.dataset.masked = hidden ? "0" : "1";
        button.textContent = hidden ? "Hide" : "Show";
    }

    if (button.dataset.copyField && item) {
        copyText(item.fields[button.dataset.copyField]);
    }

    if (button.dataset.edit) editItem(Number(button.dataset.edit));
    if (button.dataset.delete) deleteItem(Number(button.dataset.delete));
    if (button.dataset.restore) restoreItem(Number(button.dataset.restore));
});

// Keyboard shortcuts

document.addEventListener("keydown", event => {

    if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "k"
    ) {
        event.preventDefault();
        $("searchInput").focus();
    }

    if (event.key === "Escape") {
        [
            "itemModal",
            "generatorModal",
            "detailsModal"
        ].forEach(closeModal);
    }
});

// Initial screen.
// The master password is never stored in browser storage.

render();

setConnectionStatus("C++ API · Locked");

// Checks the server and opens the unlock (or create-vault) dialog.
unlockVault();

console.log("VaultX frontend connected to API.");