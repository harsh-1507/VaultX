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

function normalizeRecord(raw) {
    return {
        id: Number(raw.id),
        title: String(raw.title ?? raw.service ?? ""),
        type: String(raw.type ?? "Login"),
        username: String(raw.username ?? ""),
        password: String(raw.password ?? ""),
        url: String(raw.url ?? raw.website ?? ""),
        folder: String(raw.folder ?? raw.category ?? "Personal"),
        notes: String(raw.notes ?? ""),
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

async function unlockVault() {
    const masterPassword = window.prompt(
        "Enter your VaultX master password:"
    );

    if (masterPassword === null) return;

    if (!masterPassword) {
        showToast("Master password cannot be empty.");
        return;
    }

    try {
        await apiRequest("/api/unlock", {
            method: "POST",
            body: JSON.stringify({ masterPassword })
        });

        isUnlocked = true;

        await loadEntries();

        setConnectionStatus("Connected · Vault unlocked", true);
        showToast("Vault unlocked.");

    } catch (error) {
        isUnlocked = false;
        showToast(error.message);
        setConnectionStatus("Connection failed");
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
    showToast("Vault locked.");
}

async function loadEntries() {
    if (isLoading) return;

    isLoading = true;

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
            record.username.toLowerCase().includes(query) ||
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
                        ${escapeHTML(record.username || record.type)}
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

function passwordScore(password) {
    let score = 0;

    if (password.length >= 12) score++;
    if (password.length >= 16) score++;

    if (/[a-z]/.test(password) &&
        /[A-Z]/.test(password)) score++;

    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    return score;
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
        (sum, r) => sum + passwordScore(r.password),
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
        r => r.type === "Login" && passwordScore(r.password) < 3
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
                                    Consider replacing this weak password.
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
                    <h3>General settings</h3>
                    <p>VaultX preferences and information.</p>
                </div>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Application</strong>
                    <p>VaultX password manager</p>
                </div>
                <span>v1.0</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Storage mode</strong>
                    <p>Encrypted SQLite database</p>
                </div>
                <span>Local</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Backend connection</strong>
                    <p>C++ Crow API</p>
                </div>
                <span>${isUnlocked ? "Connected" : "Locked"}</span>
            </div>

            <div class="settings-row">
                <div>
                    <strong>Vault status</strong>
                    <p>${isUnlocked ? "Vault is unlocked" : "Vault is locked"}</p>
                </div>
                <span>${isUnlocked ? "Unlocked" : "Locked"}</span>
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

    $("itemPassword").type = "password";
    $("togglePassword").textContent = "Show";

    updateTypeFields();

    openModal("itemModal");
}

function updateTypeFields() {
    const type = $("itemType").value;

    $("loginFields").style.display =
        type === "Login" ? "block" : "none";
}

function itemPayload() {
    return {
        title: $("itemTitle").value.trim(),

        type: $("itemType").value,

        username:
            $("itemType").value === "Login"
                ? $("itemUsername").value.trim()
                : "",

        password:
            $("itemType").value === "Login"
                ? $("itemPassword").value
                : "",

        url:
            $("itemType").value === "Login"
                ? $("itemUrl").value.trim()
                : "",

        folder: $("itemFolder").value,

        notes: $("itemNotes").value.trim()
    };
}

async function saveItem(event) {
    event.preventDefault();

    const item = itemPayload();

    if (!item.title) {
        return showToast("Please enter a title.");
    }

    if (item.type === "Login" && item.password.length < 6) {
        return showToast(
            "Password must contain at least 6 characters."
        );
    }

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

function showDetails(id) {
    const item = records.find(r => r.id === id);

    if (!item) return;

    $("detailsTitle").textContent = item.title;

    const rows = [
        ["Type", item.type],
        ["Username", item.username],
        ["Password", item.password],
        ["Website", item.url],
        ["Folder", item.folder],
        ["Notes", item.notes]
    ].filter(row => row[1]);

    $("detailsContent").innerHTML =
        rows.map(([label, value]) => `
            <div class="detail-row">
                <small>${escapeHTML(label)}</small>
                <strong>${escapeHTML(value)}</strong>
            </div>
        `).join("") + `

        <div class="detail-actions">

            ${item.type === "Login" ? `
                <button
                    class="secondary-button"
                    data-copy="${item.id}"
                    data-field="username">
                    Copy username
                </button>

                <button
                    class="secondary-button"
                    data-copy="${item.id}"
                    data-field="password">
                    Copy password
                </button>
            ` : ""}

            <button
                class="secondary-button"
                data-edit="${item.id}">
                Edit
            </button>

            <button
                class="secondary-button"
                data-delete="${item.id}">
                ${currentPage === "trash"
                    ? "Permanently delete"
                    : "Move to trash"}
            </button>

        </div>
    `;

    openModal("detailsModal");
}

function editItem(id) {
    const item = records.find(r => r.id === id);

    if (!item) return;

    editingId = id;

    $("itemId").value = id;
    $("itemTitle").value = item.title;
    $("itemType").value = item.type;
    $("itemUsername").value = item.username;
    $("itemPassword").value = item.password;
    $("itemUrl").value = item.url;
    $("itemFolder").value = item.folder;
    $("itemNotes").value = item.notes;

    $("modalTitle").textContent = "Edit item";

    updateTypeFields();

    closeModal("detailsModal");
    openModal("itemModal");
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

    try {

        await apiRequest(
            `/api/entries/${encodeURIComponent(id)}/favorite`,
            {
                method: "PATCH",
                body: JSON.stringify({
                    favorite: !item.favorite
                })
            }
        );

        await loadEntries();

    } catch (error) {

        showToast(
            `Could not update favorite: ${error.message}`
        );
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

async function copyText(value) {
    if (!value) {
        return showToast("Nothing to copy.");
    }

    try {

        await navigator.clipboard.writeText(value);

        showToast("Copied to clipboard.");

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
    updateTypeFields
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

$("togglePassword").addEventListener("click", () => {

    const input = $("itemPassword");

    input.type =
        input.type === "password"
            ? "text"
            : "password";

    $("togglePassword").textContent =
        input.type === "password"
            ? "Show"
            : "Hide";
});

$("generateInForm").addEventListener("click", () => {

    try {

        $("itemPassword").value =
            generatePassword(
                20,
                {
                    upper: true,
                    lower: true,
                    numbers: true,
                    symbols: true
                }
            );

        showToast("Password generated.");

    } catch (error) {

        showToast(error.message);
    }
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

    const id = Number(
        button.dataset.copy ||
        button.dataset.edit ||
        button.dataset.delete
    );

    if (button.dataset.copy) {

        const item = records.find(r => r.id === id);

        if (item) {
            copyText(item[button.dataset.field]);
        }
    }

    if (button.dataset.edit) {
        editItem(id);
    }

    if (button.dataset.delete) {
        deleteItem(id);
    }
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

console.log("VaultX frontend connected to API.");