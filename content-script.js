// Google arama kutusundaki CVE pattern'ini yakalayıp
// ilgili CVE hakkında özet bilgi gösterir.

const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/i;

function isDarkMode() {
  return (
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

function getSearchQuery() {
  const url = new URL(window.location.href);
  const q = url.searchParams.get("q") || "";
  return q;
}

function extractCveId(query) {
  const match = query.toUpperCase().match(CVE_REGEX);
  return match ? match[0] : null;
}

function ensurePanelContainer() {
  const existing = document.getElementById("vulnfinder-panel");
  if (existing) return existing;

  const container = document.createElement("div");
  container.id = "vulnfinder-panel";
  container.style.boxSizing = "border-box";
  container.style.margin = "20px 0";
  container.style.padding = "18px 20px";
  container.style.borderRadius = "14px";
  container.style.fontFamily =
    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  container.style.fontSize = "14px";
  container.style.boxShadow = "0 18px 40px rgba(0,0,0,0.12)";
  container.style.position = "relative";
  container.style.overflow = "hidden";

  // İnce gradient border efekti
  container.style.border = "1px solid transparent";
  container.style.backgroundClip = "padding-box";

  // Google sonuç sayfasında ortadaki ana kolon genelde #center_col
  const anchor =
    document.getElementById("center_col") ||
    document.querySelector("#search") ||
    document.body;

  anchor.prepend(container);
  return container;
}

function renderLoading(cveId) {
  const panel = ensurePanelContainer();
  panel.innerHTML = "";

  const dark = isDarkMode();
  panel.style.border = dark
    ? "1px solid rgba(138, 180, 248, 0.4)"
    : "1px solid rgba(26, 115, 232, 0.18)";
  panel.style.background = dark
    ? "radial-gradient(circle at top left, #1f2933 0, #111827 40%, #020617 100%)"
    : "radial-gradient(circle at top left, #e8f0fe 0, #f9fbff 40%, #ffffff 100%)";
  panel.style.color = dark ? "#e8eaed" : "#202124";

  const title = document.createElement("div");
  title.style.display = "flex";
  title.style.alignItems = "center";
  title.style.justifyContent = "space-between";
  title.style.columnGap = "12px";

  const left = document.createElement("div");
  left.textContent = `VulnFinder – ${cveId}`;
  left.style.fontWeight = "600";
  left.style.letterSpacing = "0.02em";
  left.style.fontSize = "13px";
  if (dark) left.style.color = "#e8eaed";

  const badge = document.createElement("span");
  badge.textContent = "Yükleniyor...";
  badge.style.fontSize = "12px";
  badge.style.color = dark ? "#8ab4f8" : "#1a73e8";

  title.appendChild(left);
  title.appendChild(badge);

  const desc = document.createElement("div");
  desc.textContent =
    "Zafiyet detayları getiriliyor. Bu, kaynak API'ye bağlı olarak birkaç saniye sürebilir.";
  desc.style.marginTop = "8px";
  desc.style.opacity = "0.9";
  desc.style.fontSize = "13px";

  panel.appendChild(title);
  panel.appendChild(desc);
}

function renderError(message, cveId) {
  const panel = ensurePanelContainer();
  panel.innerHTML = "";

  const dark = isDarkMode();
  panel.style.border = dark
    ? "1px solid rgba(248, 113, 113, 0.5)"
    : "1px solid rgba(217, 48, 37, 0.25)";
  panel.style.background = dark
    ? "radial-gradient(circle at top left, #3f1d20 0, #1f0f12 35%, #050204 100%)"
    : "radial-gradient(circle at top left, #fee2e2 0, #fff7f7 40%, #ffffff 100%)";
  panel.style.color = dark ? "#e8eaed" : "#202124";

  const title = document.createElement("div");
  title.textContent = `VulnFinder – ${cveId || "CVE bulunamadı"}`;
  title.style.fontWeight = "600";
  title.style.marginBottom = "4px";
  title.style.display = "flex";
  title.style.alignItems = "center";
  title.style.columnGap = "6px";
  if (dark) title.style.color = "#e8eaed";

  const error = document.createElement("div");
  error.textContent = message;
  error.style.color = dark ? "#f28b82" : "#d93025";

  panel.appendChild(title);
  panel.appendChild(error);
}

function renderVuln(cveId, data) {
  const panel = ensurePanelContainer();
  panel.innerHTML = "";

  const dark = isDarkMode();
  panel.style.border = dark
    ? "1px solid rgba(138, 180, 248, 0.4)"
    : "1px solid rgba(26, 115, 232, 0.18)";
  panel.style.background = dark
    ? "radial-gradient(circle at top left, #111827 0, #020617 40%, #000000 100%)"
    : "radial-gradient(circle at top left, #e8f0fe 0, #f9fbff 40%, #ffffff 100%)";
  panel.style.color = dark ? "#e8eaed" : "#202124";

  const ref = data.id || cveId;
  const summary =
    data.summary ||
    (data.descriptions && data.descriptions[0] && data.descriptions[0].value) ||
    "Açıklama bulunamadı.";

  const cvssV2 =
    (data.cvss && (data.cvss.v2 || data.cvss.score || data.cvss.cvss)) ||
    (data.cvss &&
      data.cvss.cvssV2 &&
      (data.cvss.cvssV2.baseScore || data.cvss.cvssV2.score));

  const cvssV3 =
    (data.cvss && (data.cvss.v3 || (data.cvss.cvssV3 && data.cvss.cvssV3.baseScore))) ||
    (data.cvss3 && (data.cvss3.v3 || data.cvss3.score));

  const cvssV4 = data.cvss && data.cvss.v4;

  const references = data.references || data.refs || [];

  const header = document.createElement("div");
  header.style.display = "flex";
  header.style.justifyContent = "space-between";
  header.style.alignItems = "center";
  header.style.marginBottom = "10px";

  const title = document.createElement("div");
  title.textContent = `VulnFinder – ${ref}`;
  title.style.fontWeight = "600";
  title.style.letterSpacing = "0.02em";
  title.style.fontSize = "13px";
  if (dark) title.style.color = "#e8eaed";

  const badge = document.createElement("span");
  badge.textContent = "CVE özeti";
  badge.style.fontSize = "12px";
  badge.style.background = dark
    ? "rgba(37, 99, 235, 0.16)"
    : "rgba(26, 115, 232, 0.12)";
  badge.style.color = dark ? "#93c5fd" : "#1a73e8";
  badge.style.padding = "2px 8px";
  badge.style.borderRadius = "999px";
  badge.style.border = dark
    ? "1px solid rgba(37, 99, 235, 0.35)"
    : "1px solid rgba(26, 115, 232, 0.35)";

  header.appendChild(title);
  header.appendChild(badge);

  const summaryEl = document.createElement("div");
  summaryEl.textContent = summary;
  summaryEl.style.marginTop = "8px";
  summaryEl.style.lineHeight = "1.5";
  summaryEl.style.fontSize = "13px";
  if (dark) summaryEl.style.color = "#e8eaed";

  const scores = document.createElement("div");
  scores.style.marginTop = "10px";
  scores.style.display = "flex";
  scores.style.gap = "12px";
  scores.style.flexWrap = "wrap";

  if (cvssV2) {
    const chip = document.createElement("span");
    chip.textContent = `CVSS v2: ${cvssV2}`;
    chip.style.fontSize = "12px";
    chip.style.background = dark ? "#3c4043" : "#f1f3f4";
    chip.style.color = dark ? "#e8eaed" : "#202124";
    chip.style.padding = "2px 8px";
    chip.style.borderRadius = "999px";
    scores.appendChild(chip);
  }

  if (cvssV3) {
    const chip = document.createElement("span");
    chip.textContent = `CVSS v3: ${cvssV3}`;
    chip.style.fontSize = "12px";
    chip.style.background = dark ? "#3c4043" : "#f1f3f4";
    chip.style.color = dark ? "#e8eaed" : "#202124";
    chip.style.padding = "2px 8px";
    chip.style.borderRadius = "999px";
    scores.appendChild(chip);
  }

  if (cvssV4) {
    const chip = document.createElement("span");
    chip.textContent = `CVSS v4: ${cvssV4}`;
    chip.style.fontSize = "12px";
    chip.style.background = dark ? "#3c4043" : "#f1f3f4";
    chip.style.color = dark ? "#e8eaed" : "#202124";
    chip.style.padding = "2px 8px";
    chip.style.borderRadius = "999px";
    scores.appendChild(chip);
  }

  const poc = document.createElement("div");
  poc.style.marginTop = "8px";
  poc.style.fontSize = "13px";
  poc.style.color = dark ? "#bdc1c6" : "#5f6368";
  if (references.length > 0) {
    poc.textContent =
      "PoC ve detaylar için bazı referanslar (dış bağlantılar):";
    const list = document.createElement("ul");
    list.style.marginTop = "4px";
    list.style.paddingLeft = "20px";
    list.style.marginBottom = "4px";

    references.slice(0, 5).forEach((r) => {
      const url = typeof r === "string" ? r : r.url || r.href || "";
      if (!url) return;
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = url;
      a.textContent = url.replace(/^https?:\/\//, "").slice(0, 60);
      a.target = "_blank";
      a.rel = "noopener noreferrer";
       a.style.textDecoration = "none";
       a.style.color = dark ? "#93c5fd" : "#1a73e8";
       a.style.borderBottom = dark
         ? "1px solid rgba(147, 197, 253, 0.25)"
         : "1px dashed rgba(26, 115, 232, 0.35)";
       a.style.paddingBottom = "1px";
      li.appendChild(a);
      list.appendChild(li);
    });
    poc.appendChild(list);
  } else {
    poc.textContent =
      "Bu CVE için PoC/ref linkleri API yanıtında bulunamadı. Detaylar için aşağıdaki resmi CVE sayfalarına bakabilirsiniz.";
  }

  const footer = document.createElement("div");
  footer.style.marginTop = "8px";
  footer.style.fontSize = "12px";
  footer.style.color = dark ? "#bdc1c6" : "#5f6368";

  const nvdLink = document.createElement("a");
  nvdLink.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(
    ref
  )}`;
  nvdLink.textContent = "NVD detayı";
  nvdLink.target = "_blank";
  nvdLink.rel = "noopener noreferrer";

  const mitreLink = document.createElement("a");
  mitreLink.href = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(
    ref
  )}`;
  mitreLink.textContent = "MITRE kaydı";
  mitreLink.target = "_blank";
  mitreLink.rel = "noopener noreferrer";
  mitreLink.style.marginLeft = "12px";

  footer.appendChild(nvdLink);
  footer.appendChild(mitreLink);

  panel.appendChild(header);
  panel.appendChild(summaryEl);
  panel.appendChild(scores);
  panel.appendChild(poc);
  panel.appendChild(footer);
}

function normalizeCveDataFromCveAwg(raw, cveId) {
  if (!raw || !raw.containers || !raw.containers.cna) return raw;
  const cna = raw.containers.cna;

  const descEntry =
    (cna.descriptions || []).find((d) => d.lang === "en") ||
    (cna.descriptions || [])[0];

  const metrics = cna.metrics || [];
  let v2, v3, v4;
  metrics.forEach((m) => {
    if (m.cvssV2_0 && m.cvssV2_0.baseScore != null) {
      v2 = m.cvssV2_0.baseScore;
    }
    if (m.cvssV3_1 && m.cvssV3_1.baseScore != null) {
      v3 = m.cvssV3_1.baseScore;
    }
    if (m.cvssV4_0 && m.cvssV4_0.baseScore != null) {
      v4 = m.cvssV4_0.baseScore;
    }
  });

  const refs =
    (cna.references || []).map((r) => ({
      url: r.url,
    })) || [];

  return {
    id: cveId,
    summary: descEntry ? descEntry.value : undefined,
    cvss: { v2, v3, v4 },
    references: refs,
  };
}

async function fetchCveData(cveId) {
  // Önce CVE.org (cveawg) dene
  try {
    const urlAwg = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(
      cveId
    )}`;
    const respAwg = await fetch(urlAwg);
    if (respAwg.ok) {
      const raw = await respAwg.json();
      return normalizeCveDataFromCveAwg(raw, cveId);
    }
  } catch (e) {
    console.warn("CVEAWG isteği başarısız, cve.circl.lu deneniyor...", e);
  }

  // Sonra cve.circl.lu yedek olarak dene
  const urlCircl = `https://cve.circl.lu/api/cve/${encodeURIComponent(cveId)}`;
  const respCircl = await fetch(urlCircl);
  if (!respCircl.ok) {
    throw new Error(`API hata kodu: ${respCircl.status}`);
  }
  return respCircl.json();
}

async function runVulnFinder() {
  const query = getSearchQuery();
  const cveId = extractCveId(query);
  if (!cveId) {
    return;
  }

  renderLoading(cveId);

  try {
    const data = await fetchCveData(cveId);
    renderVuln(cveId, data);
  } catch (err) {
    console.error("VulnFinder CVE fetch error", err);
    renderError(
      "CVE bilgisi alınırken bir hata oluştu veya bu CVE API'de bulunamadı.",
      cveId
    );
  }
}

// Sayfa yüklendiğinde çalıştır
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runVulnFinder);
} else {
  runVulnFinder();
}

