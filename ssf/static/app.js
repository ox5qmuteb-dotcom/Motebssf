const $ = (id) => document.getElementById(id);
let key = sessionStorage.getItem("ssf_key") || "";
$("key").value = key;
async function api(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: {"X-API-Key": key, "Content-Type": "application/json"}});
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.status);
  return data;
}
const show = (id, v) => { $(id).textContent = typeof v === "string" ? v : JSON.stringify(v, null, 2); };
async function refresh() {
  try {
    const s = await api("/api/threats/status");
    $("threats").replaceChildren(...[["Events", s.events], ["Alerts", s.alerts]].map(([k, v]) => {
      const d = document.createElement("div"); d.className = "card"; d.textContent = `${k}: ${v}`; return d; }));
    show("alerts", s.recent_alerts);
    show("users", await api("/api/access/users"));
    show("report", await api("/api/reports"));
  } catch (e) { show("alerts", "Error: " + e.message); }
}
$("login").onclick = () => { key = $("key").value; sessionStorage.setItem("ssf_key", key); refresh(); };
$("scan").onclick = async () => {
  try { show("scanout", await api("/api/scan", {method: "POST", body: JSON.stringify({path: $("path").value || "."})})); refresh(); }
  catch (e) { show("scanout", "Error: " + e.message); }
};
if (key) { refresh(); setInterval(refresh, 15000); }
