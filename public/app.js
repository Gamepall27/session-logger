const $ = id => document.getElementById(id);
const filters = ["hours", "source", "severity", "action", "actor", "success"];
let events = [], timer, requestController;
let eventSort = { key: "occurred_at", direction: "desc" };
const colors = ["#54c5a4", "#75a7d8", "#e3aa5b", "#b691d4", "#e07a9a", "#8fa36b"];
const fmt = new Intl.NumberFormat("de-DE");
const dateFmt = new Intl.DateTimeFormat("de-DE", { dateStyle: "short", timeStyle: "medium" });

function params() {
  const p = new URLSearchParams();
  for (const id of filters) if ($(id).value) p.set(id, $(id).value);
  if ($("search").value.trim()) p.set("q", $("search").value.trim());
  return p;
}
async function api(url, signal) {
  const response = await fetch(url, { signal });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}
function bytes(value) {
  let n = Number(value), unit = "B"; for (const u of ["KB","MB","GB","TB"]) { if (n < 1024) break; n /= 1024; unit = u; }
  return `${new Intl.NumberFormat("de-DE", { maximumFractionDigits: n < 10 ? 1 : 0 }).format(n)} ${unit}`;
}
function escape(value) { const e = document.createElement("span"); e.textContent = value ?? "–"; return e.innerHTML; }

function lineChart(points) {
  if (!points.length) return '<div class="loading">Keine Daten für diesen Zeitraum.</div>';
  const w=900,h=200,p={l:40,r:10,t:10,b:28}, max=Math.max(1,...points.map(x=>x.total));
  const x=i=>p.l+i*(w-p.l-p.r)/Math.max(points.length-1,1), y=v=>h-p.b-v*(h-p.t-p.b)/max;
  const poly=key=>points.map((d,i)=>`${x(i)},${y(d[key])}`).join(" ");
  const grid=[0,.25,.5,.75,1].map(v=>`<line class="grid-line" x1="${p.l}" y1="${y(max*v)}" x2="${w-p.r}" y2="${y(max*v)}"/><text class="axis-label" x="${p.l-7}" y="${y(max*v)+3}" text-anchor="end">${Math.round(max*v)}</text>`).join("");
  const step=Math.max(1,Math.ceil(points.length/6)); const labels=points.map((d,i)=>i%step?"":`<text class="axis-label" x="${x(i)}" y="${h-7}" text-anchor="middle">${new Date(d.bucket).toLocaleDateString("de-DE",{day:"2-digit",month:"2-digit",hour:"2-digit"})}</text>`).join("");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#54c5a4" stop-opacity=".22"/><stop offset="1" stop-color="#54c5a4" stop-opacity="0"/></linearGradient></defs>${grid}<polygon class="area" points="${p.l},${h-p.b} ${poly("total")} ${w-p.r},${h-p.b}"/><polyline class="line-total" points="${poly("total")}"/><polyline class="line-failed" points="${poly("failed")}"/><polyline class="line-high" points="${poly("high")}"/>${labels}</svg>`;
}
function donut(rows) {
  const total=rows.reduce((n,x)=>n+x.value,0); if(!total)return '<div class="loading">Keine Daten</div>';
  let offset=0; const r=48,c=2*Math.PI*r;
  const circles=rows.map((row,i)=>{const len=row.value/total*c;const out=`<circle class="donut-segment" cx="70" cy="70" r="${r}" stroke="${colors[i%colors.length]}" stroke-dasharray="${len} ${c-len}" stroke-dashoffset="${-offset}"/>`;offset+=len;return out}).join("");
  const legend=rows.map((row,i)=>`<div><i style="background:${colors[i%colors.length]}"></i><span>${escape(row.label)}</span><strong>${fmt.format(row.value)}</strong></div>`).join("");
  return `<svg viewBox="0 0 140 140" aria-hidden="true"><circle class="donut-bg" fill="none" stroke-width="16" cx="70" cy="70" r="${r}"/>${circles}</svg><div class="donut-legend">${legend}</div>`;
}
function bars(rows) { const max=Math.max(1,...rows.map(x=>x.value)); return rows.length?rows.map(row=>`<div class="bar-row" title="${escape(row.label)}"><span>${escape(row.label)}</span><div class="bar-track"><div class="bar-fill" style="width:${row.value/max*100}%"></div></div><strong>${fmt.format(row.value)}</strong></div>`).join(""):'<div class="loading">Keine Daten</div>'; }
function target(event) { return event.path || event.command || event.process || event.message; }
const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function sortValue(event, key) {
  if (key === "target") return target(event);
  if (key === "severity") return severityRank[event.severity] ?? -1;
  if (key === "occurred_at") return new Date(event.occurred_at).getTime();
  if (key === "success") return event.success === true ? 1 : event.success === false ? 0 : null;
  return event[key];
}
function sortEvents() {
  const { key, direction } = eventSort;
  events.sort((a, b) => {
    const av = sortValue(a, key), bv = sortValue(b, key);
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    const comparison = typeof av === "number" && typeof bv === "number"
      ? av - bv
      : String(av).localeCompare(String(bv), "de", { numeric: true, sensitivity: "base" });
    return direction === "asc" ? comparison : -comparison;
  });
}
function updateSortHeaders() {
  document.querySelectorAll(".sort-button").forEach(button => {
    const active = button.dataset.sort === eventSort.key;
    const th = button.closest("th");
    button.classList.toggle("active", active);
    button.querySelector(".sort-mark").textContent = active ? (eventSort.direction === "asc" ? "↑" : "↓") : "↕";
    if (active) th.setAttribute("aria-sort", eventSort.direction === "asc" ? "ascending" : "descending");
    else th.removeAttribute("aria-sort");
  });
}
function renderEvents() {
  sortEvents(); updateSortHeaders();
  $("event-count").textContent=`${fmt.format(events.length)} angezeigt`;
  $("empty").hidden=events.length>0; $("events-body").innerHTML=events.map((e,i)=>`<tr tabindex="0" data-index="${i}"><td>${dateFmt.format(new Date(e.occurred_at))}</td><td><span class="pill ${e.severity}">${escape(e.severity)}</span></td><td>${escape(e.source)}</td><td>${escape(e.actor)}</td><td class="mono">${escape(e.remote_address)}</td><td>${escape(e.action)}</td><td class="mono" title="${escape(target(e))}">${escape(target(e))}</td><td><span class="result ${e.success===false?'fail':'ok'}">${e.success===false?'Fehler':e.success===true?'Erfolg':'–'}</span></td></tr>`).join("");
}
function openDetails(index) {
  const e=events[index]; if(!e)return; $("detail-title").textContent=e.message;
  const names={occurred_at:"Zeit",host:"Host",source:"Quelle",category:"Kategorie",action:"Aktion",severity:"Priorität",actor:"Benutzer",actor_uid:"UID",session_id:"Sitzung",remote_address:"Remote-Adresse",path:"Pfad",command:"Befehl",process:"Prozess",success:"Ergebnis"};
  $("detail-fields").innerHTML=Object.entries(names).map(([k,n])=>`<dt>${n}</dt><dd>${escape(k==="occurred_at"?dateFmt.format(new Date(e[k])):e[k])}</dd>`).join("");
  $("detail-json").textContent=JSON.stringify(e.metadata,null,2); $("details").showModal();
}
async function load() {
  requestController?.abort(); requestController=new AbortController(); const p=params();
  $("connection-label").textContent="Aktualisiere…"; $("connection-dot").className="status-dot";
  try {
    const [summary,timeline,list]=await Promise.all([api(`/api/summary?${p}`,requestController.signal),api(`/api/timeline?${p}`,requestController.signal),api(`/api/events?${p}`,requestController.signal)]);
    $("metric-total").textContent=fmt.format(summary.stats.total); $("metric-high").textContent=fmt.format(summary.stats.high); $("metric-failed").textContent=fmt.format(summary.stats.failed); $("metric-actors").textContent=fmt.format(summary.stats.actors);
    $("metric-storage").textContent=bytes(summary.storage.total_bytes); $("storage-detail").textContent=`${bytes(summary.storage.data_bytes)} Daten · ${bytes(summary.storage.index_bytes)} Indizes`;
    $("timeline").innerHTML=lineChart(timeline.points); $("source-chart").innerHTML=donut(summary.sources); $("action-bars").innerHTML=bars(summary.actions); $("actor-bars").innerHTML=bars(summary.actors);
    events=list.events; renderEvents(); $("connection-label").textContent="Verbunden"; $("connection-dot").className="status-dot ok"; $("last-refresh").textContent=`Aktualisiert ${new Date().toLocaleTimeString("de-DE")}`;
  } catch (error) { if(error.name==="AbortError")return; $("connection-label").textContent="Verbindung gestört"; $("connection-dot").className="status-dot error"; $("toast").textContent="Daten konnten nicht geladen werden. Neon-Verbindung und Container-Logs prüfen."; $("toast").hidden=false; setTimeout(()=>$("toast").hidden=true,5000); }
}
async function facets() { try { const data=await api("/api/facets"); for(const [id,key] of [["source","sources"],["action","actions"],["actor","actors"]]) for(const value of data[key]) $(id).insertAdjacentHTML("beforeend",`<option value="${escape(value)}">${escape(value)}</option>`); } catch {} }
function schedule(){clearTimeout(timer);timer=setTimeout(load,300)}
for(const id of filters) $(id).addEventListener("change",load); $("search").addEventListener("input",schedule);
$("reset").addEventListener("click",()=>{for(const id of filters)$(id).value=id==="hours"?"24":"";$("search").value="";load()});
$("events-body").addEventListener("click",e=>openDetails(e.target.closest("tr")?.dataset.index)); $("events-body").addEventListener("keydown",e=>{if(e.key==="Enter")openDetails(e.target.closest("tr")?.dataset.index)}); $("close-details").addEventListener("click",()=>$("details").close());
const resetDialog=$("reset-dialog"), resetInput=$("reset-confirmation"), resetSubmit=$("confirm-reset");
$("open-reset").addEventListener("click",()=>{resetInput.value="";resetSubmit.disabled=true;$("reset-error").hidden=true;resetDialog.showModal();resetInput.focus()});
$("cancel-reset").addEventListener("click",()=>resetDialog.close());
resetInput.addEventListener("input",()=>{resetSubmit.disabled=resetInput.value!=="ZURÜCKSETZEN"});
$("reset-form").addEventListener("submit",async event=>{
  event.preventDefault(); if(resetSubmit.disabled)return; resetSubmit.disabled=true; resetSubmit.textContent="Lösche…"; $("reset-error").hidden=true;
  try { const response=await fetch("/api/reset",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirmation:resetInput.value})}); const data=await response.json(); if(!response.ok)throw new Error(data.error||"Löschen fehlgeschlagen"); resetDialog.close(); await load(); }
  catch(error){$("reset-error").textContent=error.message;$("reset-error").hidden=false}
  finally{resetSubmit.textContent="Endgültig löschen";resetSubmit.disabled=resetInput.value!=="ZURÜCKSETZEN"}
});
document.querySelector("thead").addEventListener("click", event => {
  const button = event.target.closest(".sort-button"); if (!button) return;
  const key = button.dataset.sort;
  if (eventSort.key === key) eventSort.direction = eventSort.direction === "asc" ? "desc" : "asc";
  else eventSort = { key, direction: key === "severity" ? "desc" : "asc" };
  renderEvents();
});
await facets(); await load(); setInterval(load,30_000);
