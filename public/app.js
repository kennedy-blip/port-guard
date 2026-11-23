(() => {
  const $ = (id) => document.getElementById(id);
  const fallbackProfiles = [
    {id:"web-tls",name:"Web & TLS Edge",host:"example.com",ports:[80,443,8443],timeoutMs:1200,description:"Standard web and encrypted web entry points."},
    {id:"data",name:"Database & Cache Check",host:"example.com",ports:[5432,6379,3306,27017],timeoutMs:1000,description:"Sensitive data services."},
    {id:"dev",name:"Dev & App Ports",host:"example.com",ports:[3000,5173,8000,8080],timeoutMs:1000,description:"Development servers and app consoles."}
  ];
  const fallbackResults = [
    {port:80,service:"HTTP",status:"OPEN",risk:"SAFE_PUBLIC",connectMs:18.4,note:"Demo data only — connect the Go API to run a real scan."},
    {port:443,service:"HTTPS",status:"OPEN",risk:"SAFE_PUBLIC",connectMs:21.7,note:"Demo data only — connect the Go API to run a real scan."},
    {port:5432,service:"PostgreSQL",status:"CLOSED",risk:"EXPOSED_DATA_PORT",connectMs:1000,note:"Demo data only — connect the Go API to run a real scan."},
    {port:3000,service:"Development",status:"TIMEOUT",risk:"UNREACHABLE",connectMs:1000,note:"Demo data only — connect the Go API to run a real scan."}
  ];
  let profiles = fallbackProfiles;
  const toast = (message) => { $("toast").textContent=message; $("toast").classList.add("show"); setTimeout(()=>$("toast").classList.remove("show"),2600); };
  async function api(path, options) {
    const response = await fetch(path, {headers:{"Content-Type":"application/json"},...options});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  }
  function renderProfiles() {
    $("profileList").innerHTML = profiles.map(p => `<article class="profile-card"><h3>${escapeHTML(p.name)}</h3><p>${escapeHTML(p.description || p.host)}<br><span class="mono">${p.ports.join(", ")}</span></p><button data-profile="${escapeHTML(p.id)}">LOAD PROFILE →</button></article>`).join("");
    document.querySelectorAll("[data-profile]").forEach(btn=>btn.addEventListener("click",()=>{const p=profiles.find(x=>x.id===btn.dataset.profile);if(!p)return;$("host").value=p.host;$("ports").value=p.ports.join(",");$("timeout").value=p.timeoutMs;toast("Profile loaded");}));
  }
  function escapeHTML(value) { return String(value).replace(/[&<>"']/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
  function renderResults(results) {
    $("emptyState").hidden=true;
    $("resultsGrid").innerHTML=results.map(r=>`<article class="result-card"><div class="result-top"><span class="port">:${r.port}</span><span class="badge ${r.status.toLowerCase()}">${r.status}</span></div><div class="service">${escapeHTML(r.service)}</div><span class="risk ${r.risk}">${r.risk}</span><span class="latency">${Number(r.connectMs).toFixed(1)} ms</span>${r.banner?`<div class="banner">${escapeHTML(r.banner)}</div>`:""}<p class="note">${escapeHTML(r.note || "")}</p></article>`).join("");
  }
  function renderSummary(counts, alerts) { $("openCount").textContent=counts.OPEN||0;$("closedCount").textContent=(counts.CLOSED||0)+(counts.TIMEOUT||0);$("alertCount").textContent=alerts||0; }
  async function loadProfiles() { try { const data=await api("/api/profiles");profiles=data.profiles||fallbackProfiles; } catch (_) { profiles=fallbackProfiles; } renderProfiles(); }
  $("scanForm").addEventListener("submit",async e=>{
    e.preventDefault();
    if (!$("authorized").checked) { toast("Confirm authorization before scanning."); return; }
    const ports=$("ports").value.split(",").map(v=>Number(v.trim()));
    if (!ports.length || ports.some(p=>!Number.isInteger(p)||p<1||p>65535) || new Set(ports).size!==ports.length || ports.length>32) { toast("Enter 1–32 unique valid ports."); return; }
    const button=$("scanButton");button.disabled=true;button.textContent="Scanning…";$("engineState").textContent="SCANNING";
    try {
      const data=await api("/api/scan",{method:"POST",body:JSON.stringify({host:$("host").value.trim(),ports,timeoutMs:Number($("timeout").value),authorized:true})});
      renderResults(data.results);renderSummary(data.counts,data.riskAlerts);$("scanMeta").textContent=`${data.results.length} PORTS · ${data.resolvedIP}`;toast("Scan completed");
    } catch (err) {
      if (location.protocol==="file:") { renderResults(fallbackResults);renderSummary({OPEN:2,CLOSED:1,TIMEOUT:1},0);toast("Offline demo results — not a live scan"); }
      else toast(err.message);
    } finally { button.disabled=false;button.innerHTML="<span>▶</span> Run concurrent scan";$("engineState").textContent="READY"; }
  });
  $("portChips").addEventListener("click",e=>{const b=e.target.closest("[data-port]");if(!b)return;const list=$("ports").value.split(",").map(x=>x.trim()).filter(Boolean);const p=b.dataset.port;if(!list.includes(p))list.push(p);$("ports").value=list.join(",");});
  $("riskyPreset").addEventListener("click",()=>{$("ports").value="3306,5432,6379,27017";toast("Data service ports loaded — scan only authorized targets.");});
  $("profileForm").addEventListener("submit",async e=>{e.preventDefault();const p={name:$("profileName").value.trim(),host:$("profileHost").value.trim(),ports:$("profilePorts").value.split(",").map(x=>Number(x.trim())),timeoutMs:1000};try{const data=await api("/api/profiles",{method:"POST",body:JSON.stringify(p)});profiles.push(data.profile);renderProfiles();e.target.reset();toast("Profile saved in this server instance");}catch(err){toast(err.message+" (profiles are in-memory on the hosted server)");}});
  loadProfiles();
  if (location.protocol==="file:") { $("engineState").textContent="DEMO MODE";renderResults(fallbackResults);renderSummary({OPEN:2,CLOSED:1,TIMEOUT:1},0);$("scanMeta").textContent="OFFLINE SAMPLE"; }
})();
