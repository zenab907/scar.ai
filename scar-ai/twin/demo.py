"""Digital-twin demo: simulate a drone mission -> analyze -> build twin -> write twin_demo.html (open in a browser).
    python twin/demo.py
Mohamed Wahid can reuse the JSON shape (assets / readings / heatmap) directly in the React dashboard."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "ai_service"
sys.path.insert(0, str(ROOT))

from app import synthetic, twin                          # noqa: E402
from app.baseline import get_baseline                    # noqa: E402
from app.main import analyze                             # noqa: E402
from app.schemas import AnalyzeRequest, Event            # noqa: E402

events = synthetic.generate_events(seed=11)
risk = {}
for e in events:
    out = analyze(AnalyzeRequest(event=Event(**e)))
    risk[e["bssid"]] = max(risk.get(e["bssid"], 0), out.final.risk_score)

zone = {"zone_id": "zone-demo", "name": "Demo campus", "origin_lat": synthetic.ORIGIN[0],
        "origin_lon": synthetic.ORIGIN[1], "width_m": synthetic.SITE_W, "height_m": synthetic.SITE_H}
data = twin.build_twin(zone, events, get_baseline(None), risk_by_bssid=risk, cell_m=10)
(Path(__file__).parent / "twin_sample.json").write_text(json.dumps(data, indent=1))

HTML = """<!doctype html><meta charset="utf-8"><title>SCAR Digital Twin (demo)</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<body style="font-family:system-ui;margin:16px"><h3>SCAR Digital Twin - %(name)s</h3>
<div id="m" style="width:100%%;max-width:1000px;height:640px"></div>
<p>Heatmap = mean RSSI (dBm) seen by the drone. Markers = estimated AP position (weighted centroid). Green = authorized, red = not in baseline.</p>
<script>
const D = %(data)s;
const h = D.heatmap, xs = h.x_edges.slice(0,-1).map(v=>v+h.cell_m/2), ys = h.y_edges.slice(0,-1).map(v=>v+h.cell_m/2);
const heat = {type:'heatmap', x:xs, y:ys, z:h.mean_rssi, colorscale:'Viridis', colorbar:{title:'RSSI dBm'}, hoverongaps:false};
const pts = {type:'scatter', mode:'markers+text', x:D.assets.map(a=>a.x), y:D.assets.map(a=>a.y),
  text:D.assets.map(a=>(a.ssid||'(hidden)')), textposition:'top center',
  marker:{size:D.assets.map(a=>12+a.current_risk_score/6), color:D.assets.map(a=>a.authorized===false?'#e53935':'#43a047'), line:{color:'white',width:2}},
  customdata:D.assets.map(a=>[a.bssid,a.encryption,a.current_risk_score]),
  hovertemplate:'%%{text}<br>%%{customdata[0]}<br>%%{customdata[1]} | risk %%{customdata[2]}<extra></extra>'};
Plotly.newPlot('m',[heat,pts],{xaxis:{title:'x (m)'},yaxis:{title:'y (m)',scaleanchor:'x'},margin:{t:20}});
</script>"""
(Path(__file__).parent / "twin_demo.html").write_text(HTML % {"name": zone["name"], "data": json.dumps(data)})
print("assets:", [(a["ssid"], a["bssid"][-5:], a["authorized"], a["current_risk_score"]) for a in data["assets"]])
print("wrote twin/twin_demo.html and twin/twin_sample.json")
