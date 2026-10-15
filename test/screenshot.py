# Render the popup with a mocked messenger API and sample headers (headless Chrome).
import json, subprocess, sys, threading, http.server, functools, socketserver
from playwright.sync_api import sync_playwright
root = sys.argv[1]; out = sys.argv[2]; which = sys.argv[3] if len(sys.argv) > 3 else "authenticHeaders"
fx = json.loads(subprocess.check_output(["node", "-e",
    "import('./test/fixtures.js').then(m=>console.log(JSON.stringify({h:m[process.argv[1]],z:m.zone})))", which], cwd=root))
msgs = {k: v["message"] for k, v in json.load(open(f"{root}/src/_locales/en/messages.json")).items()}
init = """
const MSGS=%s, HEADERS=%s;
window.browser = window.messenger = {
  i18n:{getMessage:(k,s)=>{let m=MSGS[k]; if(m==null) return ''; (s||[]).forEach((v,i)=>m=m.split('$'+(i+1)).join(v)); return m;}},
  tabs:{query:async()=>[{id:1}]},
  messageDisplay:{getDisplayedMessage:async()=>({id:42})},
  messages:{getFull:async()=>({headers:HEADERS})}
};""" % (json.dumps(msgs), json.dumps(fx["h"]))
TYPES = {"A":1,"AAAA":28,"MX":15,"TXT":16,"PTR":12}
def dns_route(route):
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(route.request.url).query); n = q["name"][0].rstrip(".").lower(); t = q["type"][0]
    ans = [{"name": n, "type": TYPES[t], "data": d} for d in fx["z"].get(f"{t} {n}", [])]
    route.fulfill(status=200, content_type="application/json", headers={"access-control-allow-origin": "*"},
                  body=json.dumps({"Status": 0, "Answer": ans}))
H = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
H.log_message = lambda *a: None
srv = socketserver.TCPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome")
    pg = b.new_page(viewport={"width": 420, "height": 500}, device_scale_factor=2)
    pg.on("console", lambda m: print("console:", m.text))
    pg.add_init_script(init); pg.route("https://dns.google/**", dns_route)
    pg.goto(f"http://127.0.0.1:{port}/src/messagePopup/popup.html")
    pg.wait_for_function("!document.getElementById('verdict').classList.contains('pending')", timeout=10000)
    pg.screenshot(path=out, full_page=True); b.close()
srv.shutdown()
