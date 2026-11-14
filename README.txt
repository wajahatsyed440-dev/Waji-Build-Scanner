WAJI BUILD SCANNER — CLOUD / PHONE EDITION
=========================================
Works while the PC and desktop app are turned off IF the cloud host is running.
The phone does not run scans: your cloud host runs them and sends ntfy alerts.

1) HOSTING — An always-on Python/Docker host is required. For example, create a
   private GitHub repository and deploy the Waji_Build_Scanner_Cloud folder as a
   Docker service on a host such as Railway or another Docker host. Hosting may
   cost money; free/sleeping tiers do NOT guarantee continuous operation.
   Deploy the CLOUD FOLDER as the service root, not the original desktop folder.
2) Add these environment variables in the hosting dashboard (NOT in public code):
   API_KEY              Your authorised API key if /api/builds requires it
   API_PATHS            /api/builds,/api/old_build (edit if authorised)
   NTFY_TOPIC           Long random private topic, 12-120 letters/numbers/_/-
   DASHBOARD_PASSWORD   A strong password at least 12 characters
   SCAN_INTERVAL        60 (seconds; minimum 30, check API limits)
   PUBLIC_URL           Your deployed HTTPS domain, e.g. https://example.up.railway.app
   DATA_DIR             /data
3) Expose the HTTP service on its PORT; the host normally assigns PORT for you.
   Use HTTPS on the public domain. The full-view site requires browser login:
   username: waji      password: value of DASHBOARD_PASSWORD
4) IMPORTANT: Attach a PERSISTENT VOLUME mounted at /data. Without this, the
   baseline, full history and notifications can reset on redeployment/restart,
   potentially causing missed or duplicate detection. Make sure the volume is
   usable by the container. Keep one active cloud instance only.
5) Install ntfy on your iPhone or Android; subscribe to the same NTFY_TOPIC.
   Allow notifications. Your first scan establishes a baseline (no false "new").
   Subsequent changes send a phone alert. Tap the alert to open Full View when
   PUBLIC_URL is set to the correct HTTPS address. Sign in with the dashboard
   credentials on the phone browser.
6) Open the deployed HTTPS domain in your phone browser to see the mobile-friendly
   full API response and every new/removed/changed record. /events.json returns
   saved detections; /latest.json returns current snapshots (both require login).

IMPORTANT LIMITATIONS
- Your PC CAN be off; your CLOUD SERVER must remain on and connected.
- The cloud host and API endpoint must both be available. A 60 second scan interval
  cannot guarantee seeing changes which appear and disappear between scans.
- This scanner checks only configured, authorised, read-only API paths. It does
  not scan the entire internet or discover hidden information.
- Public ntfy.sh topics are not private/authenticated. Anyone knowing the topic
  can receive messages. Alerts contain field names, path and change type, never
  raw API values or API credentials. Do not use sensitive field identifiers.
- The full API JSON is only displayed in the password-protected HTTPS web page.
- Do not put your API key, dashboard password or private topic in screenshots,
  public GitHub repositories, or shared files.
- If the host charges for always-on service or persistent storage, check costs
  first. A free service that sleeps cannot provide truly continuous monitoring.
- iOS/Android push delivery timing depends on ntfy, the OS and connectivity.
- Never run this cloud monitor alongside the desktop monitor on the same topic
  if you want to avoid duplicate notifications.

LOCAL TEST (Windows with Python 3.9+)
  Edit env vars in a private PowerShell shell and then run python cloud_server.py
  Open http://localhost:8080 (LOCAL TEST ONLY, not safe over public plain HTTP).
  Production must use HTTPS.

No Python third-party packages needed for this cloud server.
