# Cloakbuster

**[cloakbuster.com](https://cloakbuster.com/)** — a free, open-source webpage security scanner. It fetches a URL on the server (with SSRF guards), optionally renders it in **headless Chromium (Playwright)** so JavaScript runs, then analyzes the DOM for cloaked links, hidden injections, suspicious scripts, iframes, redirects, and related signals.

> Heuristic tool only — not antivirus, not a warranty, and not legal advice. Only scan URLs you are allowed to test.

## License

This project is released under the [MIT License](LICENSE).

## Stack

- **Next.js 15** (App Router) + TypeScript + Tailwind CSS
- **Cheerio** for HTML parsing
- **Playwright** (optional) for JS-rendered pages
- **Zod** for API validation

## Requirements

| Component | Version / notes |
|-----------|-----------------|
| **Node.js** | 22.x LTS (20+ may work; CI targets 22) |
| **npm** | 10+ |
| **RAM (Playwright)** | **≥ 2 GB** recommended on the server; 1 GB can work with light traffic |
| **Disk** | ~1 GB for app + `node_modules` + Chromium browser download |

---

## Local development

```bash
git clone https://github.com/marckranat/cloakbuster.git
cd cloakbuster
npm install
npm run playwright:install   # downloads Chromium for Playwright
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

- **Production build:** `npm run build` then `npm run start`
- **Disable Playwright (e.g. CI):** set `PLAYWRIGHT_DISABLE=1` in the environment.

**Repository:** [github.com/marckranat/cloakbuster](https://github.com/marckranat/cloakbuster)

---

## JSON API (quick reference)

- `POST /api/scan` — body: `{ "url": "https://example.com", "renderJs": true }`
- `GET /api/scan?url=https://example.com&renderJs=true`

Rate limit: **5 requests / minute / IP** (in-memory; use Redis or similar for multi-instance production).

---

## Production playbook — DigitalOcean + Ubuntu (virgin server)

Below is a **from-zero** path for a small VPS (e.g. **Ubuntu 24.04 LTS**, **2 GB RAM / 1 vCPU**, any region). Commands assume you SSH in as `root` first, then create a deploy user.

### 1. Create the droplet

1. DigitalOcean → **Create** → **Droplets**
2. **Image:** Ubuntu **24.04 LTS**
3. **Plan:** Basic → Regular Intel/AMD — **2 GB / 1 vCPU** (minimum comfortable for Playwright)
4. **Authentication:** SSH keys (recommended)
5. **Hostname:** e.g. `cloakbuster`
6. Create droplet, note the **public IPv4**

### 2. SSH and base packages

```bash
ssh root@YOUR_DROPLET_IP
apt-get update && apt-get upgrade -y
apt-get install -y ca-certificates curl git ufw
```

### 3. Firewall (UFW)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
ufw status verbose
```

### 4. Non-root deploy user

```bash
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy/
```

Log in as deploy:

```bash
exit
ssh deploy@YOUR_DROPLET_IP
```

### 5. Node.js 22.x (NodeSource)

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs build-essential
node -v   # should show v22.x
npm -v
```

### 6. Clone the app

```bash
cd ~
git clone https://github.com/marckranat/cloakbuster.git cloakbuster
cd cloakbuster
```

### 7. Install dependencies + Playwright browser

```bash
npm ci
# Ubuntu/Debian server: install OS libraries for headless Chromium (avoids
# "error while loading shared libraries: libatk-1.0.so.0" and similar).
sudo npx playwright install-deps chromium
npx playwright install chromium
```

On **macOS** or local dev you can usually skip `install-deps` and run only:

```bash
npx playwright install chromium
```

Or use `npm run playwright:install` (browser only; no system packages).

### 8. Build

```bash
npm run build
```

### 9. systemd service (Next.js on port 3000)

Create `/etc/systemd/system/cloakbuster.service` (as root):

```ini
[Unit]
Description=Cloakbuster (Next.js)
After=network.target

[Service]
Type=simple
User=deploy
Group=deploy
WorkingDirectory=/home/deploy/cloakbuster
Environment=NODE_ENV=production
Environment=PORT=3000
# Optional: skip Playwright on very small boxes
# Environment=PLAYWRIGHT_DISABLE=1
ExecStart=/usr/bin/npm run start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloakbuster
sudo systemctl status cloakbuster
```

Check locally on the server:

```bash
curl -sS -I http://127.0.0.1:3000 | head
```

### 10. DNS (before TLS)

Let’s Encrypt must reach your server on **port 80** for HTTP-01 validation (what `certbot --nginx` uses by default).

In your DNS provider (DigitalOcean Networking, registrar, Cloudflare, etc.), create records pointing at **this droplet’s public IPv4** (use `AAAA` if you have IPv6):

| Name / host | Type | Value |
|-------------|------|--------|
| `@` | **A** | your droplet IPv4 |
| `www` | **A** | same IPv4 |

Wait until lookups match the droplet (propagation often takes minutes, sometimes longer):

```bash
dig +short cloakbuster.com A
dig +short www.cloakbuster.com A
```

### 11. Nginx reverse proxy — HTTPS on 443 with Let’s Encrypt (auto-renewing)

The app listens on **127.0.0.1:3000** only. Nginx terminates **HTTPS on port 443** with a certificate from **Let’s Encrypt** and proxies to Next.js.

#### 11.1 Install Nginx + Certbot (with Nginx integration)

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

Ubuntu’s Certbot packages install **`certbot.service`** plus **`certbot.timer`**, which runs renewal checks **twice daily** (`systemd` timers — no cron file required).

Ensure the renewal timer is **enabled** (usually on by default after install):

```bash
sudo systemctl enable --now certbot.timer
sudo systemctl status certbot.timer
```

Quick dry-run (**does not** change certs; verifies ACME renewal would work):

```bash
sudo certbot renew --dry-run
```

#### 11.2 Initial Nginx site (HTTP only — Certbot will add HTTPS)

Create `/etc/nginx/sites-available/cloakbuster` (adjust `server_name` if you omit `www`):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name cloakbuster.com www.cloakbuster.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Disable the default site (optional but avoids confusion), enable yours, test config, reload:

```bash
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/cloakbuster /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Confirm HTTP responds (before TLS):

```bash
curl -sS -I http://cloakbuster.com | head -n 5
```

#### 11.3 Obtain certificates and switch on HTTPS (:443)

`certbot --nginx` will obtain certificates, merge `listen 443 ssl;` blocks into your config, drop `ssl_certificate` paths under `/etc/letsencrypt/live/…`, and optionally redirect HTTP→HTTPS:

```bash
sudo certbot --nginx -d cloakbuster.com -d www.cloakbuster.com
```

Follow the prompts (email for expiry notices is recommended).

Verify HTTPS is listening and the cert is served:

```bash
sudo ss -tlnp | grep -E ':443|:80'
curl -sS -I https://cloakbuster.com | head -n 8
```

#### 11.4 Auto-renewal (what keeps 443 trusted)

| Mechanism | What it does |
|-----------|----------------|
| **`certbot.timer`** | Runs `certbot renew` on a schedule (typically twice per day). |
| **`certbot renew`** | Only renews certs within ~30 days of expiry; skips otherwise. |

After a successful renewal, **`python3-certbot-nginx`** hooks reload Nginx so new certs are picked up automatically.

Inspect timer schedule and certificates:

```bash
sudo systemctl list-timers '*certbot*'
sudo certbot certificates
```

If you ever renew manually:

```bash
sudo certbot renew
sudo systemctl reload nginx   # usually unnecessary if plugin ran renew
```

---

### 12. Deploy updates

```bash
cd ~/cloakbuster
git pull
npm ci
sudo npx playwright install-deps chromium   # when Playwright/Chromium version changes on Linux
npx playwright install chromium
npm run build
sudo systemctl restart cloakbuster
```

### Why not ZIP / SFTP the whole folder?

GitHub warns when **`node_modules/`** (or **`.next/`**) was accidentally **committed**: one dependency tree can be **20k+ files**. That folder should never be in Git.

**Better workflow:**

| Approach | Notes |
|---------|------|
| **Git + build on the server** (recommended) | Push only source + lockfile. On the droplet: `git pull` → `npm ci` → `npm run playwright:install` → `npm run build`. Matches how §12 works. |
| **`rsync` from your laptop** | OK for emergencies **if you exclude** `node_modules`, `.next`, `.git`: `rsync -avz --exclude node_modules --exclude .next ./ deploy@droplet:~/cloakbuster/` then SSH and run `npm ci` + build there. |
| **ZIP to the server** | Only if you exclude those dirs; still run **`npm ci` on Linux** so native deps match the droplet. Zipping *with* `node_modules` from macOS → Linux often **breaks** (wrong binaries). |
| **Docker / CI** | Build image in GitHub Actions, push to registry, pull on DO — reproducible and no monster folders in Git. |

**If `node_modules` is already tracked in Git**, stop tracking it (files stay on your machine):

```bash
git rm -r --cached node_modules
git rm -r --cached .next 2>/dev/null || true
git add .gitignore
git commit -m "Stop tracking node_modules and build output"
git push
```

If the repo already pushed huge trees to GitHub, you may still need **`git filter-repo`** (or BFG) once to purge history—that’s separate from ignoring going forward.

---

## Docker (alternative)

The included `Dockerfile` uses **Debian bookworm-slim**, installs Playwright’s Chromium dependencies, builds the app, and runs `npm run start`.

```bash
docker build -t cloakbuster .
docker run --rm -p 3000:3000 cloakbuster
```

Put Nginx + TLS in front the same way as above, or use a platform load balancer.

---

## Environment variables

| Variable | Purpose |
|----------|---------|
| `NODE_ENV` | Use `production` on the server |
| `PORT` | Listen port (default **3000** for `next start`) |
| `PLAYWRIGHT_DISABLE` | Set to `1` to force HTTP-only fetch (no Chromium) |
| `HOSTNAME` | Optional; `0.0.0.0` if you bind Next directly (usually Nginx proxies instead) |

---

## Security notes (operating this scanner)

### URL handling (encoded / “funky” input)

- The API accepts a **single string** per scan. Before any network I/O, `assertUrlStringHygiene` rejects **control characters**, **ASCII whitespace**, and **backslashes** (common in parser-differential / SSRF gadgets).
- URLs are parsed **once** with the WHATWG **`URL`** constructor. We **do not** apply extra rounds of manual percent-decoding (that pattern often opens decoding ambiguities). Query/path percent-encoding is decoded only as part of normal URL parsing.
- **Credentials** in the userinfo (`https://user:pass@host/`) are rejected.
- Only **http:** and **https:** are allowed for remote fetches (plus tightly scoped **data:** / **blob:** checks for Playwright subresources). **`javascript:`**, **`file:`**, etc. are blocked.
- **DNS resolution** of the hostname must yield only **public** addresses (private/reserved ranges blocked). Redirect `Location` values are checked the same way.

### Your Cloakbuster deployment vs remote pages

- Outbound fetches use the above filters to reduce **SSRF** risk; no public scanner is **SSRF-proof** against advanced DNS rebinding or novel parser bugs — isolate the app network if the instance is exposed to the internet.
- **Playwright** runs the remote page’s JavaScript **inside headless Chromium on your server**; subresource requests are also filtered. That is required to see DOM injected by JS, but it means you must keep dependencies patched and rate-limit public endpoints.
- **Cheerio** parses HTML in Node **without executing** embedded scripts; findings are returned as JSON. The web UI renders evidence in `<pre>` as **text** (React escapes content — it is not fed into `dangerouslySetInnerHTML`).

### Legal

Only scan sites you own or have **written permission** to test.

---

## Contributing

Issues and pull requests are welcome. Please keep changes focused and match existing code style.
