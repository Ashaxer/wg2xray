# WireGuard ⇄ Xray Converter

A tiny, dependency-free static web page that converts a **WireGuard `.conf`** into an
**Xray `wireguard` outbound JSON** — and back.

- 🌑 Dark / green UI
- 🧠 Two big text boxes, two buttons between them
- 🔒 100% client-side: your private keys never leave the browser
- 📦 No build step, no npm, no framework — three static files

---

## Live demo

Once GitHub Pages is enabled (see below):

```
https://<your-username>.github.io/<your-repo>/
```

---

## Project structure

```
.
├── index.html      # markup + UI
├── style.css       # dark/green theme
├── script.js       # all parsing & conversion logic
└── README.md
```

That's it. No build, no bundler, no dependencies.

---

## How to use

1. Open the page.
2. Paste a WireGuard config into the **Source** box.
3. Click **WireGuard → Xray**.
4. Copy the JSON from the **Result** box.
5. To go the other way: paste an Xray outbound JSON and click **Xray → WireGuard**.

The converter is also forgiving — if you paste JSON but click *WireGuard → Xray*,
it detects the mismatch and converts in the correct direction anyway (with a note).

### Options (top-right)

| Option | Effect |
| --- | --- |
| **Outbound tag** | Sets `"tag"` in the resulting outbound (default `wireguard-outbound`). |
| **streamSettings + mux** | Adds `"streamSettings": { "network": "raw" }` and `"mux": { "enabled": false }`. |
| **wrap in `outbounds`** | Emits `{ "outbounds": [ … ] }` instead of a bare outbound object, so you can paste it straight into a full Xray config. |

### Keyboard

- `Ctrl` / `Cmd` + `Enter` in the source box → WireGuard → Xray

---

## Conversion mapping

### WireGuard → Xray

| WireGuard | Xray (`settings`) |
| --- | --- |
| `[Interface] PrivateKey` | `secretKey` |
| `[Interface] Address` | `address[]` (comma separated, `/32` & `/128` auto-added) |
| `[Interface] MTU` | `mtu` (defaults to `1280` if absent) |
| `[Interface] Reserved` | `reserved` (WARP, kept as `[a, b, c]`) |
| `[Peer] PublicKey` | `peers[].publicKey` |
| `[Peer] PresharedKey` | `peers[].preSharedKey` |
| `[Peer] Endpoint` | `peers[].endpoint` |
| `[Peer] AllowedIPs` | `peers[].allowedIPs[]` |
| `[Peer] PersistentKeepalive` | `peers[].keepAlive` |

### Xray → WireGuard

The same table, reversed, plus `Table = off` is written into `[Interface]`.

### Fields that can't cross over

| Field | Why |
| --- | --- |
| `DNS` | Xray WireGuard outbounds have no DNS field — use a `dns` block or routing rule. |
| `Table` | wg-quick routing only. |
| `ListenPort` | Not supported by the Xray WireGuard outbound. |
| `PreUp` / `PostUp` / `PreDown` / `PostDown` | Shell hooks, no equivalent. |
| `domainStrategy`, `reserved` | Xray-only; not representable in a `.conf`. |

The UI prints these as **Notes** under the result instead of silently dropping them.

---

## Example

**Input** (`wg0.conf`)

```ini
[Interface]
PrivateKey = *****
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1, 2a07:b944::2:1
Table = off

[Peer]
PublicKey = 8jEgre7McUnWFLvjlQSenvYJgUGISWeNyLonrEupuDA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 146.70.230.114:51820
PersistentKeepalive = 25
```

**Output**

```json
{
  "tag": "wireguard-outbound",
  "protocol": "wireguard",
  "settings": {
    "address": [
      "10.2.0.2/32",
      "2a07:b944::2:2/128"
    ],
    "mtu": 1280,
    "peers": [
      {
        "publicKey": "8jEgre7McUnWFLvjlQSenvYJgUGISWeNyLonrEupuDA=",
        "endpoint": "146.70.230.114:51820",
        "allowedIPs": ["0.0.0.0/0", "::/0"],
        "keepAlive": 25
      }
    ],
    "secretKey": "*****"
  },
  "streamSettings": { "network": "raw" },
  "mux": { "enabled": false }
}
```

---

## Security

Everything runs in the browser. There is no backend, no analytics, no fetch call.
Your `PrivateKey` / `secretKey` is only ever held in the textarea of your own tab.

Still: **don't paste real keys into a page you don't control.** Self-host it (below).

---

## Deployment guide (GitHub Pages, step by step)

### 1. Create the repository

**Option A — web UI**

1. Go to <https://github.com/new>
2. **Repository name:** `wg-xray-converter` (or anything you like)
3. **Visibility:** Public *(required for free GitHub Pages)*
4. Do **not** initialise with a README (you already have one)
5. Click **Create repository**

**Option B — CLI**

```bash
gh repo create wg-xray-converter --public --description "WireGuard ⇄ Xray converter"
```

### 2. Add the files

Create a folder and drop the four files in it:

```bash
mkdir wg-xray-converter && cd wg-xray-converter
# create index.html, style.css, script.js, README.md here
```

Then push:

```bash
git init
git add index.html style.css script.js README.md
git commit -m "feat: WireGuard <-> Xray converter"
git branch -M main
git remote add origin https://github.com/<your-username>/wg-xray-converter.git
git push -u origin main
```

<details>
<summary>Uploading via the GitHub web UI instead</summary>

1. Open your new repo
2. **Add file → Upload files**
3. Drag in `index.html`, `style.css`, `script.js`, `README.md`
4. Commit message → **Commit changes**

</details>

> ⚠️ **Important:** `index.html` must sit at the **repository root**, not in a
> subfolder, unless you configure Pages to serve that folder.

### 3. Test it locally first

Because there's no build step you can just open `index.html` — but a local
server is cleaner (clipboard API needs `http://localhost` or HTTPS):

```bash
# Python 3
python3 -m http.server 8080
# then open http://localhost:8080
```

or

```bash
npx serve .
```

### 4. Enable GitHub Pages

1. Open your repo → **Settings** (top bar)
2. Left sidebar → **Pages**
3. Under **Build and deployment → Source**, choose **Deploy from a branch**
4. **Branch:** `main`  •  **Folder:** `/ (root)`
5. Click **Save**
6. Wait ~30–60 seconds for the first build (watch the **Actions** tab if you're curious)

### 5. Your page address

GitHub will show it at the top of the Pages settings:

```
https://<your-username>.github.io/<your-repo>/
```

For example `https://octocat.github.io/wg-xray-converter/`.

That's the link you share. It's HTTPS, so the clipboard button works.

### 6. (Optional) Custom domain

1. Buy/own a domain, e.g. `wg.example.com`
2. In your DNS provider add a `CNAME` record:
   `wg` → `<your-username>.github.io`
3. Repo → **Settings → Pages → Custom domain** → enter `wg.example.com` → **Save**
4. Tick **Enforce HTTPS** once the certificate is issued (can take a few minutes)
5. Optional: add a `CNAME` file at the repo root containing just `wg.example.com`

### 7. Updating the site later

```bash
git add -A
git commit -m "update converter"
git push
```

Pages redeploys automatically within a minute or so.

---

## License

MIT — do whatever you want.

## Disclaimer

Provided as-is. Always review generated configs before using them on a real
network, and never commit real private keys to a public repository.
