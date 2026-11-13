# One Sentence

Sign in with Google, write one sentence per day, see everyone's sentences. Node.js + Express + SQLite, no other services.

## Files

- `server.js` – the server: Google login check, sessions, the one-sentence-per-day rule
- `index.html` – the login page and the white dashboard (one file)
- `package.json`, `.env.example`
- `data.db` – created automatically on first run; this is your whole database

## 1. Get a Google client ID (free, ~5 minutes)

1. Go to https://console.cloud.google.com and create a project (any name).
2. Open **APIs & Services > OAuth consent screen**. Choose **External**, fill in the app name and your email, and save. While the app is in "Testing" mode, add the Gmail addresses of your users under **Test users** (up to 100). Click **Publish app** later if you want anyone to be able to sign in.
3. Open **APIs & Services > Credentials > Create credentials > OAuth client ID**.
4. Application type: **Web application**.
5. Under **Authorized JavaScript origins** add:
   - `http://localhost:3000` (for testing)
   - your real address later, e.g. `https://yourdomain.com`
6. Create it and copy the **Client ID**. You don't need the client secret.

## 2. Run it

You need Node.js 20.6 or newer.

```bash
npm install
cp .env.example .env      # then edit .env and paste your GOOGLE_CLIENT_ID
npm start
```

Open http://localhost:3000.

## 3. Put it online

Google sign-in only works on `localhost` or on an **https** address. Options:

- **A small VPS** (DigitalOcean, Hetzner, etc.): copy the folder, run `npm install`, keep it alive with `pm2 start server.js` (or a systemd service), and put **Caddy** or **nginx** in front for free https certificates. Set `NODE_ENV=production` in `.env`.
- **A computer at home**: run the server and use a **Cloudflare Tunnel** to give it an https address.

Remember to add the final https address to **Authorized JavaScript origins** in Google Cloud.

## How the rules work

- **One sentence per day** is enforced by the database (`UNIQUE (user_id, day)`), so double clicks or tampering can't create a second entry.
- **"Today"** is decided by the server using `TIMEZONE` (default India time), not the visitor's clock.
- Sentences are limited to 200 characters, with line breaks and extra spaces cleaned up. They can't be edited or deleted after posting.
- Everyone signed in sees everyone's sentences. Use the arrows to browse earlier days.
- To limit who can join, put emails in `ALLOWED_EMAILS` in `.env`.

## Backups

Copy `data.db` (and any `data.db-wal` file next to it) now and then, or stop the server and copy just `data.db`.
