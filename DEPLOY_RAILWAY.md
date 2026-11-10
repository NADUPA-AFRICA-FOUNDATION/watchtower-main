# Deploy to Railway

Your FraudGuard AI application is now ready for Railway deployment!

## 🚀 Quick Deploy Steps

### Option 1: One-Click Deploy (Easiest)
1. Click this button: [Deploy on Railway](https://railway.app/template/new)
2. Connect your GitHub repository
3. Railway will auto-detect the `railway.json` and deploy automatically

### Option 2: Manual Deploy via CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project (if not already done)
railway init

# Deploy
railway up
```

## ⚙️ Configuration

`railway.json` builds from the repo's `Dockerfile`, not Nixpacks. Nixpacks picks
a single language and checks Node before Python, so the root `package.json`
(Playwright, used only by tests) made it build a Node image with no Python, and
the start command failed with `uvicorn: command not found`.

- **Builder**: `DOCKERFILE` (Python 3.11, `requirements.txt`)
- **Start**: the Dockerfile's `CMD`, which binds the `$PORT` Railway assigns
- **Health check**: `/api/healthz`, which answers without credentials
- **Restarts**: on failure, at most 10 retries

## 🔧 Environment Variables

Set these in Railway Dashboard → Variables:

- `WATCHTOWER_PASSWORD` (**required**): the app detects Railway and fails closed.
  Without a password every page returns 503 (the health check still passes, so
  the deploy reads as healthy). Log in as `watchtower`, or set `WATCHTOWER_USER`.
- `GEMINI_API_KEY` or `ANTHROPIC_API_KEY`: model scoring. Without one, sweeps use
  keyword ranking.
- `OPENSANCTIONS_API_KEY`: optional. Without it that source shows as "off".
- `WATCHTOWER_DATA_DIR`: point it at a mounted Railway volume, or the archive and
  the review queue are lost on every redeploy.

## 🌐 After Deployment

1. Railway will provide you with a public URL (e.g., `https://your-app.railway.app`)
2. Share this URL to access the UI from anywhere
3. The OSINT sweep and URL scanner will work globally

## 📊 Monitoring

- View logs in Railway Dashboard
- Monitor resource usage (CPU, Memory, Network)
- Set up alerts for failures or high resource usage

## 💡 Tips

- **Free Tier**: Railway offers $5/month free credit (enough for light usage)
- **Scaling**: Upgrade plan if you need more concurrent searches
- **Database**: SQLite works fine for small-medium usage; consider PostgreSQL for production scale
- **Rate Limits**: Be mindful of DuckDuckGo/API rate limits with heavy usage

## 🔒 Security Notes

- Add a simple auth layer if exposing publicly (optional)
- Monitor for abuse of the scanning endpoints
- Keep dependencies updated regularly

---

**Ready to deploy?** Just push your code to GitHub and connect it to Railway!
