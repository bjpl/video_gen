# 🚀 Quick Railway Deployment - video_gen

**Time:** ~5 minutes
**Cost:** FREE (for your use case)

---

## Step 1: Install Railway CLI

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway (opens browser)
railway login

# Link your project
cd /mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen
railway init
```

---

## Step 2: Set Environment Variables

```bash
# Set your API key
railway variables set ANTHROPIC_API_KEY="your-actual-api-key-here"

# Set environment
railway variables set ENVIRONMENT="production"

# Optional: Set other variables
railway variables set PORT="8000"
```

---

## Step 3: Deploy

```bash
# Deploy to Railway (one command!)
railway up

# Get your deployment URL
railway domain
```

**That's it!** Your app is live at `https://your-app.up.railway.app`

---

## 🔄 Future Updates (Auto-Deploy)

Every time you push to GitHub, Railway auto-deploys:

```bash
git add .
git commit -m "feat: new feature"
git push origin main
# Railway automatically deploys! 🎉
```

---

## 📊 Monitor Your App

```bash
# View logs
railway logs

# Check status
railway status

# Open in browser
railway open
```

---

## 🔧 Configuration Files Needed

### 1. Create `railway.json` (optional but recommended)

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "uvicorn app.main:app --host 0.0.0.0 --port $PORT",
    "healthcheckPath": "/",
    "healthcheckTimeout": 100,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

### 2. Create `nixpacks.toml` (tells Railway how to build)

```toml
[phases.setup]
nixPkgs = ["python39", "nodejs-18_x"]

[phases.install]
cmds = ["pip install -r requirements.txt"]

[phases.build]
cmds = ["echo 'Build complete'"]

[start]
cmd = "uvicorn app.main:app --host 0.0.0.0 --port $PORT"
```

### 3. Update `requirements.txt` (if not already present)

Make sure you have all dependencies listed:
```
fastapi
uvicorn[standard]
jinja2
anthropic
edge-tts
# ... all other dependencies
```

---

## 🎯 Evolution Path: Personal → Multi-User

### Phase 1: NOW (Personal Use)
```python
# app/config.py
import os

# Your personal API key from environment
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
```

### Phase 2: LATER (Multi-User)
```python
# app/config.py
import os

# Default key for demos
DEFAULT_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# User-provided keys (from database)
def get_user_api_key(user_id: str) -> str:
    # Fetch from database
    key = db.get_user_key(user_id)
    return key or DEFAULT_API_KEY
```

**When you're ready for multi-user:**
1. Add PostgreSQL database (one click in Railway)
2. Add user authentication
3. Add API key input field in UI
4. Store encrypted user keys in database
5. Use user's key instead of your key

---

## 💰 Cost Breakdown

**Current (Personal Use):**
- Railway: **FREE** (up to $5/month included)
- Your use will likely stay under $5/month

**Future (Multi-User):**
- Railway Hobby Plan: **$5/month** (includes database)
- Users pay for their own Claude API usage
- You just pay for hosting (~$5-10/month)

---

## 🔒 Security: Environment Variables

**Your API key is secure:**
- Never committed to git
- Stored in Railway's encrypted environment
- Not exposed to users
- Not visible in logs

**View/edit variables:**
```bash
railway variables list
railway variables set KEY="value"
railway variables delete KEY
```

---

## 🚨 Troubleshooting

**App won't start:**
```bash
# Check logs
railway logs

# Common issues:
# 1. Missing environment variable
railway variables set ANTHROPIC_API_KEY="your-key"

# 2. Wrong start command
# Update railway.json startCommand

# 3. Port binding issue
# Railway sets $PORT automatically, use it
```

**Update deployment:**
```bash
# Redeploy
railway up --detach

# Force redeploy
railway redeploy
```

---

## ✅ Post-Deployment Checklist

After deploying, verify:
- [ ] App loads at Railway URL
- [ ] Can create a video (test with simple input)
- [ ] Validation works (try invalid URL)
- [ ] Cost estimator updates
- [ ] Preset packages apply correctly
- [ ] Translation works (if using multilingual)
- [ ] No console errors

**Test URL:** `https://your-app.up.railway.app/create`

---

## 🎉 Success!

You now have:
- ✅ Production app running 24/7
- ✅ Your API key securely stored
- ✅ Auto-deploys on git push
- ✅ Professional URL to share
- ✅ Ready to scale to multi-user later

**Access your app:** Run `railway open`

---

**Need help?** Railway docs: https://docs.railway.app
