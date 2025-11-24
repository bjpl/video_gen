# 🔧 Server Restart Instructions

## The Issue
Template syntax error has been FIXED. You just need to restart the server with a fresh cache.

---

## ✅ Solution (3 Steps)

### Step 1: Stop Current Server
In your terminal where uvicorn is running, press:
```
Ctrl + C
```

### Step 2: Clear Python Cache
```bash
cd /mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen

# Clear cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
```

### Step 3: Restart Server
```bash
cd app
python -m uvicorn main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
✅ Video generation system ready!
```

### Step 4: Test in Browser
```
http://127.0.0.1:8000/create
```

Then **HARD REFRESH**:
- Windows/Linux: `Ctrl + Shift + R`
- Mac: `Cmd + Shift + R`

---

## What Was Fixed

The template error was caused by invalid Jinja2 syntax in the comments of `validation-feedback.html`:

**Before (broken)**:
```jinja
{% include 'components/validation-feedback.html' with type='youtube' %}
```

**After (fixed)**:
```jinja
{% include 'components/validation-feedback.html' %}
```

Jinja2 doesn't support the `with` keyword like Django templates do.

---

## Expected Result

After restarting, you should see all new components:

### Step 1 - Input
- ✅ **Drag-drop file upload zone** (when you select "File")
- ✅ **Real-time YouTube validation** (when you select "URL")

### Step 2 - Configure
- ✅ **Multi-language selector** with search
- ✅ **Multi-voice selector** with audio preview

### Step 3 - Review
- ✅ **Preview panel** showing document structure

### Step 4 - Generate
- ✅ **Progress indicator** with 7 stages

---

## If It Still Doesn't Work

1. **Check server logs** for any errors during startup
2. **Test template directly**:
   ```bash
   cd /mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen
   python3 -c "
   import jinja2
   env = jinja2.Environment(loader=jinja2.FileSystemLoader('app/templates'))
   template = env.get_template('create-unified.html')
   result = template.render(request={'url': 'http://test'})
   print('✅ Template OK')
   "
   ```
3. **Try incognito mode** in browser
4. **Check browser console** (F12) for JavaScript errors

---

## Verification Checklist

After restart, verify:
- [ ] Server starts without errors
- [ ] Page loads (no 500 error)
- [ ] All JavaScript files load (200 OK in network tab)
- [ ] Components are visible in the UI
- [ ] Browser console has no red errors

---

**Status**: Template fixed, ready to restart server
**Next**: Follow steps above to restart
