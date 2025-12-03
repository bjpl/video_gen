# Rate Limiting Installation Guide

## Quick Start

The rate limiting feature requires the `slowapi` package. Install it in your project's virtual environment:

### Option 1: Install from requirements.txt (Recommended)
```bash
# Activate your virtual environment first
pip install -r requirements.txt
```

### Option 2: Install slowapi directly
```bash
# Activate your virtual environment first
pip install slowapi>=0.1.9
```

## Verification

Test that the module loads correctly:

```bash
python3 -c "from app.middleware.rate_limiting import limiter, UPLOAD_LIMIT; print('✅ Rate limiting ready')"
```

Expected output:
```
✅ Rate limiting ready
```

## Development Setup

If you don't have a virtual environment yet:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# OR
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Testing the Implementation

1. **Start the server:**
```bash
python app/start_test_server.py
```

2. **Test rate limiting manually:**
```bash
# Send multiple requests quickly
for i in {1..15}; do
  curl -X POST http://localhost:8000/api/parse/document \
    -H "Content-Type: application/json" \
    -d '{"content":"test.md"}' \
    -w "\nStatus: %{http_code}\n"
  sleep 1
done
```

3. **Run automated tests:**
```bash
pytest tests/test_rate_limiting.py -v
```

## Configuration

Create or update `.env` file:

```bash
# Enable rate limiting
RATE_LIMIT_ENABLED=true

# Configure limits (optional - defaults are production-ready)
RATE_LIMIT_DEFAULT="100/minute"
RATE_LIMIT_UPLOAD="5/minute"
RATE_LIMIT_GENERATE="3/minute"
RATE_LIMIT_PARSE="10/minute"
RATE_LIMIT_TASKS="60/minute"
RATE_LIMIT_HEALTH="1000/minute"
```

## Troubleshooting

### Issue: ModuleNotFoundError: No module named 'slowapi'
**Solution:** Install slowapi in your virtual environment

```bash
# Make sure virtual environment is activated
pip install slowapi
```

### Issue: Rate limiting not working
**Solution:** Check if it's disabled in environment

```bash
# Check environment variable
echo $RATE_LIMIT_ENABLED

# Should output: true
```

### Issue: Limits too strict for development
**Solution:** Increase limits or disable temporarily

```bash
# Option 1: Increase limits
export RATE_LIMIT_GENERATE="100/minute"
export RATE_LIMIT_UPLOAD="50/minute"

# Option 2: Disable (development only!)
export RATE_LIMIT_ENABLED=false
```

## Production Deployment

For production deployments with multiple servers, use Redis:

```python
# In app/middleware/rate_limiting.py
limiter = Limiter(
    key_func=get_rate_limit_key,
    storage_uri="redis://localhost:6379"
)
```

Then install Redis support:
```bash
pip install redis
```

## Next Steps

Once installed and verified:
1. Review `docs/RATE_LIMITING.md` for full documentation
2. Adjust limits in `.env` based on your needs
3. Monitor rate limit hits in application logs
4. Consider Redis for production multi-server setup

## Quick Test Script

Save as `test_rate_limit.sh`:

```bash
#!/bin/bash
echo "Testing rate limiting..."

for i in {1..12}; do
  echo "Request $i:"
  curl -s -X POST http://localhost:8000/api/parse/document \
    -H "Content-Type: application/json" \
    -d '{"content":"test.md"}' | jq -r '.task_id // .error'
  sleep 0.5
done

echo "✅ Test complete. Check for '429 Too Many Requests' above."
```

Run it:
```bash
chmod +x test_rate_limit.sh
./test_rate_limit.sh
```

Expected: First ~10 requests succeed, then rate limiting kicks in.
