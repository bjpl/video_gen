#!/bin/bash

# 🚀 Railway Deployment Script for video_gen
# Usage: ./deploy_railway.sh

set -e  # Exit on error

echo "🚀 Railway Deployment Script"
echo "=============================="
echo ""

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Installing..."
    npm install -g @railway/cli
    echo "✅ Railway CLI installed"
else
    echo "✅ Railway CLI found"
fi

echo ""
echo "📝 Please enter your Anthropic API key:"
read -s ANTHROPIC_API_KEY
echo ""

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ API key cannot be empty"
    exit 1
fi

echo "🔐 API key set (hidden for security)"
echo ""

# Login to Railway (if not already logged in)
echo "🔑 Logging into Railway..."
railway login || {
    echo "❌ Railway login failed"
    exit 1
}

echo "✅ Logged in to Railway"
echo ""

# Initialize project (if not already initialized)
if [ ! -f ".railway" ]; then
    echo "🎬 Initializing Railway project..."
    railway init
    echo "✅ Railway project initialized"
else
    echo "✅ Railway project already initialized"
fi

echo ""

# Set environment variables
echo "⚙️  Setting environment variables..."
railway variables set ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
railway variables set ENVIRONMENT="production"
railway variables set PORT="8000"

echo "✅ Environment variables set"
echo ""

# Deploy
echo "🚀 Deploying to Railway..."
railway up --detach

echo ""
echo "✅ Deployment started!"
echo ""
echo "📊 To monitor deployment:"
echo "  railway logs"
echo ""
echo "🌐 To get your URL:"
echo "  railway domain"
echo ""
echo "🎉 To open in browser:"
echo "  railway open"
echo ""
echo "=============================="
echo "✅ Deployment complete!"
