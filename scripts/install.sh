#!/usr/bin/env bash
# ==============================================================================
# KeyShield AI - Master Installation & Verification Script
# Follows: CHECK -> UNDERSTAND -> INSTALL -> VERIFY workflow.
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🛡️ KeyShield AI Platform Installation & Setup"
echo "=========================================================="

# 1. CHECK ENVIRONMENT
echo "🔍 [1/4] CHECK: Verifying system prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi
echo "   - Python version: $(python3 --version)"

if ! command -v node &> /dev/null; then
    echo "⚠️ Node.js is not found. Frontend dashboard requires Node.js."
else
    echo "   - Node.js version: $(node --version)"
fi

if ! command -v ollama &> /dev/null; then
    echo "⚠️ Ollama is not installed locally. AI Analyst will fallback to cloud/mock."
else
    echo "   - Ollama installed: $(ollama --version)"
fi

# Check /dev/input permissions
if [ -d "/dev/input" ]; then
    echo "   - /dev/input input subsystem detected."
fi

# 2. UNDERSTAND CONFIGURATION
echo "⚙️ [2/4] UNDERSTAND: Verifying configuration files..."

if [ ! -f "config/agent.yaml" ]; then
    echo "   Creating default config/agent.yaml..."
fi
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "   Copied .env.example to .env"
    fi
fi

# 3. INSTALL DEPENDENCIES
echo "📦 [3/4] INSTALL: Installing Python & Frontend dependencies..."

# Python dependencies using user mode or venv
python3 -m pip install --break-system-packages -r requirements.txt || pip3 install -r requirements.txt

if [ -d "frontend" ]; then
    echo "   Installing frontend dependencies..."
    (cd frontend && npm install)
fi

# 4. VERIFY INSTALLATION
echo "🧪 [4/4] VERIFY: Running automated test suite..."
python3 -m unittest discover -s tests

echo ""
echo "=========================================================="
echo "✅ KeyShield AI installation and verification COMPLETE!"
echo ""
echo "To start the system:"
echo "  1. Backend Agent:  python3 src/agent.py"
echo "  2. Dashboard UI:   cd frontend && npm run dev"
echo "=========================================================="
