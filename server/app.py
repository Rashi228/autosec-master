"""
server/app.py — OpenEnv Multi-Mode Deployment Wrapper
=====================================================
Directly exports the FastAPI 'app' from the backend for compliance.
"""

import uvicorn
from backend.api.server_rl import app

def main():
    """Main entry point for the OpenEnv server."""
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()

