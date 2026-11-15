"""
Vercel serverless entry point for LeakGuard Business.
Imports the Flask app from app.py so Vercel can route requests to it.
"""
import os
import sys

# Ensure the parent directory (project root) is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel expects the WSGI callable to be named `app`
# This file is mapped by vercel.json routes
