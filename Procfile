# Gunicorn entry point for Render / Heroku / Railway
# Starts 2 sync workers on the PORT environment variable (default 10000 on Render)
web: gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT
