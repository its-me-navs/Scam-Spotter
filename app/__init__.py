"""Scam Spotter. Loads a local .env file (if python-dotenv is installed) so API keys persist."""
try:
    from dotenv import load_dotenv

    load_dotenv()  # reads .env from the folder you run the command in; real env vars take priority
except ImportError:
    pass
