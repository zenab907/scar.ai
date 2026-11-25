import os
os.environ.pop("ANTHROPIC_API_KEY", None)   # tests run in deterministic rules mode
os.environ.pop("AI_API_KEY", None)
