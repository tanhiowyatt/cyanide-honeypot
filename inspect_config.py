from cyanide.core.config import load_config
import json

config = load_config()
print(json.dumps(config, indent=2))
