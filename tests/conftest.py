import os

# The test suite exercises the insecure benchmark baseline and the layer toggle,
# both of which are off by default. Set before app.config is first imported.
os.environ.setdefault("ENABLE_INSECURE_BASELINE", "true")
os.environ.setdefault("ENABLE_LAYER_TOGGLE", "true")
