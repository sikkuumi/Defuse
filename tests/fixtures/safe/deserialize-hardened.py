# EXPECT-NONE
import json
import yaml
from flask import request

def safe_yaml():
    return yaml.load(request.form['doc'], Loader=yaml.SafeLoader)

def safe_json():
    return json.loads(request.data)

# `load` on an ordinary object is not a deserialiser. Without the receiver check
# every settings loader in every Python codebase would report.
class Settings:
    def load(self, raw):
        return raw

def ordinary(settings):
    return settings.load(request.data)
