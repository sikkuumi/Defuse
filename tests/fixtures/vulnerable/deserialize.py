import pickle
import yaml
from flask import request

def restore():
    # EXPECT-FLOW unsafe-deserialization
    return pickle.loads(request.data)

def config():
    # EXPECT-FLOW unsafe-deserialization
    return yaml.load(request.form['doc'])
