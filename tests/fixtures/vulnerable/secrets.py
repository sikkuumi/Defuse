# FIXTURE: hardcoded credentials, Python. All values are FAKE.

# EXPECT hardcoded-secret
DB_PASSWORD = "correct-horse-battery-staple"

# EXPECT hardcoded-secret
GITHUB_TOKEN = "ghp_FAKEfakeFAKEfake0123456789ABCD"

def connect(host):
    # EXPECT hardcoded-secret
    return dict(host=host, password="s3cr3t-fixture-value")
