import subprocess

def run(cmd):
    # EXPECT command-injection
    subprocess.call(cmd, shell=True)
