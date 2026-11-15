import subprocess

def run_in_shell(cmd):
    # EXPECT command-injection
    subprocess.call(cmd, shell=True)
