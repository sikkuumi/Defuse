# FIXTURE: OS command injection, Python.
import os
import subprocess

def ping(host):
    # EXPECT command-injection
    os.system("ping -c 1 " + host)

def list_dir(directory):
    # EXPECT command-injection
    subprocess.run("ls -la " + directory, shell=True)
