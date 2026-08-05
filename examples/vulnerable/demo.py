# Vulnerable Python sample — DO NOT use in production
import os
import pickle
import subprocess

SECRET_PASSWORD = "SuperSecret123!"


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


def run_cmd(name):
    os.system("ping " + name)
    subprocess.call("echo " + name, shell=True)


def load_profile(data):
    return pickle.loads(data)


def calc(expr):
    return eval(expr)


def read_file(path):
    with open("/data/" + path) as f:
        return f.read()
