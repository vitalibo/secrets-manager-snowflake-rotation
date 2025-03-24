import subprocess

from snowflake import connector


def handler(event, context):
    cmd = subprocess.run("openssl version", shell=True, capture_output=True)

    return {
        "stdout": cmd.stdout.decode(),
        "stderr": cmd.stderr.decode(),
        "return_code": cmd.returncode,
        "snowflake_version": connector.__version__
    }
