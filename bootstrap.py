#!/usr/bin/env python3
"""Run with Python 3.11+; install the starter in an isolated local environment."""
import argparse
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument('--environment',required=True)
parser.add_argument('--workspace',required=True)
parser.add_argument('--name')
parser.add_argument('--restore-checkpoint')
parser.add_argument('--profile',default='zog-development')
parser.add_argument('--region',default='us-east-1')
parser.add_argument('--credentials-file')
arguments=parser.parse_args()
if sys.version_info < (3,11):
    parser.error('Python 3.11 or newer is required locally')
if bool(arguments.name) == bool(arguments.restore_checkpoint):
    parser.error('Specify either --name for a new workspace or --restore-checkpoint')
environment=Path(arguments.environment).resolve()
if not environment.exists():
    subprocess.run([sys.executable,'-m','venv',str(environment)],check=True)
python=environment/'bin/python'
if not python.is_file():
    parser.error('Environment exists without bin/python; choose another directory')
subprocess.run([str(python),'-m','pip','install',str(Path(__file__).resolve().parent)],check=True)
command=[str(environment/'bin/host-deploy')]
if arguments.credentials_file:
    subprocess.run(command+['credentials-import','--file',arguments.credentials_file,'--profile',arguments.profile],check=True)
if arguments.restore_checkpoint:
    subprocess.run(command+['checkpoint-restore','--workspace',arguments.workspace,'--archive',arguments.restore_checkpoint],check=True)
else:
    subprocess.run(command+['init','--workspace',arguments.workspace,'--name',arguments.name,'--profile',arguments.profile,'--region',arguments.region],check=True)
subprocess.run(command+['doctor','--workspace',arguments.workspace],check=True)
print('Bootstrap complete. Command:',command[0])
