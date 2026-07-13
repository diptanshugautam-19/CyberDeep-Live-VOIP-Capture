import subprocess
import time
import socket
import os
import signal

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

port = 8000
print(f"Checking if port {port} is active...")

# Find PID using netstat
pid = None
try:
    output = subprocess.check_output(f'netstat -ano | findstr LISTENING | findstr :{port}', shell=True).decode()
    for line in output.strip().split('\n'):
        parts = line.strip().split()
        if parts:
            local_addr = parts[1]
            if local_addr.endswith(f':{port}'):
                pid = int(parts[-1])
                break
except Exception as e:
    print("Error finding PID:", e)

if pid:
    print(f"Killing process {pid} on port {port}...")
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        if is_port_open(port):
            # Force kill if still open
            subprocess.call(f"taskkill /F /PID {pid}", shell=True)
            time.sleep(1)
    except Exception as e:
        print("Error killing process:", e)

if is_port_open(port):
    print(f"Port {port} is still open. Cannot restart server.")
    sys.exit(1)

print("Starting server...")
venv_python = r"D:\cyberdeep\.venv\Scripts\python.exe"
proc = subprocess.Popen(
    [venv_python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
)

# Wait and verify
for _ in range(5):
    time.sleep(1)
    if is_port_open(port):
        print(f"Success: Server restarted and listening on port {port}!")
        break
else:
    print("Warning: Server started but port 8000 is not listening yet.")
