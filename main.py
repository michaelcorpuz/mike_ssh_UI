import tkinter as tk
import paramiko
import os

# Path to your private key
SSH_KEY_PATH = r"C:\Users\michael.corpuz\.ssh\michael_id_rsa.pub.txt"

# Commands dictionary
commands = {
    "Uptime": "uptime",
    "Disk Usage (df)": "df -h",
    "Check /usr usage": "df -hT /usr",
    "Check /usr/local usage": "df -hT /usr/local",
    "Top (snapshot)": "sudo top -n 1",
    "Crontab": "crontab -l",
    "Mounts": "sudo mount",
    "SSM List": "sudo ssm list",
    "Netstat": "sudo netstat -tulpn",
    "APM status": "sudo /opt/IBM/apm/agent/bin/os-agent.sh status",
    "APM start": "sudo /opt/IBM/apm/agent/bin/os-agent.sh start",
    "ls --long": "ls -lh ."
}

username="mcorpuz"

def ping_host():
    host = host_entry.get()
    command = f"ping -c 4 {host}"  # For Linux; use 'ping -n 4' for Windows targets

    try:
        key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=22, username="mcorpuz", pkey=key)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        output_text.insert(tk.END, f"\n$ {command}\n")
        output_text.insert(tk.END, output if output else error)
        output_text.see(tk.END)

        ssh.close()
    except Exception as e:
        output_text.insert(tk.END, f"\nError: {e}\n")
        output_text.see(tk.END)

def run_command():
    host = host_entry.get()
    command = commands[selected_command.get()]

    try:
        key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=22, username="mcorpuz", pkey=key)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        output_text.insert(tk.END, f"\n{username}@{host}$ {command}\n")
        output_text.insert(tk.END, output if output else error)

        ssh.close()
    except Exception as e:
        output_text.insert(tk.END, f"\nError: {e}\n")
    
    
    output_text.see(tk.END)
    

def on_enter(event):
    # Get the last line typed
    last_line = output_text.get("end-2l linestart", "end-1c").strip()

    # Check if it's a valid command
    if last_line in commands.values():
        host = host_entry.get()
        try:
            key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port=22, username="mcorpuz", pkey=key)

            stdin, stdout, stderr = ssh.exec_command(last_line)
            output = stdout.read().decode()
            error = stderr.read().decode()

            output_text.insert(tk.END, "\n" + (output if output else error))
            output_text.see(tk.END)
            ssh.close()
        except Exception as e:
            output_text.insert(tk.END, f"\nError: {e}\n")
            output_text.see(tk.END)
    else:
        output_text.insert(tk.END, f"\nError: Command not allowed.\n")
        output_text.see(tk.END)

    return "break"  # Prevent default newline behavior
    

# Main window
root = tk.Tk()
root.title("Remote Command Runner")
root.geometry("1000x600")

# Left panel for inputs and dropdown
left_frame = tk.Frame(root)
left_frame.pack(side="left", fill="y", padx=10, pady=10)

tk.Label(left_frame, text="Host:").pack(anchor="w")
host_entry = tk.Entry(left_frame, width=30)
host_entry.pack()


tk.Label(left_frame, text="Select Command:").pack(anchor="w")
selected_command = tk.StringVar(root)
selected_command.set("Uptime")  # default value
command_menu = tk.OptionMenu(left_frame, selected_command, *commands.keys())
command_menu.pack()
tk.Button(left_frame, width=20, text="Run Command", command=run_command).pack(pady=10)
tk.Button(left_frame, width=20, text="Ping Host", command=ping_host).pack(pady=5)

# Right panel for output

output_frame = tk.Frame(root)
output_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

scrollbar = tk.Scrollbar(output_frame)
scrollbar.pack(side="right", fill="y")

output_text = tk.Text(
    output_frame,
    height=30,
    width=120,
    bg="black",
    fg="lime",
    font=("Courier", 10),
    yscrollcommand=scrollbar.set
)
output_text.pack(side="left", fill="both", expand=True)
scrollbar.config(command=output_text.yview)
output_text.bind("<Return>", on_enter)



root.mainloop()
