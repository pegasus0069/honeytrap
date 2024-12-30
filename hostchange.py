import os
import subprocess

def change_hostname(new_hostname):
  """
  Changes the Raspberry Pi's hostname.

  Args:
    new_hostname: The desired new hostname.
  """
  try:
    # Edit /etc/hostname
    with open('/etc/hostname', 'w') as f:
      f.write(new_hostname + '\n')

    # Edit /etc/hosts
    with open('/etc/hosts', 'r') as f:
      lines = f.readlines()
    with open('/etc/hosts', 'w') as f:
      for line in lines:
        if '127.0.1.1' in line:
          f.write('127.0.1.1\t' + new_hostname + '\n')
        else:
          f.write(line)

    # Refresh hostname without rebooting (using subprocess)
    subprocess.run(['hostnamectl', 'set-hostname', new_hostname], check=True)

    print(f"Hostname changed to {new_hostname}")

  except Exception as e:
    print(f"Error changing hostname: {e}")

if __name__ == "__main__":
  new_hostname = input("Enter the new hostname: ")
  change_hostname(new_hostname)