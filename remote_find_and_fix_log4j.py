
import paramiko
import re
import os
import pandas as pd

def read_computer_list(filename):
    with open(filename, 'r') as file:
        computers = [line.strip() for line in file]
    return computers

def run_command_on_remote(hostname, username, password, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')

def scan_dependencies_on_remote(hostname, username, password):
    print(f"Scanning dependencies on {hostname} for vulnerabilities...")
    output, error = run_command_on_remote(hostname, username, password, 'pip-audit')
    
    if error:
        print(f"Error during scanning on {hostname}: {error}")
    else:
        print(f"Scan complete on {hostname}.")
        return output

def parse_vulnerabilities(scan_output):
    vulnerabilities = []
    for line in scan_output.split('\n'):
        if 'log4j' in line.lower():
            vulnerabilities.append(line)
    return vulnerabilities

def update_vulnerable_packages_on_remote(hostname, username, password, vulnerabilities):
    for vulnerability in vulnerabilities:
        package_info = re.findall(r'(\S+==\S+)', vulnerability)
        if package_info:
            package = package_info[0]
            package_name = package.split('==')[0]
            print(f"Updating {package_name} on {hostname}...")
            run_command_on_remote(hostname, username, password, f'pip install --upgrade {package_name}')
            print(f"{package_name} updated on {hostname}.")

def update_requirements_on_remote(hostname, username, password):
    print(f"Updating requirements.txt on {hostname}...")
    run_command_on_remote(hostname, username, password, 'pip freeze > requirements.txt')
    print(f"requirements.txt updated on {hostname}.")

def export_results_to_csv(results, filename):
    df = pd.DataFrame(results)
    df.to_csv(filename, index=False)
    print(f"Results exported to {filename}")

def main():
    computer_list = read_computer_list('computer_list.txt')
    username = input("Enter SSH username: ")
    password = input("Enter SSH password: ")
    
    results = []
    
    for hostname in computer_list:
        scan_output = scan_dependencies_on_remote(hostname, username, password)
        vulnerabilities = parse_vulnerabilities(scan_output)
        
        result = {'hostname': hostname, 'vulnerabilities': vulnerabilities}
        results.append(result)
        
        if vulnerabilities:
            print(f"Found the following Log4j vulnerabilities on {hostname}:")
            for vulnerability in vulnerabilities:
                print(vulnerability)
            update_vulnerable_packages_on_remote(hostname, username, password, vulnerabilities)
            update_requirements_on_remote(hostname, username, password)
        else:
            print(f"No Log4j vulnerabilities found on {hostname}.")
    
    export_results_to_csv(results, 'scan_results.csv')

if __name__ == "__main__":
    main()
