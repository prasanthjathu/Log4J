import subprocess
import re
import pandas as pd

def run_command(command):
    """
    Run a system command and return the output.
    """
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8'), result.stderr.decode('utf-8')

def scan_dependencies():
    """
    Scan dependencies for Log4j vulnerabilities using pip-audit.
    """
    print("Scanning dependencies for vulnerabilities...")
    output, error = run_command('pip-audit')
    
    if error:
        print(f"Error during scanning: {error}")
    else:
        print("Scan complete.")
        return output

def parse_vulnerabilities(scan_output):
    """
    Parse the scan output to find Log4j vulnerabilities.
    """
    vulnerabilities = []
    for line in scan_output.split('\n'):
        if 'log4j' in line.lower():
            vulnerabilities.append(line)
    return vulnerabilities

def update_vulnerable_packages(vulnerabilities):
    """
    Update vulnerable packages to fixed versions.
    """
    for vulnerability in vulnerabilities:
        package_info = re.findall(r'(\S+==\S+)', vulnerability)
        if package_info:
            package = package_info[0]
            package_name = package.split('==')[0]
            print(f"Updating {package_name}...")
            run_command(f'pip install --upgrade {package_name}')
            print(f"{package_name} updated.")

def update_requirements():
    """
    Update the requirements.txt file with the latest package versions.
    """
    print("Updating requirements.txt...")
    run_command('pip freeze > requirements.txt')
    print("requirements.txt updated.")

def export_results_to_csv(results, filename):
    """
    Export the results to a CSV file.
    """
    df = pd.DataFrame(results)
    df.to_csv(filename, index=False)
    print(f"Results exported to {filename}")

def main():
    scan_output = scan_dependencies()
    vulnerabilities = parse_vulnerabilities(scan_output)
    
    results = [{'vulnerability': v} for v in vulnerabilities]
    
    if vulnerabilities:
        print("Found the following Log4j vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(vulnerability)
        update_vulnerable_packages(vulnerabilities)
        update_requirements()
    else:
        print("No Log4j vulnerabilities found.")
    
    export_results_to_csv(results, 'scan_results.csv')

if __name__ == "__main__":
    main()
