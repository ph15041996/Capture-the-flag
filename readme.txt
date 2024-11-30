PLEASE RUN THE BELOW COMMAND BEFORE RUNNING THE ACTUAL CODE.

pip install -r requirements.txt
sudo apt install nmap
sudo apt install dirb
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
#run msfconsole before running the code (need to setup db)
msfconsole

# run the actual code
python script.py
