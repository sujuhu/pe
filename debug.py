#coding = utf-8
import os, sys
import vmware
from ctypes import *
import subprocess

debug = r'd:\src\pe\build\nmake.win32\debug'
bin = "bin\\petool.exe"
parm = r'c:\windows\system32\notepad.exe'

#启动虚拟机
vm_path = r"d:\ace\debugger_wxpsp3cn\debugger_wxpsp3cn.vmx"
username = None
password = None
snapshot = None
vm = vmware.VMWare()
vm.Connect( c_int(0), 0, c_int(0), c_int(0), 0 )
vm.OpenVM(vm_path, vmware.VIX_VMOPEN_NORMAL)
username = "administrator"
password = ""
snapshot = "ready"
remote_dir = "C:\\debug"

vm.GetNamedSnapshot(snapshot)
vm.RevertToSnapshot(0)
vm.LoginInGuest(username, password, 0)


vm.CreateDirectoryInGuest(remote_dir)

#将debug目录下所有文件复制到目标虚拟机中
for root, dirs, files in os.walk(debug):
    for name in files:
    	dir_name = root.replace(debug, remote_dir)
        remote_file = os.path.join(dir_name, name);
        local_file = os.path.join(root, name)
    	vm.CopyFileFromHostToGuest(local_file, remote_file, 0)
    for name in dirs:
    	dir_name = root.replace(debug, remote_dir)
    	remote = os.path.join(dir_name, name)
    	vm.CreateDirectoryInGuest(remote)

#启动远程连接
print os.path.join(remote_dir, bin)
cmdline = ["d:\\app\\windbg\\x86\\windbg.exe",
	"-premote", 
	"tcp:port=6422, server=192.168.184.11", 
	"%s" % os.path.join(remote_dir, bin)]
subprocess.call(cmdline)



