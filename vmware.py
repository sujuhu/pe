#coding=utf-8
import os,sys
from ctypes import *
import time

VIX_OK  = 0 

VIX_API_VERSION = c_int(-1)

VIX_INVALID_HANDLE = c_int( 0 )

VIX_VMOPEN_NORMAL = c_int(0)

#VixHandleType
VIX_HANDLETYPE_NONE = c_int(0)
VIX_HANDLETYPE_HOST = c_int(2)
VIX_HANDLETYPE_VM   = c_int(3)
VIX_HANDLETYPE_NETWORK  = c_int(5)
VIX_HANDLETYPE_JOB  = c_int(6)
VIX_HANDLETYPE_SNAPSHOT = c_int(7)
VIX_HANDLETYPE_PROPERTY_LIST    = c_int(9)
VIX_HANDLETYPE_METADATA_CONTRINER   = c_int(11)

#VixServiceProvider
VIX_SERVICEPROVIDER_DEFAULT = c_int(1)
VIX_SERVICEPROVIDER_VMWARE_SERVER   = c_int(2)
VIX_SERVICEPROVIDER_VMWARE_WORKSTATION  = c_int(3)
VIX_SERVICEPROVIDER_VMWARE_PLAYER   = c_int(4)
VIX_SERVICEPROVIDER_VMWARE_VI_SERVER    = c_int(10)

# Result properties; these are returned by various procedures */
VIX_PROPERTY_JOB_RESULT_ERROR_CODE                 = c_int(3000)
VIX_PROPERTY_JOB_RESULT_VM_IN_GROUP                = c_int(3001)
VIX_PROPERTY_JOB_RESULT_USER_MESSAGE               = c_int(3002)
VIX_PROPERTY_JOB_RESULT_EXIT_CODE                  = c_int(3004)
VIX_PROPERTY_JOB_RESULT_COMMAND_OUTPUT             = c_int(3005)
VIX_PROPERTY_JOB_RESULT_HANDLE                     = c_int(3010)
VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS        = c_int(3011)
VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_ELAPSED_TIME = c_int(3017)
VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE    = c_int(3018)
VIX_PROPERTY_JOB_RESULT_ITEM_NAME                  = c_int(3035)
VIX_PROPERTY_JOB_RESULT_FOUND_ITEM_DESCRIPTION     = c_int(3036)
VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_COUNT        = c_int(3046)
VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_HOST         = c_int(3048)
VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_FLAGS        = c_int(3049)
VIX_PROPERTY_JOB_RESULT_PROCESS_ID                 = c_int(3051)
VIX_PROPERTY_JOB_RESULT_PROCESS_OWNER              = c_int(3052)
VIX_PROPERTY_JOB_RESULT_PROCESS_COMMAND            = c_int(3053)
VIX_PROPERTY_JOB_RESULT_FILE_FLAGS                 = c_int(3054)
VIX_PROPERTY_JOB_RESULT_PROCESS_START_TIME         = c_int(3055)
VIX_PROPERTY_JOB_RESULT_VM_VARIABLE_STRING         = c_int(3056)
VIX_PROPERTY_JOB_RESULT_PROCESS_BEING_DEBUGGED     = c_int(3057)
VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_SIZE          = c_int(3058)
VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_DATA          = c_int(3059)
VIX_PROPERTY_JOB_RESULT_FILE_SIZE                  = c_int(3061)
VIX_PROPERTY_JOB_RESULT_FILE_MOD_TIME              = c_int(3062)

#Vix Property ID's
VIX_PROPERTY_NONE   =   c_int( 0 )

#Guest Process functions
VIX_RUNPROGRAM_RETURN_IMMEDIATELY = c_int(1)
VIX_RUNPROGRAM_ACTIVATE_WINDOW = c_int(2)

#VixVMPowerOpOptions
VIX_VMPOWEROP_NORMAL                      = c_int(0)
VIX_VMPOWEROP_FROM_GUEST                  = c_int(0x0004)
VIX_VMPOWEROP_SUPPRESS_SNAPSHOT_POWERON   = c_int(0x0080)
VIX_VMPOWEROP_LAUNCH_GUI                  = c_int(0x0200)
VIX_VMPOWEROP_START_VM_PAUSED             = c_int(0x1000)

#Screen Capture
VIX_CAPTURESCREENFORMAT_PNG               = c_int(0x01)
VIX_CAPTURESCREENFORMAT_PNG_NOCOMPRESS    = c_int(0x02)

NULL = c_char_p(None)

class VMWareError(Exception):pass

class VMWare():
    def __init__( self ):
        '''
        vixfile = r'/usr/lib/vmware-vix/Workstation-7.1.0/32bit/libvix.so'
        if not os.path.exists( vixfile ):
            raise IOException, "VIX not found"
        env = os.environ
        if not env.has_key( 'LD_LIBRARY_PATH' ):
            print "can't find ENVIRONMENT LD_LIBRARY_PATH"
            os.environ['LD_LIBRARY_PATH'] = r'/usr/lib/vmware-vix/Workstation-7.1.0/32bit'
            os.putenv( 'LD_LIBRARY_PATH', r'/usr/lib/vmware-vix/Workstation-7.1.0/32bit')
        '''

        if sys.platform == "win32":
            vixfile = r'c:\Program Files (x86)\VMware\VMware VIX\Workstation-7.1.0\32bit\vix.dll'
        else:            
            vixfile = 'libvix.so'
        
        #print vixfile
        self.vix = cdll.LoadLibrary( vixfile )
        self.hosthandle = c_int(0) 
        self.path = None
        self.username = None
        self.password = None
        self.is_alive = False
        self.vmHandle = c_int(0)
        self.snapshotHandle = c_int(0)
        self.VixJob_Wait = self.vix.VixJob_Wait
        self.VixJob_Wait.restype = c_ulonglong 
        self.Vix_GetErrorText = self.vix.Vix_GetErrorText
        self.Vix_GetErrorText.restype = c_char_p
        self.Vix_ReleaseHandle = self.vix.Vix_ReleaseHandle
        
    def Connect(self, hostname, hostport, username, password, options):
        jobhandle = c_int(0)
        try:
            jobhandle = self.vix.VixHost_Connect( VIX_API_VERSION,
                    VIX_SERVICEPROVIDER_VMWARE_WORKSTATION,
                    hostname,   #hostname
                    hostport,      #hostport
                    username,   #username
                    password,   #password
                    options,      #options
                    VIX_INVALID_HANDLE, #propertyListHandle
                    NULL,       #callbackproc
                    NULL )      #clientData
            err = self.VixJob_Wait( jobhandle, 
                                    VIX_PROPERTY_JOB_RESULT_HANDLE, 
                                    byref( self.hosthandle ), VIX_PROPERTY_NONE )
            if err != VIX_OK:
                raise VMWareError, "Connect Fail:%s" % self.Vix_GetErrorText( err, NULL )
        finally:
            self.Vix_ReleaseHandle( jobhandle )

    def ReleaseHandle(self, handle):
        self.Vix_ReleaseHandle(handle)

    def OpenVM(self, vmxFilePathName, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixHost_OpenVM( 
                    self.hosthandle, 
                    vmxFilePathName,
                    options,
                    VIX_INVALID_HANDLE, 
                    NULL, NULL )
            err = self.VixJob_Wait( 
                    jobHandle, 
                    VIX_PROPERTY_JOB_RESULT_HANDLE,
                    byref(self.vmHandle),
                    VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "OpenVM Failed:%s" % self.Vix_GetErrorText( err, NULL )
        finally:
            self.vix.Vix_ReleaseHandle( jobHandle )

    def PowerOff(self, powerOffOptions):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_PowerOff(self.vmHandle,
                                                powerOffOptions,
                                                NULL,
                                                NULL);
            err = self.VixJob_Wait(jobHandle, VIX_PROPERTY_NONE)
            if VIX_OK != err:
                raise VMWareError, "PowerOff Failed:%s" % self.Vix_GetErrorText(err, NULL)
        finally:
            self.Vix_ReleaseHandle(jobHandle)
       
    def CopyFileFromHostToGuest(self, hostPathName, guestPathName, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_CopyFileFromHostToGuest(
                            self.vmHandle,
                            hostPathName,
                            guestPathName,
                            options,
                            VIX_INVALID_HANDLE, 
                            NULL,
                            NULL )
            err = self.VixJob_Wait( jobHandle, VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "CopyFileFromHostToGuest %s Failed:%s" % ( hostPathName, self.Vix_GetErrorText( err, NULL ) )
        finally:
            self.Vix_ReleaseHandle( jobHandle )

    def CreateDirectoryInGuest(self, pathName):
        jobHandle = c_int(0)
        try: 
            jobHandle = self.vix.VixVM_CreateDirectoryInGuest(
                            self.vmHandle, 
                            pathName, 
                            VIX_INVALID_HANDLE,
                            NULL,
                            NULL)
            err = self.VixJob_Wait(jobHandle, VIX_PROPERTY_NONE)
            if VIX_OK != err:
                raise VMWareError, "CreateDirectoryInGuest %s Failed: %s" % ( pathName, self.Vix_GetErrorText( err, NULL ) )
        finally:
            self.Vix_ReleaseHandle(jobHandle)

    def RunProgramInGuest(self, guestProgramName, commandLineArgs, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_RunProgramInGuest(
                    self.vmHandle, 
                   guestProgramName,
                   commandLineArgs, 
                   options,
                   VIX_INVALID_HANDLE,
                   NULL,
                   NULL )
            err = self.VixJob_Wait( jobHandle, VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "RunProgramInGuest \"%s %s\" Failed:%s" % ( guestProgramName, commandLineArgs, self.Vix_GetErrorText( err, NULL ))
        finally:
            self.Vix_ReleaseHandle(jobHandle)

    def FileExistsInGuest(self,guestPathName):
        is_exist = c_int()
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_FileExistsInGuest(self.vmHandle, guestPathName, NULL, NULL)
            err = self.VixJob_Wait(jobHandle, VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS, byref(is_exist), VIX_PROPERTY_NONE)
            if err != VIX_OK:
                raise VMWareError, "FileExistsInGuest %s Failed:%s" % (guestPathName, self.Vix_GetErrorText(err,NULL))
            return bool(is_exist.value)
        finally:
            self.Vix_ReleaseHandle(jobHandle)

    def CopyFileFromGuestToHost(self, guestPathName, hostPathName, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_CopyFileFromGuestToHost( self.vmHandle,
                        guestPathName,
                        hostPathName,
                        options,
                        VIX_INVALID_HANDLE,
                        NULL,
                        NULL )
            err = self.VixJob_Wait( jobHandle, VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "CopyFileFromGuestToHost %s Failed:%s" % (guestPathName, self.Vix_GetErrorText( err, NULL ))
        finally:
            self.Vix_ReleaseHandle( jobHandle )

    def GetNamedSnapshot(self, snapshot_name ):
        self.snapshotHandle = c_int(0)
        err = self.vix.VixVM_GetNamedSnapshot( self.vmHandle, 
            snapshot_name, 
            byref( self.snapshotHandle )  )
        if VIX_OK != err :
            raise VMWareError, "GetNamedSnapshot %s Failed:%s" % ( snapshot_name, self.Vix_GetErrorText( err, NULL ))
        return self.snapshotHandle

    def LoginInGuest(self,username, password, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_LoginInGuest( 
                    self.vmHandle, 
                    username, 
                    password,
                    0,
                    NULL,
                    NULL )
            err = self.VixJob_Wait( jobHandle, VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "VixVM_LoginInGuest Failed:%s" % self.Vix_GetErrorText( err, NULL )
        finally:
            self.Vix_ReleaseHandle( jobHandle )

    def CaptureScreenImage(self, png_file):
        jobHandle = c_int(0)
        byte_count = c_int()
        screen_bits = c_void_p()
        try:
            jobHandle = self.vix.VixVM_CaptureScreenImage(
                    self.vmHandle,
                    VIX_CAPTURESCREENFORMAT_PNG,
                    VIX_INVALID_HANDLE,
                    NULL,
                    NULL)
            err = self.VixJob_Wait(jobHandle,
                  VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_DATA,
                  byref(byte_count), byref(screen_bits),
                  VIX_PROPERTY_NONE)
            if VIX_OK != err:
                raise VMWareError, "VixVM_CaptureScreenImage Failed:%s" % self.Vix_GetErrorText( err, NULL )
        finally:
            self.Vix_ReleaseHandle( jobHandle )

        if byte_count.value <= 0:
            raise VMWareError, "Screen Image Size is 0"

        try:
            data = cast(screen_bits.value, POINTER(c_ubyte * byte_count.value))
            byteData = ''.join(map(chr, data.contents))
        except Exception, e:
            raise VMWareError, e

        png = open(png_file, "wb")
        try:
            #print data
            png.write(byteData)
        finally:
            png.close()

    def RevertToSnapshot(self, options):
        jobHandle = c_int(0)
        try:
            jobHandle = self.vix.VixVM_RevertToSnapshot( 
                    self.vmHandle,
                    self.snapshotHandle,
                    options,
                    VIX_INVALID_HANDLE, 
                    NULL,
                    NULL)
            err = self.VixJob_Wait( jobHandle, VIX_PROPERTY_NONE )
            if VIX_OK != err:
                raise VMWareError, "RevertToSnapshot Failed: %s" % self.Vix_GetErrorText( err, NULL )
        finally:
            self.Vix_ReleaseHandle( jobHandle ) 

    def close(self):
        self.vix.Vix_ReleaseHandle( self.vmHandle )
        self.vix.VixHost_Disconnect( self.hosthandle )
        self.hosthandle = VIX_INVALID_HANDLE







