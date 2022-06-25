#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   UserParameters LDAP attribute editor
#
# Authors:
#   Julien Galleron (@Fana_win)

from impacket.ldap import ldap
from struct import *
from ctypes import *
import pdb

# https://web.archive.org/web/20180104160558/https://00laboratories.com/resources/code/c-sharp/microsoft-active-directory-userparameters-header

class UserConfigFlags:
    # The initial program setting. TRUE indicates the value to use for InitialProgram from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_INITIAL_PROGRAM = 0x10000000
    # The callback setting. TRUE indicates the value to use for Callback from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_CALLBACK = 0x08000000
    # The callback number setting. TRUE indicates the value to use for CallbackNumber from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_CALLBACK_NUMBER = 0x04000000
    # The shadow setting. TRUE indicates the value to use for Shadow from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_SHADOW = 0x02000000
    # The maximum allowed session connection time setting. TRUE indicates the value to use for MaxSessionTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_MAX_SESSION_TIME = 0x01000000
    # The maximum allowed session disconnect time setting. TRUE indicates the value to use for MaxDisconnectionTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_MAX_DISCONNECTION_TIME = 0x00800000
    # The maximum allowed session idle time. TRUE indicates the value to use for MaxIdleTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_MAX_IDLE_TIME = 0x00400000
    # The auto client setting. TRUE indicates the value to use for fAutoClientDrivers and fAutoClientLpts from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_AUTO_CLIENT = 0x00200000
    # Inherit security setting. TRUE indicates the use of security settings from the user properties if the machine/user policy is not set, FALSE otherwise.
    INHERIT_SECURITY = 0x00100000
    # Set to TRUE to ignore the credential sent from the client and always prompt for a password, FALSE otherwise.
    PROMPT_FOR_PASSWORD = 0x00080000
    # Set to TRUE to log off the session when the idle timers for the session expire. Otherwise, the session will be disconnected when the timer expires.
    RESET_BROKEN = 0x00040000
    # FALSE indicates that the user can reconnect from any client computer to a disconnected session. TRUE indicates that the user must reconnect to a disconnected session from the same client computer that initially established the disconnected session. Logging on from a different client computer will lead to a new terminal server session being created.
    RECONNECT_SAME = 0x00020000
    # TRUE indicates that a user cannot log on to a session remotely, FALSE otherwise.
    LOGON_DISABLED = 0x00010000
    # TRUE specifies to automatically redirect local drives on the client so they are accessible to the user in the remote terminal server session, FALSE otherwise.
    AUTO_CLIENT_DRIVES = 0x00008000
    # TRUE specifies to automatically redirect printers on the client so they are accessible to the user in the remote terminal server session, FALSE otherwise.
    AUTO_CLIENT_LPTS = 0x00004000
    # TRUE indicates to force the client's redirected printer to be the default printer for the user, FALSE otherwise.
    FORCE_CLIENT_LPT_DEF = 0x00002000
    # TRUE indicates the connection does not need encryption, FALSE otherwise.
    DISABLE_ENCRYPTION = 0x00001000
    # Not used.
    HOME_DIRECTORY_MAP_ROOT = 0x00000800
    # TRUE indicates to override a third-party GINA so that only the default GINA is used for the terminal server session, FALSE otherwise.
    USE_DEFAULT_GINA = 0x00000400
    # TRUE indicates disable client printer redirection, FALSE otherwise.
    DISABLE_CPM = 0x00000200
    # TRUE indicates disable client drive redirection, FALSE otherwise.
    DISABLE_CDM = 0x00000100
    # TRUE indicates disable client COM port redirection, FALSE otherwise.
    DISABLE_CCM = 0x00000080
    # TRUE indicates disable client printer (LPT) port redirection, FALSE otherwise.
    DISABLE_LPT = 0x00000040
    # TRUE indicates disable client clipboard redirection, FALSE otherwise.
    DISABLE_CLIP = 0x00000020
    # TRUE indicates disable .exe file execution, FALSE otherwise.
    DISABLE_EXE = 0x00000010
    # TRUE indicates display of the desktop wallpaper in the session has been disabled, FALSE otherwise.
    WALLPAPER_DISABLED = 0x00000008
    # TRUE indicates disable client audio redirection, FALSE otherwise.
    DISABLE_CAM = 0x00000004

def encodeValue(value):
    bytearray = []
    for c in value:
        # Convert character to bin
        asciin = ord(c)
        # Padding to match byte format
        bits = '0'*(8-(len(bin(asciin))-2))+bin(asciin)[2:]
        # Splitting byte in two halves
        xxxx = bits[:4]
        yyyy = bits[4:]
        
        # Converting each half to int
        xxxxv = int(xxxx, 2)
        yyyyv = int(yyyy, 2)

        # Adding control bits according splits' value
        controlx = '001011' if (xxxxv <= 9) else '011010'
        controly = '001110' if (yyyyv <= 9) else '011010'

        # Modifying splits' value because Microsoft
        if xxxxv > 9:
            xxxxv -= 9
        if yyyyv > 9:
            yyyyv -= 9
        
        # Padding each half to match in byte format
        xxxx = '0'*(4-(len(bin(xxxxv))-2))+bin(xxxxv)[2:]
        
        yyyy = '0'*(4-(len(bin(yyyyv))-2))+bin(yyyyv)[2:]

        # Adding header to everything computed before
        bits = '1110' + controly + yyyy + controlx + xxxx

        # Splitting bits chain (24 bits) to 3 bytes
        byte1 = bits[:8]
        byte2 = bits[8:16]
        byte3 = bits[16:]
        bytearray += [byte1,byte2,byte3]
    return "".join(bytearray)


class UserParameters:
    class TSProperty:

        def __init__(self, propertyName, propertyValue):                  
            self.type = b'\x01'
            if propertyName == 'CtxInitialProgram':
                self.propName = propertyName
                self.propValue = propertyValue
            elif propertyName == 'CtxShadow':
                configuration = {
                    'Disable': 0,
                    'EnableInputNotify': 1,
                    'EnableInputNoNotify': 2,
                    'EnableNoInputNotify': 3,
                    'EnableNoInputNoNotify': 4
                }
                self.propName = propertyName
                self.propValue = pack('l', configuration[propertyValue])
            else:
                print('Unknown property name ' + str(propertyName))
                raise Exception()
            self.nameLength = pack('b', len(self.propName)*2)
            print("Name length :"+str(self.nameLength)+ " shoud be equal to "+str(len(self.propName)*2))
            self.valueLength = pack('b', len(self.propValue)*2)
            print("Value length :"+str(self.valueLength))

        @property
        def value(self):
            return self.nameLength + self.valueLength + self.type + str.encode(self.propName) + str.encode(self.propValue)

    def __init__(self, target, initialProgram='', shadowValue=''):
        self.target = target
        reservedData = b'\x20'*48
        signature = b'\x50'
        self.tsPropertyArray = []
        if len(initialProgram+shadowValue) > 0:
            if initialProgram != '':
                self.initialProgramProperty = self.TSProperty('CtxInitialProgram', initialProgram)
                self.tsPropertyArray.append(self.initialProgramProperty)
            if shadowValue != '':
                self.initialShadowProperty = self.TSProperty('CtxShadow', shadowValue)
                self.tsPropertyArray.append(self.initialShadowProperty)
            self.tsPropertyCount = pack('b', len(self.tsPropertyArray))
            self.header = reservedData + signature
        else:
            print('Please provide parameters')
            raise Exception()

    public uint? CtxCfgPresent
    {
        get { if (Properties.ContainsKey("CtxCfgPresent")) return Properties["CtxCfgPresent"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxCfgPresent"); return; } if (!Properties.ContainsKey("CtxCfgPresent")) { Properties.Add("CtxCfgPresent", new ActiveDirectoryUserParametersProperty()); Properties["CtxCfgPresent"].Name = "CtxCfgPresent"; } Properties["CtxCfgPresent"].SetValueUInt32(value.Value); }
    }

    # 
    # Each bit in the PropValue maps to a Boolean field of the USERCONFIG structure returned by the RpcGetConfigData method. For details about each bit, see the table of CtxCfgFlags1 values in this section. The default value is <see cref="CtxCfgFlags1Default"/>.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxCfgFlags1
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return Properties["CtxCfgFlags1"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxCfgFlags1"); return; } if (!Properties.ContainsKey("CtxCfgFlags1")) { Properties.Add("CtxCfgFlags1", new ActiveDirectoryUserParametersProperty()); Properties["CtxCfgFlags1"].Name = "CtxCfgFlags1"; } Properties["CtxCfgFlags1"].SetValueUInt32(value.Value); }
    }

    # 
    # The callback class for callback operations.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxCallBack
    {
        get { if (Properties.ContainsKey("CtxCallBack")) return Properties["CtxCallBack"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxCallBack"); return; } if (!Properties.ContainsKey("CtxCallBack")) { Properties.Add("CtxCallBack", new ActiveDirectoryUserParametersProperty()); Properties["CtxCallBack"].Name = "CtxCallBack"; } Properties["CtxCallBack"].SetValueUInt32(value.Value); }
    }

    # 
    # The keyboard layout (HKL) of the user session.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxKeyboardLayout
    {
        get { if (Properties.ContainsKey("CtxKeyboardLayout")) return Properties["CtxKeyboardLayout"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxKeyboardLayout"); return; } if (!Properties.ContainsKey("CtxKeyboardLayout")) { Properties.Add("CtxKeyboardLayout", new ActiveDirectoryUserParametersProperty()); Properties["CtxKeyboardLayout"].Name = "CtxKeyboardLayout"; } Properties["CtxKeyboardLayout"].SetValueUInt32(value.Value); }
    }

    # 
    # The minimum allowed encryption level of the user session.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public sbyte? CtxMinEncryptionLevel
    {
        get { if (Properties.ContainsKey("CtxMinEncryptionLevel")) return Properties["CtxMinEncryptionLevel"].GetValueSByte(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxMinEncryptionLevel"); return; } if (!Properties.ContainsKey("CtxMinEncryptionLevel")) { Properties.Add("CtxMinEncryptionLevel", new ActiveDirectoryUserParametersProperty()); Properties["CtxMinEncryptionLevel"].Name = "CtxMinEncryptionLevel"; } Properties["CtxMinEncryptionLevel"].SetValueSByte(value.Value); }
    }

    # 
    # The NetWare logon server name.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxNWLogonServer
    {
        get { if (Properties.ContainsKey("CtxNWLogonServer")) return Properties["CtxNWLogonServer"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxNWLogonServer"); return; } if (!Properties.ContainsKey("CtxNWLogonServer")) { Properties.Add("CtxNWLogonServer", new ActiveDirectoryUserParametersProperty()); Properties["CtxNWLogonServer"].Name = "CtxNWLogonServer"; } Properties["CtxNWLogonServer"].SetValueUInt32(value.Value); }
    }

    # 
    # This attribute specifies the home directory for the user. Each user on a terminal server has a unique home directory. This ensures that application information is stored separately for each user in a multi-user environment. To set a home directory on the local computer, the implementer specifies a local path; for example, C:\Path. To set a home directory in a network environment, the implementer MUST first set the CtxWFHomeDirDrive property, and then set this property to a Universal Naming Convention (UNC) path.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxWFHomeDir
    {
        get { if (Properties.ContainsKey("CtxWFHomeDir")) return Properties["CtxWFHomeDir"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxWFHomeDir"); return; } if (!Properties.ContainsKey("CtxWFHomeDir")) { Properties.Add("CtxWFHomeDir", new ActiveDirectoryUserParametersProperty()); Properties["CtxWFHomeDir"].Name = "CtxWFHomeDir"; } Properties["CtxWFHomeDir"].SetValueString(value); }
    }

    # 
    # This attribute specifies a home drive for the user. In a network environment, this property is a string containing a drive specification (a drive letter followed by a colon) to which the UNC path specified in the TerminalServicesCtxWFHomeDir property is mapped. To set a home directory in a network environment, the implementer MUST first set this property, and then set the CtxWFHomeDir property.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxWFHomeDirDrive
    {
        get { if (Properties.ContainsKey("CtxWFHomeDirDrive")) return Properties["CtxWFHomeDirDrive"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxWFHomeDirDrive"); return; } if (!Properties.ContainsKey("CtxWFHomeDirDrive")) { Properties.Add("CtxWFHomeDirDrive", new ActiveDirectoryUserParametersProperty()); Properties["CtxWFHomeDirDrive"].Name = "CtxWFHomeDirDrive"; } Properties["CtxWFHomeDirDrive"].SetValueString(value); }
    }

    # 
    # This attribute specifies the path and file name of the application that the user requires to start automatically when the user logs on to the terminal server. To set an initial application to start when the user logs on, the implementer MUST first set this property, and then set the CtxWorkDirectory property. If the implementer sets only the CtxInitialProgram property, the application starts in the user's session in the default user directory.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxInitialProgram
    {
        get { if (Properties.ContainsKey("CtxInitialProgram")) return Properties["CtxInitialProgram"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxInitialProgram"); return; } if (!Properties.ContainsKey("CtxInitialProgram")) { Properties.Add("CtxInitialProgram", new ActiveDirectoryUserParametersProperty()); Properties["CtxInitialProgram"].Name = "CtxInitialProgram"; } Properties["CtxInitialProgram"].SetValueString(value); }
    }

    # 
    # This attribute specifies the maximum duration (in minutes) of the Terminal Services session. After the specified number of minutes has elapsed, the session can be disconnected or terminated.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxMaxConnectionTime
    {
        get { if (Properties.ContainsKey("CtxMaxConnectionTime")) return Properties["CtxMaxConnectionTime"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxMaxConnectionTime"); return; } if (!Properties.ContainsKey("CtxMaxConnectionTime")) { Properties.Add("CtxMaxConnectionTime", new ActiveDirectoryUserParametersProperty()); Properties["CtxMaxConnectionTime"].Name = "CtxMaxConnectionTime"; } Properties["CtxMaxConnectionTime"].SetValueUInt32(value.Value); }
    }

    # 
    # This attribute specifies the maximum amount of time (in minutes) that a disconnected Terminal Services session remains active on the terminal server. After the specified number of minutes has elapsed, the session is terminated.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxMaxDisconnectionTime
    {
        get { if (Properties.ContainsKey("CtxMaxDisconnectionTime")) return Properties["CtxMaxDisconnectionTime"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxMaxDisconnectionTime"); return; } if (!Properties.ContainsKey("CtxMaxDisconnectionTime")) { Properties.Add("CtxMaxDisconnectionTime", new ActiveDirectoryUserParametersProperty()); Properties["CtxMaxDisconnectionTime"].Name = "CtxMaxDisconnectionTime"; } Properties["CtxMaxDisconnectionTime"].SetValueUInt32(value.Value); }
    }

    # 
    # This attribute specifies the maximum amount of time (in minutes) that the Terminal Services session can remain idle. After the specified number of minutes has elapsed, the session can be disconnected or terminated.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxMaxIdleTime
    {
        get { if (Properties.ContainsKey("CtxMaxIdleTime")) return Properties["CtxMaxIdleTime"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxMaxIdleTime"); return; } if (!Properties.ContainsKey("CtxMaxIdleTime")) { Properties.Add("CtxMaxIdleTime", new ActiveDirectoryUserParametersProperty()); Properties["CtxMaxIdleTime"].Name = "CtxMaxIdleTime"; } Properties["CtxMaxIdleTime"].SetValueUInt32(value.Value); }
    }

    # 
    # This attribute specifies a roaming or mandatory profile path to use when the user logs on to the terminal server. The profile path is in the following network path format: \\servername\profiles folder name\username.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxWFProfilePath
    {
        get { if (Properties.ContainsKey("CtxWFProfilePath")) return Properties["CtxWFProfilePath"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxWFProfilePath"); return; } if (!Properties.ContainsKey("CtxWFProfilePath")) { Properties.Add("CtxWFProfilePath", new ActiveDirectoryUserParametersProperty()); Properties["CtxWFProfilePath"].Name = "CtxWFProfilePath"; } Properties["CtxWFProfilePath"].SetValueString(value); }
    }

    # 
    # This attribute specifies whether to allow remote observation or remote control of the user's Terminal Services session. The values are as follows:<para>0. Disable</para><para>1. EnableInputNotify</para><para>2. EnableInputNoNotify</para><para>3. EnableNoInputNotify</para><para>4. EnableNoInputNoNotify</para>For a description of these values, see[MSDN - RCMWin32_TSRCS].
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public uint? CtxShadow
    {
        get { if (Properties.ContainsKey("CtxShadow")) return Properties["CtxShadow"].GetValueUInt32(); return null; }
        set { if (!value.HasValue) { Properties.Remove("CtxShadow"); return; } if (!Properties.ContainsKey("CtxShadow")) { Properties.Add("CtxShadow", new ActiveDirectoryUserParametersProperty()); Properties["CtxShadow"].Name = "CtxShadow"; } Properties["CtxShadow"].SetValueUInt32(value.Value); }
    }

    # 
    # This attribute specifies the working directory path for the user. To set an initial application to start when the user logs on to the terminal server, the implementer MUST first set the CtxInitialProgram property, and then set this property.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxWorkDirectory
    {
        get { if (Properties.ContainsKey("CtxWorkDirectory")) return Properties["CtxWorkDirectory"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxWorkDirectory"); return; } if (!Properties.ContainsKey("CtxWorkDirectory")) { Properties.Add("CtxWorkDirectory", new ActiveDirectoryUserParametersProperty()); Properties["CtxWorkDirectory"].Name = "CtxWorkDirectory"; } Properties["CtxWorkDirectory"].SetValueString(value); }
    }

    # 
    # This attribute specifies the call back number provided to the user on the client side for technical support.
    # Returns null if the property does not exist. Creates the property automatically when a value is assigned and deletes it when null is assigned.
    
    public string CtxCallbackNumber
    {
        get { if (Properties.ContainsKey("CtxCallbackNumber")) return Properties["CtxCallbackNumber"].GetValueString(); return null; }
        set { if (value == null) { Properties.Remove("CtxCallbackNumber"); return; } if (!Properties.ContainsKey("CtxCallbackNumber")) { Properties.Add("CtxCallbackNumber", new ActiveDirectoryUserParametersProperty()); Properties["CtxCallbackNumber"].Name = "CtxCallbackNumber"; } Properties["CtxCallbackNumber"].SetValueString(value); }
    }

    # The initial program setting. TRUE indicates the value to use for InitialProgram from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritInitialProgram
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_INITIAL_PROGRAM) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_INITIAL_PROGRAM) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_INITIAL_PROGRAM); }
    }

    # The callback setting. TRUE indicates the value to use for Callback from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritCallback
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_CALLBACK) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_CALLBACK) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_CALLBACK); }
    }

    # The callback number setting. TRUE indicates the value to use for CallbackNumber from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritCallbackNumber
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_CALLBACK_NUMBER) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_CALLBACK_NUMBER) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_CALLBACK_NUMBER); }
    }

    # The shadow setting. TRUE indicates the value to use for Shadow from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritShadow
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_SHADOW) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_SHADOW) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_SHADOW); }
    }

    # The maximum allowed session connection time setting. TRUE indicates the value to use for MaxSessionTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritMaxSessionTime
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_MAX_SESSION_TIME) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_MAX_SESSION_TIME) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_MAX_SESSION_TIME); }
    }

    # The maximum allowed session disconnect time setting. TRUE indicates the value to use for MaxDisconnectionTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritMaxDisconnectionTime
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_MAX_DISCONNECTION_TIME) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_MAX_DISCONNECTION_TIME) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_MAX_DISCONNECTION_TIME); }
    }

    # The maximum allowed session idle time. TRUE indicates the value to use for MaxIdleTime from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritMaxIdleTime
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_MAX_IDLE_TIME) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_MAX_IDLE_TIME) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_MAX_IDLE_TIME); }
    }

    # The auto client setting. TRUE indicates the value to use for fAutoClientDrivers and fAutoClientLpts from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritAutoClient
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_AUTO_CLIENT) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_AUTO_CLIENT) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_AUTO_CLIENT); }
    }

    # Inherit security setting. TRUE indicates the use of security settings from the user properties if the machine/user policy is not set, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool InheritSecurity
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.INHERIT_SECURITY) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.INHERIT_SECURITY) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.INHERIT_SECURITY); }
    }

    # Set to TRUE to ignore the credential sent from the client and always prompt for a password, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool PromptForPassword
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.PROMPT_FOR_PASSWORD) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.PROMPT_FOR_PASSWORD) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.PROMPT_FOR_PASSWORD); }
    }

    # Set to TRUE to log off the session when the idle timers for the session expire. Otherwise, the session will be disconnected when the timer expires.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool ResetBroken
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.RESET_BROKEN) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.RESET_BROKEN) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.RESET_BROKEN); }
    }

    # FALSE indicates that the user can reconnect from any client computer to a disconnected session. TRUE indicates that the user must reconnect to a disconnected session from the same client computer that initially established the disconnected session. Logging on from a different client computer will lead to a new terminal server session being created.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool ReconnectSame
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.RECONNECT_SAME) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.RECONNECT_SAME) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.RECONNECT_SAME); }
    }

    # TRUE indicates that a user cannot log on to a session remotely, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool LogonDisabled
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.LOGON_DISABLED) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.LOGON_DISABLED) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.LOGON_DISABLED); }
    }

    # TRUE specifies to automatically redirect local drives on the client so they are accessible to the user in the remote terminal server session, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool AutoClientDrives
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.AUTO_CLIENT_DRIVES) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.AUTO_CLIENT_DRIVES) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.AUTO_CLIENT_DRIVES); }
    }

    # TRUE specifies to automatically redirect printers on the client so they are accessible to the user in the remote terminal server session, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool AutoClientPrinters
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.AUTO_CLIENT_LPTS) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.AUTO_CLIENT_LPTS) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.AUTO_CLIENT_LPTS); }
    }

    # TRUE indicates to force the client's redirected printer to be the default printer for the user, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool ForceClientPrinterAsDefault
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.FORCE_CLIENT_LPT_DEF) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.FORCE_CLIENT_LPT_DEF) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.FORCE_CLIENT_LPT_DEF); }
    }

    # TRUE indicates the connection does not need encryption, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableEncryption
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_ENCRYPTION) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_ENCRYPTION) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_ENCRYPTION); }
    }

    # Not used.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool HomeDirectoryMapRoot
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.HOME_DIRECTORY_MAP_ROOT) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.HOME_DIRECTORY_MAP_ROOT) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.HOME_DIRECTORY_MAP_ROOT); }
    }

    # TRUE indicates to override a third-party GINA so that only the default GINA is used for the terminal server session, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool UseDefaultGINA
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.USE_DEFAULT_GINA) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.USE_DEFAULT_GINA) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.USE_DEFAULT_GINA); }
    }

    # TRUE indicates disable client printer redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientPrinterRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_CPM) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_CPM) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_CPM); }
    }

    # TRUE indicates disable client drive redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientDriveRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_CDM) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_CDM) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_CDM); }
    }

    # TRUE indicates disable client COM port redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientComPortRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_CCM) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_CCM) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_CCM); }
    }

    # TRUE indicates disable client printer (LPT) port redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientPrinterPortRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_LPT) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_LPT) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_LPT); }
    }

    # TRUE indicates disable client clipboard redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientClipboardRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_CLIP) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_CLIP) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_CLIP); }
    }

    # TRUE indicates disable .exe file execution, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableExeFileExecution
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_EXE) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_EXE) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_EXE); }
    }

    # TRUE indicates display of the desktop wallpaper in the session has been disabled, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableWallpaper
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.WALLPAPER_DISABLED) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.WALLPAPER_DISABLED) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.WALLPAPER_DISABLED); }
    }

    # TRUE indicates disable client audio redirection, FALSE otherwise.
    # Always returns false if the 'CtxCfgFlags1' property does not exist. Creates the 'CtxCfgFlags1' property automatically with the default flags when a value is assigned.
    
    public bool DisableClientAudioRedirection
    {
        get { if (Properties.ContainsKey("CtxCfgFlags1")) return (Properties["CtxCfgFlags1"].GetValueUInt32() & UserConfigFlags.DISABLE_CAM) > 0; return false; }
        set { if (!Properties.ContainsKey("CtxCfgFlags1")) CtxCfgFlags1 = CtxCfgFlags1Default; CtxCfgFlags1 = value ? (Properties["CtxCfgFlags1"].GetValueUInt32() | UserConfigFlags.DISABLE_CAM) : (Properties["CtxCfgFlags1"].GetValueUInt32() & ~UserConfigFlags.DISABLE_CAM); }
    }

    @property
    def value(self):
        properties = b''
        for p in self.tsPropertyArray:
            properties += p.value
        return self.header + self.tsPropertyCount + properties
          
userParam = UserParameters(target='machineAccount',initialProgram='test')
print(userParam.value)
print(encodeValue("Hello World!"))