import "pe"
import "dotnet"

private rule _mpfs_valid_pe_header
{
    condition:
        filesize > 512 and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

rule MPFS_STRICT_KnownCheatArtifacts_PE : cheat pe lowfp
{
    meta:
        description = "Strict low-FP detection of known cheat loaders/clients in PE files only"
        author = "Jumarf"
        date = "2026-04-08"

    strings:
        $brand1 = "Exodus.codes" nocase ascii wide
        $brand2 = "slinky.gg" nocase ascii wide
        $brand3 = "vape.gg" nocase ascii wide
        $brand4 = "lithiumclient.wtf" nocase ascii wide
        $brand5 = "discord.gg/advantages" nocase ascii wide

        $dll1 = "slinkyhook.dll" nocase ascii wide
        $dll2 = "slinky_library.dll" nocase ascii wide
        $dll3 = "breeze.dll" nocase ascii wide

        $msg1 = "[!] Failed to find Vape jar" nocase ascii wide
        $msg2 = "Vape Launcher" nocase ascii wide
        $msg3 = "Open Minecraft, then try again." nocase ascii wide
        $msg4 = "Adding delay to Minecraft" nocase ascii wide

        $name1 = "Cracked by Kangaroo" nocase ascii wide
        $name2 = "Sapphire LITE Clicker" nocase ascii wide
        $name3 = "Monolith Lite" nocase ascii wide
        $name4 = "UNICORN CLIENT" nocase ascii wide
        $name5 = "UwU Client" nocase ascii wide
        $name6 = "dream-injector" nocase ascii wide
        $name7 = "VROOMCLICKER" nocase ascii wide

        $pdb1 = "C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3.pdb" nocase ascii wide
        $pdb2 = "C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external.pdb" nocase ascii wide
        $pdb3 = "C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal.pdb" nocase ascii wide
        $pdb4 = "C:\\Users\\DeathZ\\source\\repos\\StarDLL\\x64\\Release\\MoonDLL.pdb" nocase ascii wide
        $pdb5 = "C:\\Users\\mella\\source\\repos\\Fox v2\\x64\\Release\\Fox.pdb" nocase ascii wide
        $pdb6 = "C:\\Users\\hyeox\\Desktop\\imgui-master\\examples\\example_win32_directx9\\Release\\icetea_dx9_final.pdb" nocase ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            any of ($pdb*) or
            2 of ($dll*, $msg*, $name*) or
            2 of ($brand*)
        )
}

rule MPFS_STRICT_NativeClicker_PE : cheat pe lowfp
{
    meta:
        description = "Strict native clicker detection via combined synthetic-input imports"
        author = "Jumarf"
        date = "2026-04-08"

    condition:
        pe.is_pe and
        not dotnet.is_dotnet and
        filesize <= 67108864 and
        pe.number_of_imported_functions <= 140 and
        (
            pe.imports("user32.dll", "SendInput") or
            pe.imports("user32.dll", "mouse_event")
        ) and
        (
            pe.imports("user32.dll", "GetAsyncKeyState") or
            pe.imports("user32.dll", "GetKeyState")
        ) and
        (
            pe.imports("user32.dll", "SetCursorPos") or
            pe.imports("user32.dll", "mouse_event") or
            pe.imports("user32.dll", "SendInput")
        )
}

rule MPFS_STRICT_DotNetClicker_PE : cheat pe dotnet lowfp
{
    meta:
        description = "Strict .NET clicker detection via API plus UI keyword combinations"
        author = "Jumarf"
        date = "2026-04-08"

    strings:
        $inj1 = "SendInput" ascii wide
        $inj2 = "mouse_event" ascii wide
        $inj3 = "SetCursorPos" ascii wide

        $key1 = "GetAsyncKeyState" ascii wide
        $key2 = "GetKeyState" ascii wide

        $kw1 = "AutoClicker" nocase ascii wide
        $kw2 = "Click Interval" nocase ascii wide
        $kw3 = "Start Clicking" nocase ascii wide
        $kw4 = "Stop Clicking" nocase ascii wide
        $kw5 = "Jitter Click" nocase ascii wide
        $kw6 = "Butterfly Click" nocase ascii wide
        $kw7 = "Double Clicker" nocase ascii wide
        $kw8 = "String Cleaner" nocase ascii wide

    condition:
        pe.is_pe and
        dotnet.is_dotnet and
        filesize <= 67108864 and
        1 of ($inj*) and
        1 of ($key*) and
        1 of ($kw*)
}

rule MPFS_STRICT_Injector_ManualMap_PE : injector hacktool pe lowfp
{
    meta:
        description = "Strict PE-only detection of injectors and manual-map loaders"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://github.com/DarthTon/Blackbone"
        source2 = "https://github.com/DarthTon/Xenos"
        source3 = "https://github.com/Neo23x0/signature-base"

    strings:
        $msg1 = "Injecting DLL: %ls into PID: %d" ascii wide
        $msg2 = "Cannot write the shellcode in the process memory, error:" ascii wide
        $msg3 = "/d dll_file PID: dll injection via LoadLibrary()." ascii wide
        $msg4 = "Error injecting remote thread in process:" ascii wide
        $msg5 = "No injection target has been provided!" ascii wide
        $msg6 = "BBInjectDll" ascii wide
        $msg7 = "BlackBone: %s: APC injection failed with status 0x%X" ascii wide
        $msg8 = "%s: Invalid injection type specified - %d" ascii wide
        $msg9 = "Specify -l to list all IE processes running in the current session" ascii wide

        $api1 = "CreateRemoteThread" ascii wide
        $api2 = "NtCreateThreadEx" ascii wide
        $api3 = "WriteProcessMemory" ascii wide
        $api4 = "VirtualAllocEx" ascii wide
        $api5 = "LoadLibraryA" ascii wide
        $api6 = "LoadLibraryW" ascii wide
        $api7 = "LdrLoadDll" ascii wide

        $trait1 = "ManualMap" ascii wide
        $trait2 = "ReflectiveLoader" ascii wide
        $trait3 = "InjectDLL" ascii wide
        $trait4 = "shellcode injection" ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            2 of ($msg*) or
            ($msg6 and $api7 and 1 of ($msg7,$msg8)) or
            (4 of ($api*) and 1 of ($trait*))
        )
}

rule MPFS_STRICT_CheatEngine_PE : cheat pe lowfp
{
    meta:
        description = "Strict PE-only Cheat Engine detection to avoid LNK/cache false positives"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://github.com/cheat-engine/cheat-engine"
        source2 = "https://github.com/cheat-engine/cheat-engine/releases"

    strings:
        $ce_name = "Cheat Engine" nocase ascii wide
        $ce_exe = "Cheat Engine.exe" nocase ascii wide
        $ce_drv1 = "dbk64.sys" nocase ascii wide
        $ce_drv2 = "dbk32.sys" nocase ascii wide
        $ce_dll1 = "speedhack-i386.dll" nocase ascii wide
        $ce_dll2 = "speedhack-x86_64.dll" nocase ascii wide
        $ce_dll3 = "vehdebug-i386.dll" nocase ascii wide
        $ce_dll4 = "vehdebug-x86_64.dll" nocase ascii wide
        $ce_misc1 = "tutorial-i386.exe" nocase ascii wide
        $ce_misc2 = "tutorial-x86_64.exe" nocase ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            any of ($ce_drv*, $ce_dll*, $ce_misc*) or
            ($ce_name and 1 of ($ce_drv*, $ce_dll*, $ce_misc*)) or
            $ce_exe
        )
}

rule MPFS_STRICT_KDMapper_VulnDriver_PE : cheat hacktool kernel pe lowfp
{
    meta:
        description = "Strict PE-only detection of kdmapper and vulnerable-driver loader ecosystems"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://github.com/TheCruZ/kdmapper"
        source2 = "https://github.com/hfiref0x/KDU"

    strings:
        $map1 = "kdmapper" nocase ascii wide
        $map2 = "iqvw64e.sys" nocase ascii wide
        $map3 = "\\Device\\Nal" nocase ascii wide
        $map4 = "MmUnloadedDrivers" nocase ascii wide
        $map5 = "PiDDBCacheTable" nocase ascii wide
        $map6 = "g_KernelHashBucketList" nocase ascii wide
        $map7 = "Wdfilter RuntimeDriverList" nocase ascii wide
        $map8 = "capcom.sys" nocase ascii wide
        $map9 = "gdrv.sys" nocase ascii wide
        $map10 = "dbutil_2_3.sys" nocase ascii wide
        $map11 = "RTCore64.sys" nocase ascii wide
        $map12 = "WinRing0x64.sys" nocase ascii wide
        $map13 = "WinRing0.sys" nocase ascii wide
        $map14 = "AsIO.sys" nocase ascii wide
        $map15 = "AsIO2.sys" nocase ascii wide
        $map16 = "AsUpIO.sys" nocase ascii wide
        $map17 = "eneio64.sys" nocase ascii wide
        $map18 = "MSIO64.sys" nocase ascii wide
        $map19 = "NTIOLib_X64.sys" nocase ascii wide
        $map20 = "nvoclock.sys" nocase ascii wide
        $api1 = "NtLoadDriver" ascii wide
        $api2 = "NtUnloadDriver" ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            2 of ($map*) or
            (1 of ($map*) and 1 of ($api*)) or
            ($map1 and 1 of ($map2,$map3,$map4,$map5,$map6,$map7))
        )
}

rule MPFS_STRICT_Clumsy_PE : network_tool prohibited_game_tool pe lowfp
{
    meta:
        description = "Strict PE-only detection of clumsy"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://github.com/jagt/clumsy"
        source2 = "https://raw.githubusercontent.com/jagt/clumsy/master/src/main.c"

    strings:
        $event1 = "Global\\CLUMSY_IS_RUNNING_EVENT_NAME" ascii wide
        $msg1 = "Theres' already an instance of clumsy running." ascii wide
        $msg2 = "You're running 32bit clumsy on 64bit Windows, which wouldn't work. Please use the 64bit clumsy version." ascii wide
        $msg3 = "Started filtering. Enable functionalities to take effect." ascii wide
        $msg4 = "Stopped. To begin again, edit criteria and click Start." ascii wide
        $ui1 = "loopback packets" ascii wide
        $ui2 = "NOTICE: When capturing localhost (loopback) packets, you CAN'T include inbound criteria." ascii wide
        $ui3 = "Filters like 'udp' need to be 'udp and outbound' to work. See readme for more info." ascii wide
        $ui4 = "clumsy " ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            $event1 or
            (1 of ($msg*) and 1 of ($ui*)) or
            ($ui4 and 2 of ($msg*,$ui1,$ui2,$ui3))
        )
}

rule MPFS_STRICT_NetLimiter_PE : network_tool prohibited_game_tool pe lowfp
{
    meta:
        description = "Strict PE-only detection of NetLimiter"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://www.netlimiter.com/docs/internals/3-netlimiter-components"
        source2 = "https://netlimiter.com/docs/installation/purchase-and-registration"

    strings:
        $brand = "NetLimiter" ascii wide
        $vendor = "Locktime Software" ascii wide
        $exe1 = "NLClientApp.exe" ascii wide
        $exe2 = "NLDiag.exe" ascii wide
        $svc1 = "nlsvc.exe" ascii wide
        $svc2 = "nlsvc" ascii wide fullword
        $drv1 = "nldrv" ascii wide fullword
        $api1 = "NetLimiter.Service.NLClient" ascii wide
        $api2 = "NetLimiter.Service.NLService" ascii wide
        $path1 = "C:\\Program Files\\Locktime Software\\NetLimiter\\NetLimiter.dll" ascii wide
        $path2 = "C:\\Program Files\\Locktime Software\\NetLimiter 4\\NetLimiter.dll" ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            ($brand and 1 of ($exe*,$svc*,$drv*,$api*,$path*)) or
            ($vendor and 2 of ($exe*,$svc*,$drv*,$api*,$path*))
        )
}

rule MPFS_STRICT_NoPing_PE : network_tool prohibited_game_tool pe lowfp
{
    meta:
        description = "Strict PE-only detection of NoPing"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://noping.com/"
        source2 = "https://noping.com/en/blog/new-noping-how-to-set-up-with-a-click"

    strings:
        $brand1 = "NoPing" ascii wide
        $brand2 = "NoPing Game Booster" ascii wide
        $dom1 = "noping.com" ascii wide
        $dom2 = "nptunnel.com" ascii wide
        $ui1 = "Optimize this game" ascii wide
        $ui2 = "Optimize Game" ascii wide
        $ui3 = "Turbo Games" ascii wide
        $ui4 = "Smart Exit" ascii wide
        $ui5 = "Start NoPing with Windows" ascii wide
        $ui6 = "Windows Packet Filter" ascii wide
        $ui7 = "Game Statistics" ascii wide
        $ui8 = "DISCONNECT" ascii wide
        $ui9 = "Select the server" ascii wide
        $feat1 = "Multi Connection" ascii wide
        $feat2 = "Multi Internet" ascii wide
        $feat3 = "AI Route Calculation" ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            (1 of ($brand*) and 2 of ($ui*)) or
            (1 of ($brand*,$dom1,$dom2) and 2 of ($feat*)) or
            ($brand1 and 1 of ($feat*) and 1 of ($ui*))
        )
}

rule MPFS_STRICT_ExitLag_PE : network_tool prohibited_game_tool pe lowfp
{
    meta:
        description = "Strict PE-only detection of ExitLag"
        author = "Jumarf"
        date = "2026-04-08"
        source1 = "https://www.exitlag.com/how-it-works"
        source2 = "https://webhook.exitlag.com/pricing"

    strings:
        $brand1 = "ExitLag" ascii wide
        $dom1 = "exitlag.com" ascii wide
        $ui1 = "Apply Routes" ascii wide
        $ui2 = "CONNECTED" ascii wide
        $ui3 = "Choose a region or server" ascii wide
        $ui4 = "Automatic choice" ascii wide
        $ui5 = "ExitLag ON" ascii wide
        $feat1 = "Multipath Connection" ascii wide
        $feat2 = "Multi Internet" ascii wide
        $feat3 = "FPS Boost" ascii wide
        $feat4 = "Traffic Shaper" ascii wide
        $feat5 = "Network Analyzer" ascii wide
        $feat6 = "RAM Cleaner" ascii wide

    condition:
        _mpfs_valid_pe_header and
        (
            ($brand1 and 2 of ($ui*)) or
            (1 of ($brand1,$dom1) and 2 of ($feat*)) or
            ($brand1 and $ui1 and 1 of ($feat*))
        )
}
