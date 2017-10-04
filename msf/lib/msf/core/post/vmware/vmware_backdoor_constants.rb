module Msf
class  Post
module Vmware
module Constants
  # from backdoor_def.h
  BDOOR_MAGIC                         = 0x564D5868

  # Low-bandwidth backdoor port
  BDOOR_PORT                          = 0x5658

  # High-bandwidth backdoor port*/
  BDOORHB_PORT                        = 0x5659
  BDOORHB_CMD_MESSAGE                 = 0
  BDOORHB_CMD_VASSERT                 = 1
  BDOORHB_CMD_MAX                     = 2

  BDOOR_CMD_GETMHZ                    =   1
  BDOOR_CMD_APMFUNCTION               =   2 # CPL= 0 only.
  BDOOR_CMD_GETDISKGEO                =   3
  BDOOR_CMD_GETPTRLOCATION            =   4
  BDOOR_CMD_SETPTRLOCATION            =   5
  BDOOR_CMD_GETSELLENGTH              =   6
  BDOOR_CMD_GETNEXTPIECE              =   7
  BDOOR_CMD_SETSELLENGTH              =   8
  BDOOR_CMD_SETNEXTPIECE              =   9
  BDOOR_CMD_GETVERSION                =  10
  BDOOR_CMD_GETDEVICELISTELEMENT      =  11
  BDOOR_CMD_TOGGLEDEVICE              =  12
  BDOOR_CMD_GETGUIOPTIONS             =  13
  BDOOR_CMD_SETGUIOPTIONS             =  14
  BDOOR_CMD_GETSCREENSIZE             =  15
  BDOOR_CMD_MONITOR_CONTROL           =  16 # Disabled by default.
  BDOOR_CMD_GETHWVERSION              =  17
  BDOOR_CMD_OSNOTFOUND                =  18 # CPL= 0 only.
  BDOOR_CMD_GETUUID                   =  19
  BDOOR_CMD_GETMEMSIZE                =  20
  BDOOR_CMD_HOSTCOPY                  =  21 # Devel only.

  BDOOR_CMD_GETTIME                   =  23 # Deprecated -> GETTIMEFULL.
  BDOOR_CMD_STOPCATCHUP               =  24
  BDOOR_CMD_PUTCHR                    =  25 # Disabled by default.
  BDOOR_CMD_ENABLE_MSG                =  26 # Devel only.
  BDOOR_CMD_GOTO_TCL                  =  27 # Devel only.
  BDOOR_CMD_INITPCIOPROM              =  28 # CPL = 0 only.

  BDOOR_CMD_MESSAGE                   =  30 # 0x1e
  BDOOR_CMD_SIDT                      =  31
  BDOOR_CMD_SGDT                      =  32
  BDOOR_CMD_SLDT_STR                  =  33
  BDOOR_CMD_ISACPIDISABLED            =  34

  BDOOR_CMD_ISMOUSEABSOLUTE           =  36
  BDOOR_CMD_PATCH_SMBIOS_STRUCTS      =  37 # CPL = 0 only.
  BDOOR_CMD_MAPMEM                    =  38 # Devel only
  BDOOR_CMD_ABSPOINTER_DATA           =  39
  BDOOR_CMD_ABSPOINTER_STATUS         =  40
  BDOOR_CMD_ABSPOINTER_COMMAND        =  41

  BDOOR_CMD_PATCH_ACPI_TABLES         =  43 # CPL = 0 only.

  BDOOR_CMD_GETHZ                     =  45
  BDOOR_CMD_GETTIMEFULL               =  46

  BDOOR_CMD_CHECKFORCEBIOSSETUP       =  48 # CPL = 0 only.
  BDOOR_CMD_LAZYTIMEREMULATION        =  49 # CPL = 0 only.
  BDOOR_CMD_BIOSBBS                   =  50 # CPL = 0 only.

  BDOOR_CMD_ISGOSDARWIN               =  52
  BDOOR_CMD_DEBUGEVENT                =  53
  BDOOR_CMD_OSNOTMACOSXSERVER         =  54 # CPL = 0 only.
  BDOOR_CMD_GETTIMEFULL_WITH_LAG      =  55
  BDOOR_CMD_ACPI_HOTPLUG_DEVICE       =  56 # Devel only.
  BDOOR_CMD_ACPI_HOTPLUG_MEMORY       =  57 # Devel only.
  BDOOR_CMD_ACPI_HOTPLUG_CBRET        =  58 # Devel only.

  BDOOR_CMD_ACPI_HOTPLUG_CPU          =  60 # Devel only.

  BDOOR_CMD_XPMODE                    =  62 # CPL = 0 only.
  BDOOR_CMD_NESTING_CONTROL           =  63
  BDOOR_CMD_FIRMWARE_INIT             =  64 # CPL = 0 only.
  BDOOR_CMD_FIRMWARE_ACPI_SERVICES    =  65 # CPL = 0 only.
  BDOOR_CMD_FAS_GET_TABLE_SIZE        =   0
  BDOOR_CMD_FAS_GET_TABLE_DATA        =   1
  BDOOR_CMD_FAS_GET_PLATFORM_NAME     =   2
  BDOOR_CMD_FAS_GET_PCIE_OSC_MASK     =   3
  BDOOR_CMD_FAS_GET_APIC_ROUTING      =   4
  BDOOR_CMD_FAS_GET_TABLE_SKIP        =   5
  BDOOR_CMD_FAS_GET_SLEEP_ENABLES     =   6
  BDOOR_CMD_FAS_GET_HARD_RESET_ENABLE =   7
  BDOOR_CMD_FAS_GET_MOUSE_HID         =   8
  BDOOR_CMD_FAS_GET_SMBIOS_VERSION    =   9
  BDOOR_CMD_SENDPSHAREHINTS           =  66 # Not in use. Deprecated.
  BDOOR_CMD_ENABLE_USB_MOUSE          =  67
  BDOOR_CMD_GET_VCPU_INFO             =  68
  BDOOR_CMD_VCPU_SLC64                =   0
  BDOOR_CMD_VCPU_SYNC_VTSCS           =   1
  BDOOR_CMD_VCPU_HV_REPLAY_OK         =   2
  BDOOR_CMD_VCPU_LEGACY_X2APIC_OK     =   3
  BDOOR_CMD_VCPU_MMIO_HONORS_PAT      =   4
  BDOOR_CMD_VCPU_RESERVED             =  31
  BDOOR_CMD_EFI_SERIALCON_CONFIG      =  69 # CPL = 0 only.
  BDOOR_CMD_BUG328986                 =  70 # CPL = 0 only.
  BDOOR_CMD_FIRMWARE_ERROR            =  71 # CPL = 0 only.
  BDOOR_CMD_FE_INSUFFICIENT_MEM       =   0
  BDOOR_CMD_FE_EXCEPTION              =   1
  BDOOR_CMD_VMK_INFO                  =  72
  BDOOR_CMD_EFI_BOOT_CONFIG           =  73 # CPL = 0 only.
  BDOOR_CMD_EBC_LEGACYBOOT_ENABLED        = 0
  BDOOR_CMD_EBC_GET_ORDER                 = 1
  BDOOR_CMD_EBC_SHELL_ACTIVE              = 2
  BDOOR_CMD_EBC_GET_NETWORK_BOOT_PROTOCOL = 3
  BDOOR_CMD_EBC_QUICKBOOT_ENABLED         = 4
  BDOOR_CMD_GET_HW_MODEL              =  74 # CPL = 0 only.
  BDOOR_CMD_GET_SVGA_CAPABILITIES     =  75 # CPL = 0 only.
  BDOOR_CMD_GET_FORCE_X2APIC          =  76 # CPL = 0 only
  BDOOR_CMD_SET_PCI_HOLE              =  77 # CPL = 0 only
  BDOOR_CMD_GET_PCI_HOLE              =  78 # CPL = 0 only
  BDOOR_CMD_GET_PCI_BAR               =  79 # CPL = 0 only
  BDOOR_CMD_SHOULD_GENERATE_SYSTEMID  =  80 # CPL = 0 only
  BDOOR_CMD_READ_DEBUG_FILE           =  81 # Devel only.
  BDOOR_CMD_SCREENSHOT                =  82 # Devel only.
  BDOOR_CMD_INJECT_KEY                =  83 # Devel only.
  BDOOR_CMD_INJECT_MOUSE              =  84 # Devel only.
  BDOOR_CMD_MKS_GUEST_STATS           =  85 # CPL = 0 only.
  BDOOR_CMD_MKSGS_RESET               =   0
  BDOOR_CMD_MKSGS_ADD_PPN             =   1
  BDOOR_CMD_MKSGS_REMOVE_PPN          =   2
  BDOOR_CMD_ABSPOINTER_RESTRICT       =  86
  BDOOR_CMD_GUEST_INTEGRITY           =  87
  BDOOR_CMD_GI_GET_CAPABILITIES       =   0
  BDOOR_CMD_GI_SETUP_ENTRY_POINT      =   1
  BDOOR_CMD_GI_SETUP_ALERTS           =   2
  BDOOR_CMD_GI_SETUP_STORE            =   3
  BDOOR_CMD_GI_SETUP_EVENT_RING       =   4
  BDOOR_CMD_GI_SETUP_NON_FAULT_READ   =   5
  BDOOR_CMD_GI_ENTER_INTEGRITY_MODE   =   6
  BDOOR_CMD_GI_EXIT_INTEGRITY_MODE    =   7
  BDOOR_CMD_GI_RESET_INTEGRITY_MODE   =   8
  BDOOR_CMD_GI_GET_EVENT_RING_STATE   =   9
  BDOOR_CMD_GI_CONSUME_RING_EVENTS    =  10
  BDOOR_CMD_GI_WATCH_MAPPINGS_START   =  11
  BDOOR_CMD_GI_WATCH_MAPPINGS_STOP    =  12
  BDOOR_CMD_GI_CHECK_MAPPINGS_NOW     =  13
  BDOOR_CMD_GI_WATCH_PPNS_START       =  14
  BDOOR_CMD_GI_WATCH_PPNS_STOP        =  15
  BDOOR_CMD_GI_SEND_MSG               =  16
  BDOOR_CMD_GI_TEST_READ_MOB          = 128
  BDOOR_CMD_GI_TEST_ADD_EVENT         = 129
  BDOOR_CMD_GI_TEST_MAPPING           = 130
  BDOOR_CMD_GI_TEST_PPN               = 131
  BDOOR_CMD_GI_MAX                    = 131
  BDOOR_CMD_MKSSTATS_SNAPSHOT         =  88 # Devel only.
  BDOOR_CMD_MKSSTATS_START            =   0
  BDOOR_CMD_MKSSTATS_STOP             =   1
  BDOOR_CMD_SECUREBOOT                =  89
  BDOOR_CMD_COPY_PHYSMEM              =  90 # Devel only.
  BDOOR_CMD_MAX                       =  91

  # from various other sources in open_vm_tools
  RPCI_PROTOCOL_NUM                   = 0x49435052 # 'RPCI'
  GUESTMSG_FLAG_COOKIE                = 0x80000000
  MESSAGE_TYPE_SENDSIZE               = 0x10000
  MESSAGE_TYPE_CLOSE                  = 0x60000

#    MESSAGE_TYPE_OPEN,
#    MESSAGE_TYPE_SENDSIZE,
#    MESSAGE_TYPE_SENDPAYLOAD,
#    MESSAGE_TYPE_RECVSIZE,
#    MESSAGE_TYPE_RECVPAYLOAD,
#    MESSAGE_TYPE_RECVSTATUS,
#    MESSAGE_TYPE_CLOSE,

  # # Nesting control operations 
  # NESTING_CONTROL_RESTRICT_BACKDOOR     = 0
  # NESTING_CONTROL_OPEN_BACKDOOR         = 1
  # NESTING_CONTROL_QUERY                 = 2
  # NESTING_CONTROL_MAX                   = 2

  # # EFI Boot Order options, nibble-sized. 
  # EFI_BOOT_ORDER_TYPE_EFI               = 0x0
  # EFI_BOOT_ORDER_TYPE_LEGACY            = 0x1
  # EFI_BOOT_ORDER_TYPE_NONE              = 0xf

  # BDOOR_NETWORK_BOOT_PROTOCOL_NONE      = 0x0
  # BDOOR_NETWORK_BOOT_PROTOCOL_IPV4      = 0x1
  # BDOOR_NETWORK_BOOT_PROTOCOL_IPV6      = 0x2

  # #BDOOR_SECUREBOOT_STATUS_DISABLED      = 0xFFFFFFFFUL
  # BDOOR_SECUREBOOT_STATUS_APPROVED      = 1
  # BDOOR_SECUREBOOT_STATUS_DENIED        = 2

  # #
  # # There is another backdoor which allows access to certain TSC-related
  # # values using otherwise illegal PMC indices when the pseudo_perfctr
  # # control flag is set.
  # BDOOR_PMC_HW_TSC          = 0x10000
  # BDOOR_PMC_REAL_NS         = 0x10001
  # BDOOR_PMC_APPARENT_NS     = 0x10002
  # BDOOR_PMC_PSEUDO_TSC      = 0x10003

  # #IS_BDOOR_PMC(index)  (((index) | 3) == 0x10003)
  # #BDOOR_CMD(ecx)       ((ecx) & 0xffff)

  # # Sub commands for BDOOR_CMD_VMK_INFO 
  # BDOOR_CMD_VMK_INFO_ENTRY       = 1
end
end
end
end
