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
  # $cp vmware.rb metasploit-framework/lib/msf/core/post/vmware.
  # $cp -r vmware metasploit-framework/lib/msf/core/post/
  # and either edit metasploit-framework/lib/msf/core/post.rb to:
  # require 'msf/core/post/vmware'
  # AND/OR (esp if framework is already loaded)
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
    asm_cmd(BDOOR_CMD_MESSAGE|MESSAGE_TYPE_CLOSE)
  end

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

