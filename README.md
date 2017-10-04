# DerbyCon 2017 Presentation VMware Escapology: How to Houdini the Hypervisor

### Experimental Metasploit Framework Code
 
  ## WARNING
  
  This is very much an unstable work in progress and is presented for 
  demonstration purposes only. It is currently not considered "production-ready" 
  for inclusion in the Metasploit Framework. For example, this code results
  in a memory leak on the targeted process. This is a known issue. Attempts
  to free the allocated memory currently result in a timeout condition.
  
  **Once it is stable, a pull request will be created.**
  
  ## WARNING

 If testing, the main steps:
  * `$cp vmware.rb metasploit-framework/lib/msf/core/post/vmware.rb`
  * and either edit `metasploit-framework/lib/msf/core/post.rb` to require vmware.rb
  * AND/OR `irb> Kernel.load "metasploit-framework/lib/msf/core/post/vmware.rb"`
