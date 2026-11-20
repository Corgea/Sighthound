require "shellwords"

def unsafe(params)
  system("sh -c #{params[:cmd]}") # Unsafe
  system "sh -c #{params[:cmd]}" # Unsafe
  exec("sh -c #{params[:cmd]}") # Unsafe
  spawn("sh -c #{params[:cmd]}") # Unsafe
  Open3.capture2("sh -c #{params[:cmd]}") # Unsafe
  IO.popen("sh -c #{params[:cmd]}") # Unsafe
  
  cmd = params[:cmd]
  system(cmd) # Unsafe (taint)
  system(*cmd) # Unsafe (taint)

  # Explicit shell executions with multiple arguments
  system("sh", "-c", params[:cmd]) # Unsafe (explicit shell)
  system("bash", "-c", params[:cmd]) # Unsafe (explicit shell)
  system("/bin/sh", "-c", params[:cmd]) # Unsafe (explicit shell path)
  system("/usr/bin/bash", "-c", params[:cmd]) # Unsafe (explicit shell path)
  system("powershell", "-Command", params[:cmd]) # Unsafe (powershell -Command flag)
  system("pwsh", "-EncodedCommand", params[:cmd]) # Unsafe (pwsh -EncodedCommand flag)
  system(["sh", "-c", params[:cmd]]) # Unsafe (array literal invoking shell with -c flag)
  exec("sh", "-c", params[:cmd]) # Unsafe (explicit shell)
  spawn("sh", "-c", params[:cmd]) # Unsafe (explicit shell)
  IO.popen("ls -la #{params[:cmd]}", "r") # Unsafe (IO.popen single string command with mode)
  Open3.pipeline("ls", "grep #{params[:cmd]}") # Unsafe (Open3.pipeline with string commands)

  # Explicit shell executions with env hash and options hash
  system({"ENV_VAR" => "val"}, "sh", "-c", params[:cmd]) # Unsafe (explicit shell with env hash)
  system("sh", "-c", params[:cmd], {chdir: "/tmp"}) # Unsafe (explicit shell with options hash)
  system({"ENV_VAR" => "val"}, "sh", "-c", params[:cmd], {chdir: "/tmp"}) # Unsafe (explicit shell with env and options hash)
  system({"ENV_VAR" => "val"}, "bash", "-lc", params[:cmd]) # Unsafe (explicit shell with clustered -lc flag)
  system({"ENV_VAR" => "val"}, "sh", "-ec", params[:cmd]) # Unsafe (explicit shell with clustered -ec flag)
  
  User.where("id = #{params[:id]}")
end
