require "shellwords"

def unsafe(params)
  system("sh -c #{params[:cmd]}")
  User.where("id = #{params[:id]}")
end
