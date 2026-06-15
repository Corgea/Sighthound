require "shellwords"

def safe(params)
  system("ls", Shellwords.escape(params[:cmd]))
  User.where("id = ?", params[:id].to_i)
end
