# Sample Ruby file with vulnerabilities

require 'sinatra'
require 'sqlite3'
require 'erb'

# Hardcoded credentials vulnerability
PASSWORD = "hardcoded_password"

# SQL Injection vulnerability
get '/user/:id' do
  id = params[:id]
  db = SQLite3::Database.new "database.db"
  result = db.execute("SELECT * FROM users WHERE id = #{id}")  # SQL Injection
  result.to_s
end

# Another SQL Injection vulnerability
get '/search' do
  query = params[:q]
  db = SQLite3::Database.new "database.db"
  result = db.execute("SELECT * FROM products WHERE name LIKE '%#{query}%'")  # SQL Injection
  result.to_s
end

# Command injection vulnerability
get '/run' do
  command = params[:cmd]
  result = `ls #{command}`  # Command injection
  result
end

# XSS vulnerability
get '/welcome' do
  name = params[:name]
  "<h1>Welcome, #{name}!</h1>".html_safe  # XSS vulnerability
end

# File access vulnerability
get '/file' do
  filename = params[:filename]
  content = File.read("data/#{filename}")  # File access vulnerability
  content
end

# Mass assignment vulnerability
post '/users' do
  user = User.new(params[:user])  # Mass assignment vulnerability
  user.save
  redirect '/users'
end

# Template injection vulnerability
get '/template' do
  template = params[:template]
  ERB.new(template).result(binding)  # Template injection
end
