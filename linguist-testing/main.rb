#!/usr/bin/env ruby

require 'sqlite3'
require 'webrick'
require 'json'

# Simple web server with SQL injection vulnerability for CodeQL testing
class VulnerableApp
  def initialize
    @db = SQLite3::Database.new ':memory:'
    setup_database
  end

  def setup_database
    @db.execute <<-SQL
      CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT
      );
    SQL

    @db.execute "INSERT INTO users (username, password, email) VALUES ('admin', 'secret123', 'admin@test.com')"
    @db.execute "INSERT INTO users (username, password, email) VALUES ('user1', 'pass456', 'user1@test.com')"
  end

  def login(username, password)
    # VULNERABLE: Direct string interpolation creates SQL injection
    query = "SELECT * FROM users WHERE username = '#{username}' AND password = '#{password}'"
    puts "Executing query: #{query}"
    
    result = @db.execute(query)
    return result.length > 0
  end

  def get_user_info(user_id)
    # VULNERABLE: Direct concatenation allows SQL injection
    query = "SELECT username, email FROM users WHERE id = " + user_id.to_s
    puts "Executing query: #{query}"
    
    @db.execute(query)
  end

  def search_users(search_term)
    # VULNERABLE: String formatting with user input
    query = "SELECT username FROM users WHERE username LIKE '%#{search_term}%'"
    puts "Executing query: #{query}"
    
    @db.execute(query)
  end
end

# Example usage demonstrating the vulnerabilities
app = VulnerableApp.new

puts "=== Testing SQL Injection Vulnerabilities ==="

# Normal usage
puts "\n1. Normal login:"
result = app.login("admin", "secret123")
puts "Login successful: #{result}"

# SQL injection in login (bypass authentication)
puts "\n2. SQL injection in login:"
malicious_input = "admin' OR '1'='1' --"
result = app.login(malicious_input, "anything")
puts "Login successful with injection: #{result}"

# SQL injection in user info lookup
puts "\n3. SQL injection in user lookup:"
malicious_id = "1 UNION SELECT password, 'hacked' FROM users --"
result = app.get_user_info(malicious_id)
puts "User info result: #{result}"

# SQL injection in search
puts "\n4. SQL injection in search:"
malicious_search = "test' UNION SELECT password FROM users --"
result = app.search_users(malicious_search)
puts "Search result: #{result}"