using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Sqlite;
using Microsoft.EntityFrameworkCore.Design;
namespace authsystem
{
	public class AuthenticationContext : DbContext
	{
		public DbSet<user> users {get;set;}
		  protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<user>()
                .HasKey(c => c.user_id);
        }
		protected override void OnConfiguring(DbContextOptionsBuilder options)
			            => options.UseSqlite("Data Source=authenticateDB.db");
		
	}		
	



	public class user
	{
		public int user_id {get;set;}
		public string  username {get;set;}
		public string  salt {get;set;}
		public string  hashed {get;set;}
		public string  role {get;set;}
	}


}
