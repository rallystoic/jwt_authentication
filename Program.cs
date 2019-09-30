using System;
using System.Collections.Generic;
using System.Linq;
namespace authsystem
{
    class Program
    {
        static void Main(string[] args)
        {
		// username  hardcoded//////////////////////////////////////
		string Username = "jojo";
		string Userpassword = "123456";
		Console.WriteLine($"{Username} : {Userpassword}");
		//////////////////////Next section///////////////////////
	
                Authenticationjwt authenticate = new Authenticationjwt(); 
              authenticate.Autentication(Username,Userpassword);
                
        }
	
    }

}
