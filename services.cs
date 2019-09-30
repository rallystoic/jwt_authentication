using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
// For generating a tokens
using Microsoft.IdentityModel.Tokens; 
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
//




namespace authsystem
{
    public class Authenticationjwt
    {

    public void creatuser(string username, string userpassword)
    {
       

        // random salt and decode to 64basestring 
        byte[] Randomsalt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(Randomsalt);
        }
        // after random this salt byte 
        // convert salt byte to base 64string and convert back to a byte
        // if we didnt  use this methode the authentication methode will fail
    string saltTostring = Convert.ToBase64String(Randomsalt);
        byte[] getBytesalt = Encoding.ASCII.GetBytes(saltTostring);


       string Hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: userpassword,
            salt: getBytesalt,
            // hmascha256 ,
            prf : KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 256 / 8));
            var salted = Convert.ToBase64String(Randomsalt); 
            Console.WriteLine(salted);
       /// after this process  we keep username,userpassword salt(randomed) and hashed result to database
       /// datetime  of this is optional ! 
             using (var db = new  AuthenticationContext())
             {
                 var newuser = new user { username = username,salt = salted,hashed = Hashed };
                 db.users.Add(newuser);
                db.SaveChanges();
             }
            
        
    }
    /// this is authentication process if user is valid then we generate a token for a valiaded user!
    /// we use system.linq to query user and password in the database(sqlite3) 
    /// if user existed in the the database , provided a salt from a database to be hashed with password
    /// if hased from the request matched a hashed from database then the requested user is valid  ! so we provid a token !
    public void Autentication(string Username,string Userpassword)
    {
            using (var db = new  AuthenticationContext())
            {
               user ThisUser = db.users.FirstOrDefault(x=> x.username == Username);
                {
                    if (ThisUser == null)
                    {
                        // return error!
                        Console.WriteLine("username or password invalid");
                    }
                    else
                    {
                        // change salt string to salt byte format with saltx variable
                        Byte[] saltx = Encoding.ASCII.GetBytes(ThisUser.salt);

                        
                            // client send a password to be hashed with a salt from user stored in database
                         string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                         password: Userpassword,
                         salt: saltx,
                        // prf: KeyDerivationPrf.HMACSHA1,
                        prf : KeyDerivationPrf.HMACSHA256,
                            iterationCount: 10000,
                        numBytesRequested: 256 / 8));
                        bool isvalid = hashed.Equals(ThisUser.hashed);
                        System.Console.WriteLine(isvalid);
                             if(isvalid == false)
                    {
                             System.Console.WriteLine("Username or password invalide!");
                             
                            
                    }
                    else
                    {
                        // this is a test we do not hardcode our secret 
                        string secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                        // byte key will be use inside tokendesriptor()
                        var key = Encoding.ASCII.GetBytes(secret);
                             	var Jwtokenmaker =  new JwtSecurityTokenHandler();

                        //there are more than one clain we going to make a list of claims
                                 	IList<Claim> claimcollection = new List<Claim>
                       {
			                            new Claim(ClaimTypes.Name,ThisUser.username),
			                            new Claim(ClaimTypes.Role,ThisUser.role),

		                };

                        // listof claim (claincollection) need to be parse inside claimidentity()

                        ClaimsIdentity myclaim = new ClaimsIdentity();
                        myclaim.AddClaims(claimcollection);

                                 var tokendescriptor = new SecurityTokenDescriptor
	                    {
                                
                                    Subject = myclaim,
                                    Expires = DateTime.Now.AddHours(4),
                                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)	
	                        };
                                // now creat a token with  tokendescriptor!
                       
                        	var token  = Jwtokenmaker.CreateToken(tokendescriptor);
                            
                            //write token 
                            	var result = Jwtokenmaker.WriteToken(token);

                         System.Console.WriteLine("welcome {0}",ThisUser.username);
                         System.Console.WriteLine("Token : {0}",token);
                         System.Console.WriteLine("Token : {0}",result);
                    }
                       
                    }
               
                    
                
                }
            }

    }


    }
}
