using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthProject.Models;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using BCrypt.Net;
using Microsoft.AspNetCore.Http;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;

namespace AuthProject.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly AuthContext auth;
        private readonly IConfiguration _config; 
        public AuthenticationController(AuthContext _auth, IConfiguration config)
        {
            auth = _auth;
            _config = config;
        }
        public IActionResult Login()
        {
            return View();
        }
        public IActionResult Register()
        {
            return View();
        }



        [HttpPost]
        public IActionResult Register(Users input)
        {
            var dupUsername = auth.Users.Any(d=>d.UserName==input.UserName);
            var dupEmail = auth.Users.Any(d => d.Email == input.Email);
            EmailAddressAttribute e = new EmailAddressAttribute();
            if(!e.IsValid(input.Email))
                return BadRequest("Invalid email address");
            if(dupEmail || dupUsername)
                return BadRequest("Username or Email already exists");
            if (input.Password.Length<6)
                return BadRequest("Password less than 6 letters");
            string pattern = @"^(?=.*[A-Z])(?=.*\d)(?=.*\W).+$";
            if(!Regex.IsMatch(input.Password, pattern))
                return BadRequest("Password must contain at least one capital letter, one number and one special character");
            input.Password = BCrypt.Net.BCrypt.HashPassword(input.Password);
            auth.Users.Add(input);
            auth.SaveChanges();
            var tokenString = Generate(input);
            HttpContext.Session.SetString("JWTToken", tokenString);
            return RedirectToAction("Welcome");
        }
        [HttpPost]
        public IActionResult Login(Users input)
        {
            var regUser = auth.Users.FirstOrDefault(d => d.Email.ToLower() == input.Email.ToLower());
            if(regUser==null)
                return BadRequest("No registered user of this Email");
            if(!BCrypt.Net.BCrypt.Verify(input.Password, regUser.Password))
                return BadRequest("Wrong Password");
            var tokenString = Generate(regUser);
            HttpContext.Session.SetString("JWTToken", tokenString);
            // Retrieve the token for each request
            
            return RedirectToAction("Welcome");
        }
        private string Generate(Users obj)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, obj.UserName),
                new Claim(ClaimTypes.Email, obj.Email),
            };

            var token = new JwtSecurityToken(
               _config["Jwt:Issuer"],
               _config["Jwt:Issuer"],
               claims,
               expires: DateTime.Now.AddMinutes(30),
               signingCredentials: credentials
           );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public IActionResult Welcome()
        {
            // Retrieve the JWT token from the session
            var tokenString = HttpContext.Session.GetString("JWTToken");

            // Decode the JWT token to access its claims
            if (!string.IsNullOrEmpty(tokenString))
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.ReadJwtToken(tokenString);
                // Retrieve the email claim from the token
                var emailClaim = token.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email);
                var userName = token.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Name);

                // Pass the email to the view
                ViewBag.Username = userName.Value;
                ViewBag.Email = emailClaim.Value;
            }
            return View();
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}