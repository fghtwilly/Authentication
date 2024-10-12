using Authentication3.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using System.Web;

namespace Authentication3.Controllers
{
    public class Authentication3Controller : Controller
    {        
        public string pathAvatar = "C:\\Users\\Михаил\\ПАПКА\\IT\\C#\\aspnet\\Authentication3\\wwwroot\\Avatar";
        public string pathClient = "C:\\Users\\Михаил\\ПАПКА\\IT\\C#\\aspnet\\Authentication3\\wwwroot\\Clients";


        public IActionResult Index()
        {
            ClientViewModel model = new ClientViewModel();
            model.AvatarView = Directory.GetFiles(pathAvatar);

            /*
            Type myType = typeof(Client);
            foreach (MemberInfo member in myType.GetMembers())
            {
                Console.WriteLine($"{member.DeclaringType} {member.MemberType} {member.Name}");
            }*/

            return View(model);
        }


        [HttpPost]
        public IActionResult TakeLogin(Guid avatarId, string username, string password)
        {
            string[] fileName = Directory.GetFiles(pathClient);
            foreach(var item in fileName) 
            {                
                StreamReader sr = new StreamReader(item);
                string? jsonToText = sr.ReadToEnd();
                Client userCheck = JsonSerializer.Deserialize<Client>(jsonToText);
                if (userCheck.IdAvatar == avatarId && userCheck.UserName == username && userCheck.Password == password) 
                {  
                    var claims = new List<Claim> { new Claim(ClaimTypes.Name, userCheck.UserName) };
                    // создаем JWT-токен
                    var jwt = new JwtSecurityToken(
                            issuer: AuthOptions.ISSUER,
                            audience: AuthOptions.AUDIENCE,
                            claims: claims,
                            expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                            signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                   
                    sr.Close();

                    var response = new
                    {
                        access_token = encodedJwt,
                        username = userCheck.UserName
                    };
                    //return Json(new { success = response });
                    return Json(response);                    
                }
            }
            
            return BadRequest("Неверные логин или пароль");                        
        }

        [HttpPost]
        public IActionResult Registration()
        {            
            return PartialView("_Registration");
        }
                
        [HttpPost]
        public IActionResult RegistrationSave(IFormFile data, string usernameR, string datebirthR, string genderR, string passwordR)   //сохранение зарегистрированного пользователя
        {
            string[] fileName = Directory.GetFiles(pathClient);
            foreach (string item in fileName)                                                                           //проверка совпадения UserName с уже существующими
            {
                StreamReader sr = new StreamReader(item);
                string? jsonToText = sr.ReadToEnd();
                Client userCheck = JsonSerializer.Deserialize<Client>(jsonToText);                
                if (userCheck.UserName == usernameR)
                {
                    return BadRequest("Это имя уже занято"); 
                }                
            }
            Client person = new Client() { UserName = usernameR, DateBirth = datebirthR, Gender = genderR, Password = passwordR };
            var pathNew = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/Avatar", person.IdAvatar.ToString() + ".jpg");
            var options1 = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Cyrillic),
                WriteIndented = true
            };
            string textToJson = JsonSerializer.Serialize(person, options1);
            FileInfo newFile = new FileInfo(pathClient + "\\" + person.Id);
            StreamWriter sw = newFile.CreateText();
            sw.Write(textToJson);
            sw.Close();
            using (var stream = new FileStream(pathNew, FileMode.Create))
            {
                data.CopyTo(stream);
            }
            return PartialView("_Home", person);            
        }

        [HttpPost]
        [Authorize]
        public IActionResult SaveChange(IFormFile data, string Idclient, string username, string datebirthC, string genderC, string passwordC)  //сохранение измененных данных пользователя
        {
            string[] fileName = Directory.GetFiles(pathClient);
            foreach (string item in fileName)
            {
                if (item.Remove(0, 67) == Idclient)
                {
                    StreamReader sr = new StreamReader(item);
                    string? jsonToText = sr.ReadToEnd();
                    Client changeClient = JsonSerializer.Deserialize<Client>(jsonToText);

                    FileInfo fileInf = new FileInfo(pathAvatar + "\\" + changeClient.IdAvatar.ToString() + ".jpg");
                    if (fileInf.Exists)
                    {
                        fileInf.Delete();                        
                    }
                    sr.Close();

                    Client person = new Client(Idclient) { UserName = username, DateBirth = datebirthC, Gender = genderC, Password = passwordC };                    
                    var pathNew = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/Avatar", person.IdAvatar.ToString() + ".jpg");
                    var options1 = new JsonSerializerOptions
                    {
                        Encoder = JavaScriptEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Cyrillic),
                        WriteIndented = true
                    };
                    string textToJson = JsonSerializer.Serialize(person, options1);
                    FileInfo newFile = new FileInfo(pathClient + "\\" + person.Id);
                    StreamWriter sw = newFile.CreateText();
                    sw.Write(textToJson);
                    sw.Close();
                    using (var stream = new FileStream(pathNew, FileMode.Create))
                    {
                        data.CopyTo(stream);             
                    }
                    return PartialView("_Home", person);
                }                                
            }
            return BadRequest("Изменения не сохранены");
        }

        [HttpPost]
        [Authorize]
        public IActionResult Home(string avatarId)
        {
            string[] fileName = Directory.GetFiles(pathClient);
            foreach (string item in fileName)
            {
                StreamReader sr = new StreamReader(item);
                string? jsonToText = sr.ReadToEnd();
                Client? userCheck = JsonSerializer.Deserialize<Client>(jsonToText);
                if (userCheck.IdAvatar.ToString() == avatarId)
                {
                    sr.Close();
                    return PartialView("_Home", userCheck);                 //?
                }
            }
            return BadRequest("Ошибка");
        }
    }
}
