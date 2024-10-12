namespace Authentication3.Models
{
    public class Client
    {        
        public Guid Id { get; set; }
        public Guid IdAvatar { get; set; }
        public string? UserName { get; set; }
        public string? DateBirth { get; set; }
        public string? Gender { get; set; }
        public string? Password { get; set; }
        public Role[]? Roles { get; set; }
        public Client() 
        {            
            Id = Guid.NewGuid();
            IdAvatar = Guid.NewGuid();
        }
        public Client(string stringGuid)
        {
            Id = Guid.Parse(stringGuid);
            IdAvatar = Guid.NewGuid();
        }
        public Client(string username, string password)
        {
            UserName = username;
            Password = password;
            Id = Guid.NewGuid();
        }
    }

    public enum Role
    {
        User,
        Admin
    }
}
