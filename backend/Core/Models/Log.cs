namespace backend.Core.Models
{
    public class Log : BaseModel<long>
    {
        public string? UserName { get; set; }
        public string Description { get; set; }
    }
}
