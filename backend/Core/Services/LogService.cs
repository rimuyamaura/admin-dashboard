using backend.Core.Context;
using backend.Core.Dtos.Log;
using backend.Core.Interfaces;
using backend.Core.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace backend.Core.Services
{
    public class LogService : ILogService
    {
        private readonly AppDbContext _context;

        public LogService(AppDbContext context)
        {
            _context = context;
        }

        public async Task SaveNewLog(string UserName, string Description)
        {
            var newLog = new Log()
            {
                UserName = UserName,
                Description = Description,
            };
            await _context.Logs.AddAsync(newLog);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<GetLogDto>> GetLogsAsync()
        {
            var logs = await _context.Logs
                .Select(q => new GetLogDto
                {
                    CreatedAt = q.CreatedAt,
                    Description = q.Description,
                    UserName = q.UserName,
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();
            return logs;
        }

        public async Task<IEnumerable<GetLogDto>> GetMyLogsAsync(ClaimsPrincipal User)
        {
            var logs = await _context.Logs
                .Where(q => q.UserName == User.Identity.Name)
                .Select(q => new GetLogDto
                {
                    CreatedAt = q.CreatedAt,
                    Description = q.Description,
                    UserName = q.UserName,
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();
            return logs;
        }
    }
}
