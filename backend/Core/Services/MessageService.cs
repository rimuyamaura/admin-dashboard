using backend.Core.Context;
using backend.Core.Dtos.General;
using backend.Core.Dtos.Message;
using backend.Core.Interfaces;
using backend.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace backend.Core.Services
{
    public class MessageService : IMessageService
    {
        private readonly AppDbContext _context;
        private readonly ILogService _logService;
        private readonly UserManager<User> _userManager;

        public MessageService(AppDbContext context, ILogService logService, UserManager<User> userManager)
        {
            _context = context;
            _logService = logService;
            _userManager = userManager;
        }

        public async Task<GeneralServiceResponseDto> CreateNewMessageAsync(ClaimsPrincipal User, CreateMessageDto createMessageDto)
        {
            if(User.Identity.Name == createMessageDto.RecieverUserName)
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "You can't send a message to yourself"
                };

            var isRecieverExist = _userManager.Users.Any(q => q.UserName == createMessageDto.RecieverUserName);
            if (!isRecieverExist    )
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "Reciever not found"
                };

            Message newMessage = new Message()
            {
                SenderUserName = User.Identity.Name,
                ReceiverUserName = createMessageDto.RecieverUserName,
                Text = createMessageDto.Text
            };
            await _context.Messages.AddAsync(newMessage);
            await _context.SaveChangesAsync();
            await _logService.SaveNewLog(User.Identity.Name, "Sent Message");

            return new GeneralServiceResponseDto()
            {
                IsSuccess = true,
                StatusCode = 201,
                Message = "Message saved successfully"
            };
        }

        public async Task<IEnumerable<GetMessageDto>> GetMessagesAsync()
        {
            var messages = await _context.Messages
                .Select(q => new GetMessageDto()
                {
                    Id = q.Id,
                    SenderUserName = q.SenderUserName,
                    ReceiverUserName = q.ReceiverUserName,
                    Text = q.Text,
                    CreatedAt = q.CreatedAt
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();

            return messages;
        }

        public async Task<IEnumerable<GetMessageDto>> GetMyMessagesAsync(ClaimsPrincipal User)
        {
            var loggedInUser = User.Identity.Name;

            var messages = await _context.Messages
                .Where(q => q.SenderUserName == loggedInUser || q.ReceiverUserName == loggedInUser)
                .Select(q => new GetMessageDto()
                {
                    Id = q.Id,
                    SenderUserName = q.SenderUserName,
                    ReceiverUserName = q.ReceiverUserName,
                    Text = q.Text,
                    CreatedAt = q.CreatedAt
                })
                .OrderByDescending(q => q.CreatedAt)
                .ToListAsync();

            return messages;
        }
    }
}
