﻿namespace backend.Core.Dtos.Auth
{
    public class LoginServiceResponseDto
    {
        public string NewToken { get; set; }
        public UserInfoResult UserInfo { get; set; }
    }
}
