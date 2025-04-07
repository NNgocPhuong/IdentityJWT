﻿using JWT_withWebAPI.Data;
using JWT_withWebAPI.Entities;
using JWT_withWebAPI.Models;

namespace JWT_withWebAPI.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<string?> LoginAsync(UserDto request);
    }
}
