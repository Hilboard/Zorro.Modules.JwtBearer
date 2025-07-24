using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Zorro.Query;
using static Zorro.Query.Essentials.Auth.SignInUserQuery;

namespace Zorro.Services;

public static class JwtBearerService
{
    public static string COOKIE_TOKEN_NAME { get; set; } = "accessToken";

    public delegate TokenValidationParameters TokenValidationBuilder(TokenValidationParameters builder);
    public static TokenValidationBuilder? TokenValidationMaster { get; set; } = null;

    public static TokenValidationParameters DefaultParameters { get; set; } = new();

    private static TokenValidationParameters? parameters { get; set; } = null;
    private static SigningCredentials? signingCreds { get; set; } = null;

    public static AuthenticationBuilder UseJwtBearer(IServiceCollection services)
    {
        parameters = DefaultParameters;
        if (TokenValidationMaster is not null)
            TokenValidationMaster.Invoke(parameters);

        signingCreds = new SigningCredentials(parameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

        var builder = services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = parameters;
                options.SaveToken = true;
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        var accessToken = context.HttpContext.Request.Cookies[COOKIE_TOKEN_NAME];
                        if (!string.IsNullOrEmpty(accessToken))
                        {
                            context.Token = accessToken;
                        }
                        return Task.CompletedTask;
                    },
                };
            });

        DefaultAuthenticationMethod = (QueryContext context, IUserSignInForm form, dynamic user) =>
        {
            object userId = user.Id;
            string userName = user.UserName;

            Claim[] claims =
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()!),
                new Claim(JwtRegisteredClaimNames.Name, userName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.AuthTime, DateTime.UtcNow.ToString())
            };

            var expireDate = form.rememberMe.HasValue && form.rememberMe.Value
                ? DateTime.UtcNow.AddDays(30)
                : DateTime.UtcNow.AddDays(1);

            var cookieOptions = new CookieOptions
            {
                Expires = expireDate,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            };

            context.ResponseCookies.Append(COOKIE_TOKEN_NAME, GenerateToken(expireDate, claims), cookieOptions);
        };

        return builder;
    }

    private static string GenerateToken(DateTime expireDate, params Claim[] claims)
    {
        if (parameters is null)
        {
            if (TokenValidationMaster is null)
                throw new InvalidOperationException("TokenValidationMaster is not set.");
            parameters = TokenValidationMaster.Invoke(new TokenValidationParameters());
        }

        var token = new JwtSecurityToken(
            issuer: parameters.ValidIssuer,
            audience: parameters.ValidAudience,
            claims: claims,
            expires: expireDate,
            signingCredentials: signingCreds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}