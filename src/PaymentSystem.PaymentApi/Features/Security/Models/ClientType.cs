namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Client types based on certificate properties
/// </summary>
public enum ClientType
{
    Standard = 0,
    Enterprise = 1,
    Financial = 2,
    Government = 3
}