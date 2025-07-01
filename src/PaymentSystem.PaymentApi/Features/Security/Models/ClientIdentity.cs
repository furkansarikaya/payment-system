namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Client identity extracted from certificate
/// </summary>
public class ClientIdentity
{
    public string ClientId { get; set; } = string.Empty;
    public string OrganizationName { get; set; } = string.Empty;
    public string CertificateSubject { get; set; } = string.Empty;
    public string CertificateIssuer { get; set; } = string.Empty;
    public string CertificateThumbprint { get; set; } = string.Empty;
    public string CertificateSerialNumber { get; set; } = string.Empty;
    public ClientType ClientType { get; set; } = ClientType.Standard;
    public bool IsHighSecurityClient { get; set; }
    public List<string> AllowedIpRanges { get; set; } = new();
    public bool IsValid { get; set; } = true;
}