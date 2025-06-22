namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Key generation request model
/// </summary>
public class KeyGenerationRequest
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<EnvironmentConfig> Environments { get; set; } = new();
}