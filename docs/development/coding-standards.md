# Coding Standards

## C# Coding Guidelines

### Naming Conventions

#### Classes and Methods
```csharp
// ✅ Good - PascalCase
public class PaymentService
{
    public async Task<PaymentResult> ProcessPaymentAsync(PaymentRequest request)
    {
        // Implementation
    }
}

// ❌ Bad - Wrong casing
public class paymentService
{
    public async Task<PaymentResult> processPayment(PaymentRequest request)
    {
        // Implementation
    }
}
```

#### Variables and Parameters
```csharp
// ✅ Good - camelCase
public void ProcessPayment(PaymentRequest paymentRequest)
{
    var encryptionService = GetEncryptionService();
    var transactionId = GenerateTransactionId();
}

// ❌ Bad - Wrong conventions
public void ProcessPayment(PaymentRequest PaymentRequest)
{
    var EncryptionService = GetEncryptionService();
    var transaction_id = GenerateTransactionId();
}
```

#### Constants and Fields
```csharp
// ✅ Good
public class PaymentConstants
{
    public const int MaxRetryAttempts = 3;
    private readonly ILogger _logger;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
}
```

### Code Organization

#### Feature-based Structure
```csharp
// ✅ Good - Feature-based organization
src/PaymentSystem.PaymentApi/Features/
├── Payment/
│   ├── Controllers/PaymentController.cs
│   ├── Services/PaymentService.cs
│   ├── DTOs/PaymentRequestDto.cs
│   └── Models/PaymentResult.cs
├── Encryption/
│   ├── Services/EncryptionService.cs
│   └── Models/EncryptionConfiguration.cs
```

#### Dependency Injection
```csharp
// ✅ Good - Constructor injection
public class PaymentService
{
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<PaymentService> _logger;

    public PaymentService(
        IEncryptionService encryptionService,
        ILogger<PaymentService> logger)
    {
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }
}
```

### Error Handling

#### Exception Handling
```csharp
// ✅ Good - Specific exception handling
public async Task<PaymentResult> ProcessPaymentAsync(PaymentRequest request)
{
    try
    {
        var validationResult = await ValidatePaymentAsync(request);
        if (!validationResult.IsValid)
        {
            return PaymentResult.Failed(validationResult.ErrorMessage);
        }

        return await ExecutePaymentAsync(request);
    }
    catch (ValidationException ex)
    {
        _logger.LogWarning(ex, "Payment validation failed for request {RequestId}", request.Id);
        return PaymentResult.Failed("Invalid payment data");
    }
    catch (PaymentGatewayException ex)
    {
        _logger.LogError(ex, "Payment gateway error for request {RequestId}", request.Id);
        return PaymentResult.Failed("Payment processing temporarily unavailable");
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Unexpected error processing payment {RequestId}", request.Id);
        throw; // Re-throw unexpected exceptions
    }
}
```

#### Result Pattern
```csharp
// ✅ Good - Result pattern for operation outcomes
public class PaymentResult
{
    public bool IsSuccessful { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? TransactionId { get; private set; }

    public static PaymentResult Success(string transactionId) => 
        new() { IsSuccessful = true, TransactionId = transactionId };

    public static PaymentResult Failed(string errorMessage) => 
        new() { IsSuccessful = false, ErrorMessage = errorMessage };
}
```

### Async/Await Best Practices

#### Async Method Naming
```csharp
// ✅ Good - Async suffix
public async Task<PaymentResult> ProcessPaymentAsync(PaymentRequest request)
{
    var result = await _paymentGateway.ProcessAsync(request);
    return result;
}

// ✅ Good - ConfigureAwait(false) in libraries
public async Task<string> GetPublicKeyAsync()
{
    var keyData = await _fileService.ReadKeyFileAsync().ConfigureAwait(false);
    return ProcessKeyData(keyData);
}
```

#### Avoid Async Void
```csharp
// ✅ Good - Return Task
public async Task HandlePaymentEventAsync(PaymentEvent paymentEvent)
{
    await ProcessEventAsync(paymentEvent);
}

// ❌ Bad - Async void (except event handlers)
public async void HandlePaymentEvent(PaymentEvent paymentEvent)
{
    await ProcessEventAsync(paymentEvent);
}
```

### Documentation Standards

#### XML Documentation
```csharp
/// <summary>
/// Processes a payment request using hybrid encryption.
/// </summary>
/// <param name="request">The payment request containing encrypted card data.</param>
/// <returns>A task that represents the asynchronous payment operation. The task result contains the payment result.</returns>
/// <exception cref="ArgumentNullException">Thrown when request is null.</exception>
/// <exception cref="ValidationException">Thrown when request validation fails.</exception>
public async Task<PaymentResult> ProcessPaymentAsync(PaymentRequest request)
{
    // Implementation
}
```

#### Interface Documentation
```csharp
/// <summary>
/// Provides encryption and decryption services for payment data.
/// Implements hybrid encryption using RSA + AES for unlimited data size support.
/// </summary>
public interface IEncryptionService
{
    /// <summary>
    /// Encrypts payment data using hybrid encryption.
    /// </summary>
    /// <param name="plainText">The plain text data to encrypt.</param>
    /// <returns>The encrypted data as a base64 string.</returns>
    string EncryptData(string plainText);
}
```

### Security Coding Standards

#### Sensitive Data Handling
```csharp
// ✅ Good - Secure string handling
public class PaymentProcessor
{
    public async Task<PaymentResult> ProcessAsync(PaymentRequest request)
    {
        // Log without sensitive data
        _logger.LogInformation("Processing payment for order {OrderId}", request.OrderReference);
        
        try
        {
            var decryptedData = _encryptionService.DecryptData(request.EncryptedData);
            var result = await ProcessDecryptedDataAsync(decryptedData);
            
            // Clear sensitive data from memory
            ClearSensitiveData(decryptedData);
            
            return result;
        }
        catch (Exception ex)
        {
            // Log without sensitive data
            _logger.LogError(ex, "Payment processing failed for order {OrderId}", request.OrderReference);
            throw;
        }
    }
    
    private void ClearSensitiveData(string sensitiveData)
    {
        // Implementation to clear memory
    }
}
```

#### Input Validation
```csharp
// ✅ Good - Comprehensive validation
public class PaymentRequestValidator
{
    public ValidationResult Validate(PaymentRequest request)
    {
        if (request == null)
            return ValidationResult.Failed("Request cannot be null");

        if (string.IsNullOrWhiteSpace(request.OrderReference))
            return ValidationResult.Failed("Order reference is required");

        if (request.Amount <= 0)
            return ValidationResult.Failed("Amount must be greater than zero");

        if (request.Amount > 10000) // Business rule
            return ValidationResult.Failed("Amount exceeds maximum limit");

        if (!IsValidCurrency(request.Currency))
            return ValidationResult.Failed("Invalid currency code");

        return ValidationResult.Success();
    }
}
```

### Performance Guidelines

#### Memory Management
```csharp
// ✅ Good - Using using statements
public async Task<string> ReadKeyFileAsync(string filePath)
{
    using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
    using var reader = new StreamReader(fileStream);
    return await reader.ReadToEndAsync();
}

// ✅ Good - StringBuilder for string concatenation
public string BuildLogMessage(PaymentRequest request)
{
    var sb = new StringBuilder();
    sb.Append("Processing payment: ");
    sb.Append("Order=").Append(request.OrderReference);
    sb.Append(", Amount=").Append(request.Amount);
    sb.Append(", Currency=").Append(request.Currency);
    return sb.ToString();
}
```

#### Efficient Collections
```csharp
// ✅ Good - Appropriate collection types
public class PaymentCache
{
    private readonly ConcurrentDictionary<string, PaymentResult> _cache = new();
    private readonly List<string> _processedOrders = new(capacity: 1000);
    
    public bool TryGetCachedResult(string orderId, out PaymentResult result)
    {
        return _cache.TryGetValue(orderId, out result);
    }
}
```

---