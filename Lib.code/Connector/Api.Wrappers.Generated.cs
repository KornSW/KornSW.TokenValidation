/* WARNING: THIS IS GENERATED CODE - PLEASE DONT EDIT DIRECTLY - YOUR CHANGES WILL BE LOST! */

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Security.AccessTokenHandling {
  
  /// <summary>
  /// Contains arguments for calling 'ValidateAccessToken'.
  /// </summary>
  public class ValidateAccessTokenRequest {
    
    /// <summary> Required Argument for 'ValidateAccessToken' (string) </summary>
    [Required]
    public string rawToken { get; set; }
    
    /// <summary> Required Argument for 'ValidateAccessToken' (string) </summary>
    [Required]
    public string callerHost { get; set; }
    
  }
  
  /// <summary>
  /// Contains results from calling 'ValidateAccessToken'.
  /// </summary>
  public class ValidateAccessTokenResponse {
    
    /// <summary> Out-Argument of 'ValidateAccessToken' (Int32): 0=no token provided / 1=authenticated / -1=auth-failed - tokjen EXPIRED / -2=auth-failed INVALID token -3=auth-Failes - firewalle </summary>
    [Required]
    public Int32 authStateCode { get; set; }
    
    /// <summary> Out-Argument of 'ValidateAccessToken' (string[]) </summary>
    [Required]
    public string[] permittedScopes { get; set; }
    
    /// <summary> Out-Argument of 'ValidateAccessToken' (Int32) </summary>
    [Required]
    public Int32 cachableForMinutes { get; set; }
    
    /// <summary> Out-Argument of 'ValidateAccessToken' (string) </summary>
    [Required]
    public string identityLabel { get; set; }
    
    /// <summary> Out-Argument of 'ValidateAccessToken' (string) </summary>
    [Required]
    public string validationOutcomeMessage { get; set; }
    
  }
  
}
