/* WARNING: THIS IS GENERATED CODE - PLEASE DONT EDIT DIRECTLY - YOUR CHANGES WILL BE LOST! */

using Newtonsoft.Json;
using System;
using System.Net;

namespace Security.AccessTokenHandling {

  public partial class ValidationServiceConnector {

    public ValidationServiceConnector(string url, string apiToken) {

      if (!url.EndsWith("/")) {
        url = url + "/";
      }

      _AccessTokenValidatorClient = new AccessTokenValidatorClient(url + "accessTokenValidator/", apiToken);

    }

    private AccessTokenValidatorClient _AccessTokenValidatorClient = null;
    public IAccessTokenValidator AccessTokenValidator {
      get {
        return _AccessTokenValidatorClient;
      }
    }

  }

  internal partial class AccessTokenValidatorClient : IAccessTokenValidator {
    
    private string _Url;
    private string _ApiToken;
    
    public AccessTokenValidatorClient(string url, string apiToken) {
      _Url = url;
      _ApiToken = apiToken;
    }
    
    private WebClient CreateWebClient() {
      var wc = new WebClient();
      wc.Headers.Set("Authorization", _ApiToken);
      wc.Headers.Set("Content-Type", "application/json");
      return wc;
    }
    
    /// <summary> ValidateAccessToken </summary>
    /// <param name="rawToken">  </param>
    /// <param name="callerHost">  </param>
    /// <param name="authStateCode"> 0=no token provided / 1=authenticated / -1=auth-failed - tokjen EXPIRED / -2=auth-failed INVALID token -3=auth-Failes - firewalle </param>
    /// <param name="permittedScopes">  </param>
    /// <param name="cachableForMinutes">  </param>
    /// <param name="identityLabel">  </param>
    /// <param name="validationOutcomeMessage">  </param>
    public void ValidateAccessToken(string rawToken, string callerHost, out Int32 authStateCode, out string[] permittedScopes, out Int32 cachableForMinutes, out string identityLabel, out string validationOutcomeMessage) {
      using (var webClient = this.CreateWebClient()) {
        string url = _Url + "validateAccessToken";
        var args = new ValidateAccessTokenRequest {
          rawToken = rawToken,
          callerHost = callerHost,
        };
        string rawRequest = JsonConvert.SerializeObject(args);
        string rawResponse = webClient.UploadString(url, rawRequest);
        var result = JsonConvert.DeserializeObject<ValidateAccessTokenResponse>(rawResponse);
        authStateCode = result.authStateCode;
        permittedScopes = result.permittedScopes;
        cachableForMinutes = result.cachableForMinutes;
        identityLabel = result.identityLabel;
        validationOutcomeMessage = result.validationOutcomeMessage;
        return;
      }
    }
    
  }
  
}
