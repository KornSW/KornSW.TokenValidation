using System;

namespace Security.AccessTokenHandling {

  public interface IAccessTokenValidator {

    /// <summary>
    /// </summary>
    /// <param name="rawToken"></param>
    /// <param name="authStateCode">
    ///   0=no token provided / 
    ///   1=authenticated /
    ///  -1=auth failed (token EXPIRED) / 
    ///  -2=auth failed (INVALID token)
    ///  -3=auth failes (by FIREWALL)
    /// </param>
    /// <param name="callerHost"></param>
    /// <param name="permittedScopes"></param>
    /// <param name="cachableForMinutes"></param>
    /// <param name="identityLabel"></param>
    /// <param name="validationOutcomeMessage"></param>
    /// <returns></returns>
    void ValidateAccessToken(
      string rawToken,
      string callerHost,
      out int authStateCode,
      out string[] permittedScopes,
      out int cachableForMinutes,
      out string identityLabel,
      out string validationOutcomeMessage
    );

  }

}
