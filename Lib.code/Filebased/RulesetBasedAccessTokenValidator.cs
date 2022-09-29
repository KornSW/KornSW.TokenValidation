using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Security.AccessTokenHandling {

  public class RulesetBasedAccessTokenValidator : IAccessTokenValidator {

    #region " Constructors & Ruleset "

    public RulesetBasedAccessTokenValidator() {
      _Ruleset = new TokenValidationRuleset();
    }

    public RulesetBasedAccessTokenValidator(TokenValidationRuleset ruleset) {
      _Ruleset = ruleset;
    }

    /// <summary>
    /// </summary>
    /// <param name="fileFullName">the name of a JSON-File, which contains a serialized 'TokenValidationRuleset'</param>
    /// <param name="reloadIntervalMinutes"></param>
    public RulesetBasedAccessTokenValidator(string fileFullName, int reloadIntervalMinutes = 15) {
      _FileFullName = fileFullName;
      _ReloadIntervalMinutes = reloadIntervalMinutes;
      _FileValidUntil = DateTime.MinValue;
    }

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private TokenValidationRuleset _Ruleset;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private string _FileFullName = null;
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private int _ReloadIntervalMinutes = 1;
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private DateTime _FileValidUntil = DateTime.MaxValue;

    public TokenValidationRuleset Ruleset {
      get {
        if(_FileFullName != null && _FileValidUntil < DateTime.Now) {
          string rawFileContent = File.ReadAllText(_FileFullName, Encoding.Default);
          _Ruleset = JsonConvert.DeserializeObject<TokenValidationRuleset>(rawFileContent);
          _FileValidUntil = DateTime.Now.AddMinutes(_ReloadIntervalMinutes);
        }
        return _Ruleset;
      }
    }

    #endregion

    public void ValidateAccessToken(
      string rawToken,
      string callerHost,
      out int authStateCode,
      out string[] permittedScopes,
      out int cachableForMinutes,
      out string identityLabel,
      out string validationOutcomeMessage
    ) {

      TokenValidationRuleset ruleset = this.Ruleset;
      if (_FileFullName != null) {
        cachableForMinutes = Convert.ToInt32(_FileValidUntil.Subtract(DateTime.Now).TotalMinutes);
        if(cachableForMinutes < 0) {
          cachableForMinutes = 0;
        }
      }
      else {
        cachableForMinutes = _ReloadIntervalMinutes;
      }
     
      authStateCode = 1;
      identityLabel = "UNAUTHORIZED";
      validationOutcomeMessage = "";

      if (string.IsNullOrWhiteSpace(rawToken)) {
        identityLabel = "(not authenticated)";
        authStateCode = 0;
        validationOutcomeMessage = "no Token provided";
      }

      JwtContent jwtContent = null;
      SubjectProfileConfigurationEntry subjectProfile = null;
      IssuerProfileConfigurationEntry issuerProfile = null;
      //if we have not failed until here -> DECODE the Token
      if (authStateCode == 1) {
        try {

          jwtContent = JWT.Payload<JwtContent>(rawToken);
  
          string issuerName = jwtContent.iss;
          issuerProfile = ruleset.IssuerProfiles.Where(e => e.IssuerName.Equals(issuerName, StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
          if (issuerProfile == null) {
            //fallback
            issuerProfile = ruleset.IssuerProfiles.Where(e => e.IssuerName == "?").SingleOrDefault();
          }
          if (issuerProfile == null) {
            validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (unknown issuer)!";
            authStateCode = -2;
          }
          else if (issuerProfile.Disabled) {
            validationOutcomeMessage = "issuer is blocked!";
            authStateCode = -2;
            issuerProfile = null;
          }

          if(issuerProfile != null) {

            IDictionary<string, object> headers = JWT.Headers(rawToken);
            string alg = headers["alg"].ToString();
            bool useComplexJwk = (alg.StartsWith("RS", StringComparison.CurrentCultureIgnoreCase));

            if (useComplexJwk) {
              if (string.IsNullOrWhiteSpace(issuerProfile.JwkE)) {
                validationOutcomeMessage = $"'Authorization'-Header contains an invalid bearer token (expecting JWK for alg '{alg}')!";
                authStateCode = -2;
              }
              else {
                // can be convertd from base64 PEM via this tool:  https://8gwifi.org/jwkconvertfunctions.jsp
                Jwk jwk = new Jwk(
                  e: issuerProfile.JwkE,
                  n: issuerProfile.JwkN,
                  p: issuerProfile.JwkP,
                  q: issuerProfile.JwkQ,
                  d: issuerProfile.JwkD,
                  dp: issuerProfile.JwkDp,
                  dq: issuerProfile.JwkDq,
                  qi: issuerProfile.JwkQi
                );
                jwtContent = JWT.Decode<JwtContent>(rawToken, jwk);
              }
            }
            else {
              if (string.IsNullOrWhiteSpace(issuerProfile.JwtSignKey)) {
                validationOutcomeMessage = $"'Authorization'-Header contains an invalid bearer token (expecting 'JwtSignKey' for alg '{alg}')!";
                authStateCode = -2;
              }
              else {
                byte[] jwtSignKeyBytes = Encoding.ASCII.GetBytes(issuerProfile.JwtSignKey);
                jwtContent = JWT.Decode<JwtContent>(rawToken, jwtSignKeyBytes);
              }
            }
          }

        }
        catch (Exception ex) {
          validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (decode failure): " + ex.Message;
          cachableForMinutes = 1140; //invalid forever -> cache 24h
          authStateCode = -2;
        }
      }

      //if we have not failed until here -> DECODE the Token
      if (authStateCode == 1) {
        var expirationTimeUtc = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddSeconds(jwtContent.exp);
        if (DateTime.UtcNow > expirationTimeUtc) {
          validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (expired)!";
          cachableForMinutes = 1140; //invalid forever -> cache 24h
          authStateCode = -1;
        }
      }

      //if we have not failed until here -> validate the SUBJECT (try to find corr. profile)
      if (authStateCode == 1) {
        string subjectName = jwtContent.sub;
        subjectProfile = ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals(subjectName, StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        if (subjectProfile == null) {
          //fallback
          subjectProfile = ruleset.SubjectProfiles.Where(e => e.SubjectName == "?").SingleOrDefault();
        }
        if (subjectProfile == null) {
          validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (unknown subject)!";
          authStateCode = -2;
        }
        else if (subjectProfile.Disabled) {
          validationOutcomeMessage = "subject is blocked!";
          authStateCode = -2;
          subjectProfile = null;
        }
      }

      if (subjectProfile == null) {
        //this will be loaded for not-authenticated requests (if existing)
        subjectProfile = ruleset.SubjectProfiles.Where(e => e.SubjectName == "(public)").SingleOrDefault();
        if (subjectProfile != null && subjectProfile.Disabled) {
          subjectProfile = null;
        }
      }

      //evaluate the optional Firewall-Rules (can only be done after a profile was assigned...)
      if (subjectProfile != null && subjectProfile.AllowedHosts != null && !subjectProfile.AllowedHosts.Contains("*")) {
        //TODO: *-resolving via regex!!!!!!!!!! + fallback for DNS-names to IP!!!
        if (!subjectProfile.AllowedHosts.Contains(callerHost.ToLower())) {
          authStateCode = -3;
          validationOutcomeMessage = "access denied by firewall rules";
        }
      }

      if (authStateCode < 0) {
        permittedScopes = new string[] { };
        return;
      }

      var scopes = new List<string>();
      if (subjectProfile == null) {
        identityLabel = "(not authenticated)";
      }
      else {
        identityLabel = subjectProfile.SubjectTitle;
        //import permissions/clearances from profile
        if (subjectProfile.DefaultApiPermissions != null) {
          foreach (var defaultApiPermission in subjectProfile.DefaultApiPermissions) {
            scopes.Add("API:" + defaultApiPermission);
          }
        }
        if (subjectProfile.DefaultDataAccessClearances != null) {
          foreach (string dimensionName in subjectProfile.DefaultDataAccessClearances.Keys) {
            string[] values = subjectProfile.DefaultDataAccessClearances[dimensionName].Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
            foreach (var value in values) {
              scopes.Add(dimensionName + ":" + value);
            }
          }
        }
      }

      //if there is a VALID token and we are configured to import permissions/clearances from the JWT-scope field!
      if (authStateCode == 1 && jwtContent != null && ruleset.ApplyApiPermissionsFromJwtScope) {
        string[] jwtScopes;
        string rawScopes = string.Empty;
        if (!String.IsNullOrWhiteSpace(jwtContent.scp)) {
          rawScopes = jwtContent.scp;
        }

        if (jwtContent.scope != null) {
          rawScopes = rawScopes + "," + jwtContent.scope.ToString();
          //if (jwtContent.scope.GetType() == typeof(string)) {
          //  rawScopes = rawScopes + "," + jwtContent.scope.ToString();
          //}
          //if(jwtContent.scope.GetType() == typeof(string[])) {
          //  rawScopes = rawScopes + "," + String.Join(",", jwtContent.scope);
          //}
        }
        jwtScopes = rawScopes.Split(',', ';', ' ').Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
        foreach (string jwtScope in jwtScopes) {
          scopes.Add(jwtScope);
        }
      }

      permittedScopes = scopes.ToArray();
      return;
    }

    internal class JwtContent {

      /// <summary> issuer </summary>
      public String iss { get; set; } = string.Empty;

      /// <summary> subject </summary>
      public String sub { get; set; } = string.Empty;

      /// <summary> expires (unix-epoch utc) </summary>
      public long exp { get; set; } = 0;

      /*
      /// <summary> audience </summary>
      public String aud { get; set; } = string.Empty;
      */

      /// <summary> OAUTH Scope(s) in long name </summary>
      public object scope { get; set; } = string.Empty;

      /// <summary> OAUTH Scope(s) in short name </summary>
      public String scp { get; set; } = string.Empty;

    }

    }

}
