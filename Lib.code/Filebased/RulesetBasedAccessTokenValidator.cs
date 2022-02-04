using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

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
      SubjectProfileConfigurationEntry profile = null;

      //if we have not failed until here -> DECODE the Token
      if (authStateCode == 1) {
        try {

          jwtContent = JWT.Payload<JwtContent>(rawToken);

          string issuerRelatedSignKey = ruleset.JwtSignKey; //TODO: muss improfil pro issuer stehen!

          byte[] jwtSignKeyBytes = Encoding.ASCII.GetBytes(issuerRelatedSignKey);
          jwtContent = JWT.Decode<JwtContent>(rawToken, jwtSignKeyBytes);

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

      //if we have not failed until here -> validate the ISSUER
      if (authStateCode == 1) {
        if (ruleset.JwtAllowedIssuers != null && !ruleset.JwtAllowedIssuers.Contains("*")) {
          if (!ruleset.JwtAllowedIssuers.Contains(jwtContent.iss)) {
            validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (invalid issuer)!";
            authStateCode = -2;
          }
        }
      }

      //if we have not failed until here -> validate the SUBJECT (try to find corr. profile)
      if (authStateCode == 1) {
        string subjectName = jwtContent.sub;
        profile = ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals(subjectName, StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        if (profile == null) {
          //fallback
          profile = ruleset.SubjectProfiles.Where(e => e.SubjectName == "(generic)").SingleOrDefault();
        }
        if (profile == null) {
          validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (unknown subject)!";
          authStateCode = -2;
        }
        else if (profile.Disabled) {
          validationOutcomeMessage = "subject is blocked!";
          authStateCode = -2;
          profile = null;
        }
      }

      if (profile == null) {
        //this will be loaded for not-authenticated requests (if existing)
        profile = ruleset.SubjectProfiles.Where(e => e.SubjectName == "(public)").SingleOrDefault();
        if (profile != null && profile.Disabled) {
          profile = null;
        }
      }

      //evaluate the optional Firewall-Rules (can only be done after a profile was assigned...)
      if (profile != null && profile.AllowedHosts != null && !profile.AllowedHosts.Contains("*")) {
        //TODO: *-resolving via regex!!!!!!!!!! + fallback for DNS-names to IP!!!
        if (!profile.AllowedHosts.Contains(callerHost.ToLower())) {
          authStateCode = -3;
          validationOutcomeMessage = "access denied by firewall rules";
        }
      }

      if (authStateCode < 0) {
        permittedScopes = new string[] { };
        return;
      }

      var scopes = new List<string>();
      if (profile == null) {
        identityLabel = "(not authenticated)";
      }
      else {
        identityLabel = profile.SubjectName;
        //import permissions/clearances from profile
        if (profile.DefaultApiPermissions != null) {
          foreach (var defaultApiPermission in profile.DefaultApiPermissions) {
            scopes.Add("API:" + defaultApiPermission);
          }
        }
        if (profile.DefaultDataAccessClearances != null) {
          foreach (string dimensionName in profile.DefaultDataAccessClearances.Keys) {
            string[] values = profile.DefaultDataAccessClearances[dimensionName].Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
            foreach (var value in values) {
              scopes.Add(dimensionName + ":" + value);
            }
          }
        }
      }

      //if there is a VALID token and we are configured to import permissions/clearances from the JWT-scope field!
      if (authStateCode == 1 && jwtContent != null && ruleset.ApplyApiPermissionsFromJwtScope) {
        string[] jwtScopes;
        jwtContent.scp = jwtContent.scp.Replace(";", ",");
        if (jwtContent.scp.Contains(",")) {
          jwtScopes = jwtContent.scp.Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
        }
        else {
          jwtScopes = jwtContent.scp.Split(' ').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
        }
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

      /// <summary> audience </summary>
      public String aud { get; set; } = string.Empty;

      /// <summary> scope </summary>
      public String scp { get; set; } = string.Empty;

    }

  }

}
