using Jose;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling {

  [AttributeUsage(validOn: AttributeTargets.Method)]
  public class EvaluateBearerTokenAttribute : Attribute, IAsyncActionFilter {

    private string[] _RequiredApiPermissions;

    public EvaluateBearerTokenAttribute(params string[] requiredApiPermissions) {
      _RequiredApiPermissions = requiredApiPermissions;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next) {

      IAccessTokenValidator validator = DefaultAccessTokenValidator.Instance;
      if (validator == null) {
        throw new Exception("Usage of the 'EvaluateBearerTokenAttribute' requires, that 'DefaultAccessTokenValidator.Instance' was set during startup!");
      }

      int authStateCode = 1;
      string validationOutcomeMessage = "UNAUTHORIZED";
      string[] permittedScopes;
      string identityLabel = "";

      try {

        //evaluate, if we have a token
        if (!context.HttpContext.Request.Headers.TryGetValue("Authorization", out var extractedAuthHeader)) {
          validationOutcomeMessage = "'Authorization'-Header was not provided";
          authStateCode = 0;
        }

        string rawJwt = extractedAuthHeader.ToString();
        if (String.IsNullOrWhiteSpace(rawJwt)) {
          rawJwt = null;
        }
        else {
          rawJwt = extractedAuthHeader.ToString();
          if (rawJwt.StartsWith("bearer ")) {
            rawJwt = rawJwt.Substring(7);
          }
        }

        HostString apiCaller = context.HttpContext.Request.Host;

        GetCachedValidatorResponse(
          rawJwt,
          apiCaller.Host,
          out authStateCode,
          out permittedScopes,
          out identityLabel,
          out validationOutcomeMessage,
          validator
        );

      }
      catch (Exception ex) {
        context.Result = new ContentResult() {
          StatusCode = 401,
          Content = "'Authorization'-Header could not be validated: " + ex.Message
        };
        return;
      }

      //note: <0 is correct because that are errors regarding an exisiting jwt!
      //0 means that there was just no token, which could be ok when there is a '(public)' profile
      //(further evaluations will be done below just based on the 
      //permissions which are defined by the ressolved profile)
      if (authStateCode < 0) {
        context.Result = new ContentResult() {
          StatusCode = 401,
          Content = validationOutcomeMessage
        };
        return;
      }

      using (var mac = new AccessControlContext()) {
        mac.SetAuthStateCode(authStateCode);
        mac.SetAccessorName(identityLabel);

        foreach (string permittedScope in permittedScopes) {
          if (permittedScope.Contains(":")) {
            var idx = permittedScope.IndexOf(':');
            var dimensionName = permittedScope.Substring(0, idx);
            var clearanceValue = permittedScope.Substring(idx + 1);
            if (string.Equals(dimensionName, "API", StringComparison.InvariantCultureIgnoreCase)) {
              mac.AddPermissions(clearanceValue);
            }
            else {
              mac.AddClearance(dimensionName, clearanceValue);
            }
          }
        }

        bool missingPermission = false;
        if (_RequiredApiPermissions != null && _RequiredApiPermissions.Length > 0) {
          foreach (string requiredPermission in _RequiredApiPermissions) {
            if (!mac.HasEffectivePermission(requiredPermission)) {
              missingPermission = true;
              break;
            }
          }
        }

        if (missingPermission) {
          if (authStateCode == 0) {
            context.Result = new ContentResult() {
              StatusCode = 401,
              Content = "'Authorization'-Header is required for this operation!"
            };
            return;
          }
          else {
            context.Result = new ContentResult() {
              StatusCode = 401,
              Content = "PERMISSION DENIED for this operation!"
            };
            return;
          }
        }

        await next();
      }
    }

    #region " Cache "

    private static List<CacheEntry> _Cache = new List<CacheEntry>();

    private static void GetCachedValidatorResponse(
      string rawToken,
      string callerHost,
      out int authStateCode,
      out string[] permittedScopes,
      out string identityLabel,
      out string validationOutcomeMessage,
      IAccessTokenValidator validator
    ) {

      lock (_Cache) {
        CacheEntry result = null;
        int idx = 0; 
        foreach (CacheEntry entry in _Cache) {
          if(entry.RawToken == rawToken && entry.CallerHost == callerHost && DateTime.Now < entry.CachableUntil) {
            result = entry;
            break;
          }
          idx++;
        }

        if (result != null ) {
          if (idx > 20) {
            _Cache.RemoveAt(idx);
            _Cache.Insert(0, result);
          }
          authStateCode = result.AuthStateCode;
          permittedScopes = result.PermittedScopes;
          identityLabel = result.IdentityLabel;
          validationOutcomeMessage = result.ValidationOutcomeMessage;
          authStateCode = result.AuthStateCode;
          return;
        }

        int cachableForMinutes;
        validator.ValidateAccessToken(
          rawToken,
          callerHost,
          out authStateCode,
          out permittedScopes,
          out cachableForMinutes,
          out identityLabel,
          out validationOutcomeMessage
        );

        result = new CacheEntry();
        result.RawToken = rawToken;
        result.CallerHost = callerHost;
        result.AuthStateCode = authStateCode;
        result.PermittedScopes = permittedScopes;
        result.IdentityLabel = identityLabel;
        result.ValidationOutcomeMessage = validationOutcomeMessage;
        result.AuthStateCode = authStateCode;
        result.CachableUntil = DateTime.Now.AddMinutes(cachableForMinutes);

        _Cache.Insert(0, result);

        //remove expired entries
        for (int i = _Cache.Count-1; i > 0; i--) {
          if(_Cache[i].CachableUntil < DateTime.Now) {
            _Cache.RemoveAt(i);
          }
        }

        return;
      }

      #endregion

    }

    internal class CacheEntry {
      public string RawToken { get; set; } 
      public string CallerHost { get; set; }
      public int AuthStateCode { get; set; }
      public string[] PermittedScopes { get; set; }
      public string IdentityLabel { get; set; }
      public string ValidationOutcomeMessage { get; set; }
      public DateTime CachableUntil { get; set; }
    }

  }

}
