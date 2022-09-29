using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling;

namespace Security {

  [TestClass]
  public class AccessControlTests {

    [TestMethod]
    public void TestSignatureH256() {

      var subjectProfile = new SubjectProfileConfigurationEntry();
      subjectProfile.Disabled = false;
      subjectProfile.SubjectName = "MM001";
      subjectProfile.SubjectTitle = "Max Mustermann";
      subjectProfile.DefaultApiPermissions = new string[] { 
        "ControllerA", "ControllerB" 
      };

      var ruleset = new TokenValidationRuleset();
      ruleset.ApplyApiPermissionsFromJwtScope = true;

      ruleset.IssuerProfiles = new IssuerProfileConfigurationEntry[]{
        new IssuerProfileConfigurationEntry {
          IssuerName = "FOO-Issuer",
          JwtSignKey = "this-is-a-very-secure-demo-secret"
        }
      };

      ruleset.SubjectProfiles = new SubjectProfileConfigurationEntry []{
        subjectProfile
      };

      var validator = new RulesetBasedAccessTokenValidator(ruleset);

      //HS256
      var rawTokenToValidate = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJGT08tSXNzdWVyIiwiaWF0IjoxNjY0Mzc5ODMyLCJleHAiOjcyNDk5NjcwMzIsImF1ZCI6IkZPTy1BdWRpZW5jZSIsInN1YiI6Ik1NMDAxIiwic2NwIjoic2NwMSBzY3AyIHNjcDMiLCJzY29wZSI6InNjb3BlNCxzY29wZTU7c2NvcGU2In0.wLagNXGuaRrMtwUjQ5ol4ArnZ1Jv3h--h9fUyu1-nF0";
      var callHost = "localhost";

      validator.ValidateAccessToken(
        rawTokenToValidate,
        callHost,
        out int outState,
        out string[] permittedScopes,
        out int cacheForMinutes,
        out string identiyLabel,
        out string outcomeMsg
      );

      const int authStateAuthenticated = 1;
      Assert.AreEqual(authStateAuthenticated, outState);

      Assert.AreEqual(subjectProfile.SubjectTitle, identiyLabel);

      //scopes from profile
      Assert.IsTrue(permittedScopes.Contains("API:ControllerA"));
      Assert.IsTrue(permittedScopes.Contains("API:ControllerB"));

      //scopes from 'scp'-Claim
      Assert.IsTrue(permittedScopes.Contains("scp1"));
      Assert.IsTrue(permittedScopes.Contains("scp2"));
      Assert.IsTrue(permittedScopes.Contains("scp3"));

      //scopes from 'scp'-Claim
      Assert.IsTrue(permittedScopes.Contains("scope4"));
      Assert.IsTrue(permittedScopes.Contains("scope5"));
      Assert.IsTrue(permittedScopes.Contains("scope6"));

    }

    //[TestMethod]
    public void TestSignatureRS256() {

      var subjectProfile = new SubjectProfileConfigurationEntry();
      subjectProfile.Disabled = false;
      subjectProfile.SubjectName = "6";
      subjectProfile.SubjectTitle = "Max Mustermann";
      subjectProfile.DefaultApiPermissions = new string[] {
        "ControllerA", "ControllerB"
      };

      var ruleset = new TokenValidationRuleset();
      ruleset.ApplyApiPermissionsFromJwtScope = true;

      ruleset.IssuerProfiles = new IssuerProfileConfigurationEntry[]{
        new IssuerProfileConfigurationEntry {
          IssuerName = "XXXXXXXXXXX",
          JwkE = "AQAB",
          JwkN = "XXXXXXXXX"
        }
      };

      ruleset.SubjectProfiles = new SubjectProfileConfigurationEntry[]{
        subjectProfile
      };

      var validator = new RulesetBasedAccessTokenValidator(ruleset);

      var rawTokenToValidate = "XXXXXX";
      var callHost = "localhost";

      validator.ValidateAccessToken(
        rawTokenToValidate,
        callHost,
        out int outState,
        out string[] permittedScopes,
        out int cacheForMinutes,
        out string identiyLabel,
        out string outcomeMsg
      );

      const int authStateAuthenticated = 1;
      Assert.AreEqual(authStateAuthenticated, outState);

      Assert.AreEqual(subjectProfile.SubjectTitle, identiyLabel);

      Assert.IsTrue(permittedScopes.Contains("API:ControllerA"));
      Assert.IsTrue(permittedScopes.Contains("API:ControllerB"));

    }

  }

}
