using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Security.AccessTokenHandling {

  public class TokenValidationRuleset {

    public SubjectProfileConfigurationEntry[] SubjectProfiles { get; set; }
    public IssuerProfileConfigurationEntry[] IssuerProfiles { get; set; }

    public bool ApplyApiPermissionsFromJwtScope { get; set; }
    public bool ApplyDataAccessClearancesFromJwtScope { get; set; }

  }

  public class IssuerProfileConfigurationEntry {

    /// <summary>
    /// Use '?' as name to declare a generic fallback profile!
    /// </summary>
    public string IssuerName { get; set; }

    public bool Disabled { get; set; } = false;

    public string JwtSignKey { get; set; }

    //FOR RSA
    public string JwkE { get; set; }
    public string JwkN { get; set; }
    public string JwkP { get; set; }
    public string JwkQ { get; set; }
    public string JwkD { get; set; }
    public string JwkDp { get; set; }
    public string JwkDq { get; set; }
    public string JwkQi { get; set; }

  }

  public class SubjectProfileConfigurationEntry {

    /// <summary>
    /// Use '?' as name to declare a generic fallback profile!
    /// </summary>
    public string SubjectName { get; set; }

    public string SubjectTitle { get; set; } = "";

    public bool Disabled { get; set; } = false;

    public String[] AllowedHosts { get; set; }

    public String[] DefaultApiPermissions { get; set; }

    public Dictionary<String, String> DefaultDataAccessClearances { get; set; }

  }

}
